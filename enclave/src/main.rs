use std::env::args;
use std::io;

use cfg_if::cfg_if;
use parity_scale_codec::{DecodeAll, Encode};
use sp_core::{ed25519, Pair};

use common::attestation::{Attestation, AttestationBundle, AttestedData};
use common::ENCODING_VERSION;
use common::GloveResult;
use enclave_interface::{EnclaveRequest, EnclaveResponse, EnclaveStream, Error, SignedVoteRequest};

// The Glove enclave is a simple process which listens for vote mixing requests.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Generate a random signing key and embed it in the attestation document.
    let (signing_pair, _) = ed25519::Pair::generate();
    let attested_data = AttestedData {
        signing_key: signing_pair.public()
    };

    cfg_if! {
        if #[cfg(target_os = "linux")] {
            let (mut stream, attestation) = match args().nth(1) {
                Some(socket_file) => {
                    (mock::establish_connection(socket_file).await?, Attestation::Mock)
                },
                None => {
                    (nitro::establish_connection().await?, nitro::create_attestation(&attested_data)?)
                }
            };
        } else {
            let mut stream = mock::establish_connection(args().nth(1).unwrap()).await?;
            let attestation = Attestation::Mock;
        }
    }

    let attestation_bundle = AttestationBundle {
        version: ENCODING_VERSION,
        attested_data,
        attestation
    };

    // Loop, processing requests from the host. If the host termintes, it will close the stream,
    // break the loop and terminate the enclave as well.
    loop {
        let encoded_request = stream.read_len_prefix_bytes().await?;
        let response = process_request(encoded_request, &signing_pair, &attestation_bundle);
        stream.write_len_prefix_bytes(&response.encode()).await?;
    }
}

#[cfg(target_os = "linux")]
mod nitro {
    use anyhow::anyhow;
    use aws_nitro_enclaves_nsm_api::api::{Request, Response};
    use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
    use nix::sys::socket::VsockAddr;
    use serde_bytes::ByteBuf;
    use sha2::{Digest, Sha256};
    use tokio_vsock::VsockStream;

    use common::nitro;
    use enclave_interface::{NITRO_HOST_CID, NITRO_PORT};

    use super::*;

    pub(crate) async fn establish_connection() -> io::Result<EnclaveStream> {
        let stream = VsockStream::connect(VsockAddr::new(NITRO_HOST_CID, NITRO_PORT)).await?;
        println!("Connected to host as AWS Nitro enclave");
        Ok(EnclaveStream::Vsock(stream))
    }

    pub(crate) fn create_attestation(attested_data: &AttestedData) -> Result<Attestation, anyhow::Error> {
        let attested_data_hash = Sha256::digest(attested_data.encode()).to_vec();

        let request = Request::Attestation {
            public_key: None,
            user_data: Some(ByteBuf::from(attested_data_hash)),
            nonce: None,
        };
        println!("Requesting attestation document from NSM: {:?}", request);
        let nsm_fd = nsm_init();
        let response = nsm_process_request(nsm_fd, request);
        nsm_exit(nsm_fd);

        match response {
            Response::Attestation { document } => {
                let attestation = nitro::Attestation::try_from(document.as_slice())
                    .map_err(|e| anyhow!(e.to_string()))?;
                Ok(Attestation::Nitro(attestation))
            }
            _ => Err(anyhow!("Unexpected NSM response: {:?}", response))
        }
    }
}

mod mock {
    use tokio::net::UnixStream;

    use super::*;

    pub(crate) async fn establish_connection(socket_file: String) -> io::Result<EnclaveStream> {
        let stream = UnixStream::connect(socket_file.clone()).await?;
        println!("Connected to host as insecure mock enclave: {}", socket_file);
        Ok(EnclaveStream::Unix(stream))
    }
}


fn process_request(
    encoded_request: Vec<u8>,
    signing_key: &ed25519::Pair,
    attestation_bundle: &AttestationBundle
) -> EnclaveResponse {
    let request_decode_result = EnclaveRequest::decode_all(&mut encoded_request.as_slice());
    println!("Decoded request: {:?}", request_decode_result);
    match request_decode_result {
        Ok(EnclaveRequest::Attestation) => EnclaveResponse::Attestation(attestation_bundle.clone()),
        Ok(EnclaveRequest::MixVotes(vote_requests)) => process_mix_votes(&vote_requests, signing_key),
        Err(scale_error) => EnclaveResponse::Error(Error::Scale(scale_error.to_string())),
    }
}

fn process_mix_votes(
    vote_requests: &Vec<SignedVoteRequest>,
    signing_key: &ed25519::Pair
) -> EnclaveResponse {
    println!("Received request: {:?}", vote_requests);
    let signatures_valid = vote_requests
        .iter()
        .all(|signed_request| signed_request.is_signature_valid());
    if signatures_valid {
        let mixed_votes = enclave::mix_votes(&vote_requests);
        let signature = signing_key.sign(&mixed_votes.encode());
        EnclaveResponse::GloveResult(GloveResult { mixed_votes, signature })
    } else {
        EnclaveResponse::Error(Error::InvalidSignature)
    }
}
