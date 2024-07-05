use std::env::args;
use std::io;

use cfg_if::cfg_if;
use sp_core::{ed25519, H256, Pair};

use common::attestation::{Attestation, AttestationBundle, AttestedData};
use common::SignedVoteRequest;
use enclave_interface::{EnclaveRequest, EnclaveResponse, EnclaveStream, Error};

// The Glove enclave is a simple process which listens for vote mixing requests.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    cfg_if! {
        if #[cfg(target_os = "linux")] {
            let mut stream = match args().nth(1) {
                Some(socket_file) => mock::establish_connection(socket_file).await?,
                None => nitro::establish_connection().await?
            };
        } else {
            let mut stream = mock::establish_connection(args().nth(1).unwrap()).await?;
        }
    }

    // Receive from the host the genesis hash for the chain the enclave is working on. It actually
    // has no way of knowing if this is what's intended, until clients send in their requests
    // specifying the same hash. Only then is the genesis hash in the attestation proven to be
    // correct.
    let genesis_hash = stream.read::<H256>().await?;
    // Generate a random signing key and embed it in the attestation document.
    let (signing_pair, _) = ed25519::Pair::generate();
    let attested_data = AttestedData {
        genesis_hash,
        signing_key: signing_pair.public()
    };

    cfg_if! {
        if #[cfg(target_os = "linux")] {
            let attestation = match args().nth(1) {
                Some(_) => Attestation::Mock,
                None => nitro::create_attestation(&attested_data)?
            };
        } else {
            let attestation = Attestation::Mock;
        }
    }
    // Send the attestation bundle to the host as the first thing it receives.
    stream.write(&AttestationBundle { attested_data, attestation }).await?;

    // Loop, processing requests from the host. If the host termintes, it will close the stream,
    // break the loop and terminate the enclave as well.
    loop {
        let request = stream.read::<EnclaveRequest>().await?;
        println!("Request: {:?}", request);
        let response = match request {
            EnclaveRequest::MixVotes(vote_requests) =>
                process_mix_votes(&vote_requests, &signing_pair, genesis_hash),
        };
        stream.write(&response).await?;
    }
}

#[cfg(target_os = "linux")]
mod nitro {
    use anyhow::anyhow;
    use aws_nitro_enclaves_nsm_api::api::{Request, Response};
    use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
    use nix::sys::socket::VsockAddr;
    use parity_scale_codec::Encode;
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
            user_data: ByteBuf::from(attested_data_hash).into(),
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

fn process_mix_votes(
    vote_requests: &Vec<SignedVoteRequest>,
    signing_key: &ed25519::Pair,
    genesis_hash: H256
) -> EnclaveResponse {
    println!("Received request: {:?}", vote_requests);
    match enclave::mix_votes(genesis_hash, &vote_requests) {
        Ok(glove_result) => EnclaveResponse::GloveResult(glove_result.sign(signing_key)),
        Err(error) => EnclaveResponse::Error(Error::Mixing(error.to_string()))
    }
}
