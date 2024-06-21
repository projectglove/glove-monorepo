use std::env::args;

use cfg_if::cfg_if;
use parity_scale_codec::{DecodeAll, Encode};

use enclave_interface::{AttestationDoc, EnclaveRequest, EnclaveResponse, Error, SignedVoteRequest};

// The Glove enclave is a simple process which listens for vote mixing requests.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    cfg_if! {
        if #[cfg(target_os = "linux")] {
            let (mut stream, attestation_doc) = match args().nth(1) {
                Some(socket_file) =>
                    (mock::establish_connection(socket_file).await?, AttestationDoc::Mock),
                None => (nitro::establish_connection().await?, nitro::retrieve_attestation_doc()?)
            };
        } else {
            let mut stream = mock::establish_connection(args().nth(1).unwrap()).await?;
            let attestation_doc = AttestationDoc::Mock;
        }
    }

    loop {
        let encoded_request = stream.read_len_prefix_bytes().await?;
        let response = process_request(encoded_request, &attestation_doc);
        stream.write_len_prefix_bytes(&response.encode()).await?;
    }
}

#[cfg(target_os = "linux")]
mod nitro {
    use std::io;

    use anyhow::anyhow;
    use aws_nitro_enclaves_nsm_api::api::{Request, Response};
    use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
    use nix::sys::socket::VsockAddr;
    use tokio_vsock::VsockStream;

    use enclave_interface::{AttestationDoc, EnclaveStream};
    use enclave_interface::{NITRO_HOST_CID, NITRO_PORT};

    pub(crate) async fn establish_connection() -> io::Result<EnclaveStream> {
        let stream = VsockStream::connect(VsockAddr::new(NITRO_HOST_CID, NITRO_PORT)).await?;
        println!("Connected to host as AWS Nitro enclave");
        Ok(EnclaveStream::Vsock(stream))
    }

    pub(crate) fn retrieve_attestation_doc() -> Result<AttestationDoc, anyhow::Error> {
        let nsm_fd = nsm_init();
        let request = Request::Attestation {
            public_key: None,
            user_data: None,
            nonce: None,
        };
        println!("Requesting attestation document from NSM: {:?}", request);
        let response = nsm_process_request(nsm_fd, request);
        nsm_exit(nsm_fd);

        match response {
            Response::Attestation { document } => Ok(AttestationDoc::Nitro(document)),
            _ => Err(anyhow!("Unexpected NSM response: {:?}", response))
        }
    }
}

mod mock {
    use std::io;

    use tokio::net::UnixStream;

    use enclave_interface::EnclaveStream;

    pub(crate) async fn establish_connection(socket_file: String) -> io::Result<EnclaveStream> {
        let stream = UnixStream::connect(socket_file.clone()).await?;
        println!("Connected to host as insecure mock enclave: {}", socket_file);
        Ok(EnclaveStream::Unix(stream))
    }
}


fn process_request(encoded_request: Vec<u8>, attestation_doc: &AttestationDoc) -> EnclaveResponse {
    let request_decode_result = EnclaveRequest::decode_all(&mut encoded_request.as_slice());
    println!("Decoded request: {:?}", request_decode_result);
    match request_decode_result {
        Ok(EnclaveRequest::AttestationDoc) =>
            EnclaveResponse::AttestationDoc(attestation_doc.clone()),
        Ok(EnclaveRequest::MixVotes(vote_requests)) => process_mix_votes(&vote_requests),
        Err(scale_error) => EnclaveResponse::Error(Error::Scale(scale_error.to_string())),
    }
}

fn process_mix_votes(vote_requests: &Vec<SignedVoteRequest>) -> EnclaveResponse {
    println!("Received request: {:?}", vote_requests);
    let signatures_valid = vote_requests
        .iter()
        .all(|signed_request| signed_request.is_signature_valid());
    if signatures_valid {
        EnclaveResponse::MixingResult(enclave::mix_votes(&vote_requests))
    } else {
        EnclaveResponse::Error(Error::InvalidSignature)
    }
}
