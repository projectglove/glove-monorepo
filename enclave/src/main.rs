use std::env::args;

use parity_scale_codec::{DecodeAll, Encode};
use tokio::net::UnixStream;

use enclave_interface::{Error, EnclaveResponse, read_len_prefix_bytes, write_len_prefix_bytes, EnclaveRequest};

// The Glove enclave is a simple process which listens for vote mixing requests on a UNIX socket.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let socket_file = args().nth(1).unwrap();
    let mut stream = UnixStream::connect(socket_file.clone()).await?;
    println!("ENCLAVE> Connected to socket: {}", socket_file);
    loop {
        let bytes = read_len_prefix_bytes(&mut stream).await?;
        let result = process_request(bytes);
        println!("ENCLAVE> Sending result: {:?}", result);
        write_len_prefix_bytes(&mut stream, &result.encode()).await?;
    }
}

fn process_request(bytes: Vec<u8>) -> EnclaveResponse {
    match EnclaveRequest::decode_all(&mut bytes.as_slice()) {
        Ok(enclave_request) => {
            println!("ENCLAVE> Received request: {:?}", enclave_request);
            let signatures_valid = enclave_request
                .iter()
                .all(|signed_request| signed_request.is_signature_valid());
            if signatures_valid {
                Ok(enclave::mix_votes(&enclave_request))
            } else {
                Err(Error::InvalidSignature)
            }
        }
        Err(scale_error) => Err(Error::Scale(scale_error.to_string())),
    }
}
