use std::env::args;

use parity_scale_codec::{DecodeAll, Encode};
use tokio::net::UnixStream;

use enclave_interface::{Error, MixVotesRequest, MixVotesResult, read_len_prefix_bytes, write_len_prefix_bytes};

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

fn process_request(bytes: Vec<u8>) -> MixVotesResult {
    let request = MixVotesRequest::decode_all(&mut bytes.as_slice());
    let result = match request {
        Ok(request) => {
            println!("ENCLAVE> Received request: {:?}", request);
            let signatures_valid = request.requests
                .iter()
                .all(|signed_request| signed_request.is_signature_valid());
            if signatures_valid {
                Ok(enclave::mix_votes(&request.requests))
            } else {
                Err(Error::InvalidSignature)
            }
        }
        Err(error) => {
            println!("ENCLAVE> Unable to decode request: {:?}", error);
            Err(Error::Scale(error.to_string()))
        },
    };
    MixVotesResult { result }
}
