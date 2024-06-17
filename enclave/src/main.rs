use std::env::args;
use std::io;

use cfg_if::cfg_if;
use parity_scale_codec::{DecodeAll, Encode};
use tokio::net::UnixStream;

use enclave_interface::{EnclaveRequest, EnclaveResponse, EnclaveStream, Error};

// The Glove enclave is a simple process which listens for vote mixing requests.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    cfg_if! {
        if #[cfg(target_os = "linux")] {
            let mut stream = match args().nth(1) {
                Some(socket_file) => establish_mock_connection(socket_file).await?,
                None => establish_vsock_connection().await?
            };
        } else {
            let mut stream = establish_mock_connection(args().nth(1).unwrap()).await?;
        }
    }

    loop {
        let bytes = stream.read_len_prefix_bytes().await?;
        let result = process_request(bytes);
        println!("ENCLAVE> Sending result: {:?}", result);
        stream.write_len_prefix_bytes(&result.encode()).await?;
    }
}

#[cfg(target_os = "linux")]
async fn establish_vsock_connection() -> io::Result<EnclaveStream> {
    // The CID used by the parent AWS host instance is always 3
    let address = nix::sys::socket::VsockAddr::new(3, enclave_interface::NITRO_ENCLAVE_PORT);
    let mut listener = tokio_vsock::VsockListener::bind(address)?;
    println!("ENCLAVE> Waiting for VSOCK connection from AWS host VM...");
    let (stream, _) = listener.accept().await?;
    println!("ENCLAVE> AWS host connected");
    Ok(EnclaveStream::Vsock(stream))
}

async fn establish_mock_connection(socket_file: String) -> io::Result<EnclaveStream> {
    let stream = UnixStream::connect(socket_file.clone()).await?;
    println!("ENCLAVE> Connected to host as insecure mock enclave: {}", socket_file);
    Ok(EnclaveStream::Unix(stream))
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
