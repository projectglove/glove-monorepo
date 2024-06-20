use std::{env, io};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use parity_scale_codec::{DecodeAll, Encode};
use tokio::sync::Mutex;
use tracing::{debug, info};

use enclave_interface::{EnclaveRequest, EnclaveResponse, EnclaveStream};

#[derive(Clone)]
pub struct EnclaveHandle {
    stream: Arc<Mutex<EnclaveStream>>
}

impl EnclaveHandle {
    pub async fn send_request(&self, request: &EnclaveRequest) -> io::Result<EnclaveResponse> {
        let mut stream = self.stream.lock().await;
        stream.write_len_prefix_bytes(&request.encode()).await?;
        let encoded_response = stream.read_len_prefix_bytes().await?;
        let response = EnclaveResponse::decode_all(&mut encoded_response.as_slice())
            .map_err(|scale_error| io::Error::new(io::ErrorKind::InvalidData, scale_error))?;
        Ok(response)
    }
}

#[cfg(target_os = "linux")]
pub mod aws_nitro_enclave {
    use nix::sys::socket::VsockAddr;
    use tokio_vsock::VsockStream;

    use enclave_interface::{NITRO_ENCLAVE_CID, NITRO_ENCLAVE_PORT};

    use super::*;

    /// Connects to an AWS Nitro enclave via a VSOCK connection.
    pub async fn connect() -> io::Result<EnclaveHandle> {
        info!("Connecting to AWS Nitro enclave...");
        let address = VsockAddr::new(NITRO_ENCLAVE_CID, NITRO_ENCLAVE_PORT);
        let stream = VsockStream::connect(address).await?;
        info!("Connected to AWS Nitro enclave");
        Ok(EnclaveHandle { stream: Arc::new(Mutex::new(EnclaveStream::Vsock(stream))) })
    }
}

/// A mock enclave which is just the enclave binary running as a normal process connected via a
/// UNIX socket. There is no security benefit to this implementation, and is only provided for
/// testing purposes.
pub mod mock_enclave {
    use io::ErrorKind::NotFound;

    use tempfile::tempdir;
    use tokio::net::UnixListener;

    use super::*;

    /// Spawns a new mock enclave process and connects to it via a UNIX socket.
    pub async fn spawn() -> io::Result<EnclaveHandle> {
        let temp_dir = tempdir()?;
        let socket_file = temp_dir.path().join("glove.sock");
        let listener = UnixListener::bind(socket_file.clone())?;
        let mut cmd = Command::new(enclave_exec()?);
        cmd.arg(socket_file);
        debug!("Mock enclave cmd: {:?}", cmd);
        let process = cmd.spawn()?;
        info!("Mock enclave process started: {}", process.id());
        let (stream, _) = listener.accept().await?;
        info!("Mock enclave connection established");
        Ok(EnclaveHandle { stream: Arc::new(Mutex::new(EnclaveStream::Unix(stream))) })
    }

    fn enclave_exec() -> io::Result<PathBuf> {
        env::args()
            .nth(0)
            .map(|exe| {
                Path::new(&exe).parent().unwrap_or(Path::new("/")).join("enclave").to_path_buf()
            })
            .filter(|path| path.exists())
            .ok_or_else(|| io::Error::new(
                NotFound,
                "Enclave executable not in the same directory as the service executable",
            ))
    }
}
