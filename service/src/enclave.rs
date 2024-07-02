use io::{Error as IoError, ErrorKind};
use std::{env, io};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use parity_scale_codec::{DecodeAll, Encode};
use tokio::sync::Mutex;
use tracing::{debug, info};

use enclave_interface::EnclaveStream;

#[derive(Clone)]
pub struct EnclaveHandle {
    stream: Arc<Mutex<EnclaveStream>>
}

impl EnclaveHandle {
    pub async fn send_receive<RSP: DecodeAll>(&self, request: &impl Encode) -> io::Result<RSP> {
        let mut stream = self.stream.lock().await;
        stream.write(request).await?;
        stream.read::<RSP>().await
    }
}

#[cfg(target_os = "linux")]
pub mod nitro {
    use nix::sys::socket::VsockAddr;
    use tokio_vsock::VsockListener;

    use enclave_interface::{NITRO_HOST_CID, NITRO_PORT};

    use super::*;

    /// Starts the AWS Nitro enclave and waits for it to connect via VSOCK.
    pub async fn connect(debug_mode: bool) -> io::Result<EnclaveHandle> {
        let mut listener = VsockListener::bind(VsockAddr::new(NITRO_HOST_CID, NITRO_PORT))?;
        let mut cmd = Command::new("nitro-cli");
        cmd.arg("run-enclave");
        cmd.arg("--cpu-count").arg("2");
        cmd.arg("--memory").arg("1024");
        cmd.arg("--eif-path").arg(local_file("glove.eif")?);
        if debug_mode {
            cmd.arg("--debug-mode");
            cmd.arg("--attach-console");
        }
        debug!("AWS Nitro enclave cmd: {:?}", cmd);
        if debug_mode {
            let process = cmd.spawn()?;
            debug!("Process to start AWS Nitro enclave, and capture its output, started: {}",
                process.id());
        } else {
            let output = cmd.output()?;
            if !output.status.success() {
                return Err(IoError::new(
                    ErrorKind::Other,
                    format!("Failed to start AWS Nitro enclave: {:?}", output))
                );
            }
            debug!("AWS Nitro enclave started: {:?}", output);
        }
        let (stream, _) = listener.accept().await?;
        info!("AWS Nitro enclave connection established");
        Ok(EnclaveHandle { stream: Arc::new(Mutex::new(EnclaveStream::Vsock(stream))) })
    }
}

/// A mock enclave which is just the enclave binary running as a normal process connected via a
/// UNIX socket. There is no security benefit to this implementation, and is only provided for
/// testing purposes.
pub mod mock {
    use tempfile::tempdir;
    use tokio::net::UnixListener;

    use super::*;

    /// Spawns a new mock enclave process and connects to it via a UNIX socket.
    pub async fn spawn() -> io::Result<EnclaveHandle> {
        let temp_dir = tempdir()?;
        let socket_file = temp_dir.path().join("glove.sock");
        let listener = UnixListener::bind(socket_file.clone())?;
        let mut cmd = Command::new(local_file("enclave")?);
        cmd.arg(socket_file);
        debug!("Mock enclave cmd: {:?}", cmd);
        let process = cmd.spawn()?;
        debug!("Mock enclave process started: {}", process.id());
        let (stream, _) = listener.accept().await?;
        info!("Mock enclave connection established");
        Ok(EnclaveHandle { stream: Arc::new(Mutex::new(EnclaveStream::Unix(stream))) })
    }
}

fn local_file(file: &str) -> io::Result<PathBuf> {
    env::args()
        .nth(0)
        .map(|exe| Path::new(&exe).parent().unwrap_or(Path::new("/")).join(file).to_path_buf())
        .filter(|path| path.exists())
        .ok_or_else(|| IoError::new(
            ErrorKind::NotFound,
            format!("'{}' executable not in the same directory as the service executable", file),
        ))
}