use io::ErrorKind::NotFound;
use std::{env, io};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use axum::async_trait;
use tempfile::tempdir;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tracing::{debug, info};

use enclave_interface::{read_len_prefix_bytes, write_len_prefix_bytes};

#[async_trait]
pub trait EnclaveHandle: Send + Sync {
    async fn send_and_receive(&self, msg: &[u8]) -> io::Result<Vec<u8>>;
}

/// A mock enclave which is just the enclave binary running as a normal process connected via a UNIX socket. There is no security
/// benefit to this implementation, and is only provided for testing purposes.
#[derive(Clone)]
pub struct MockEnclaveHandle {
    stream: Arc<Mutex<UnixStream>>
}

impl MockEnclaveHandle {
    pub async fn spawn() -> io::Result<Self> {
        let temp_dir = tempdir()?;
        let socket_file = temp_dir.path().join("glove.sock");
        let listener = UnixListener::bind(socket_file.clone())?;
        let mut cmd = Command::new(Self::enclave_exec()?);
        cmd.arg(socket_file);
        debug!("Mock enclave cmd: {:?}", cmd);
        let process = cmd.spawn()?;
        info!("Mock enclave process started: {}", process.id());
        let (stream, _) = listener.accept().await?;
        info!("Mock enclave connection established");
        Ok(Self { stream: Arc::new(Mutex::new(stream)) })
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

#[async_trait]
impl EnclaveHandle for MockEnclaveHandle {
    async fn send_and_receive(&self, msg: &[u8]) -> io::Result<Vec<u8>> {
        let mut stream = self.stream.lock().await;
        write_len_prefix_bytes(&mut *stream, msg).await?;
        read_len_prefix_bytes(&mut *stream).await
    }
}
