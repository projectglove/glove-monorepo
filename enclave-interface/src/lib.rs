use std::io;

use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use sp_runtime::MultiSignature;
use sp_runtime::traits::Verify;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use common::{GloveResult, VoteRequest};
use common::attestation::AttestationBundle;

/// The parent EC2 instance always has a CID of 3.
pub const NITRO_HOST_CID: u32 = 3;

/// Well-known VSOCK port the enclave process will listen on.
pub const NITRO_PORT: u32 = 5000;

#[derive(Debug, Clone, Encode, Decode)]
pub enum EnclaveRequest {
    Attestation,
    MixVotes(Vec<SignedVoteRequest>),
}

#[derive(Debug, Clone, PartialEq, Encode, Decode, MaxEncodedLen)]
pub struct SignedVoteRequest {
    pub request: VoteRequest,
    pub signature: MultiSignature
}

impl SignedVoteRequest {
    pub fn is_signature_valid(&self) -> bool {
        self.signature.verify(&*self.request.encode(), &self.request.account)
    }
}

#[derive(Debug, Clone, Encode, Decode)]
pub enum EnclaveResponse {
    Attestation(AttestationBundle),
    GloveResult(GloveResult),
    Error(Error)
}

pub enum EnclaveStream {
    #[cfg(target_os = "linux")]
    Vsock(tokio_vsock::VsockStream),
    Unix(tokio::net::UnixStream)
}

impl EnclaveStream {
    pub async fn write_len_prefix_bytes(&mut self, bytes: &[u8]) -> io::Result<()> {
        match self {
            #[cfg(target_os = "linux")]
            EnclaveStream::Vsock(stream) => write_len_prefix_bytes(stream, bytes).await,
            EnclaveStream::Unix(stream) => write_len_prefix_bytes(stream, bytes).await
        }
    }

    pub async fn read_len_prefix_bytes(&mut self) -> io::Result<Vec<u8>> {
        match self {
            #[cfg(target_os = "linux")]
            EnclaveStream::Vsock(stream) => read_len_prefix_bytes(stream).await,
            EnclaveStream::Unix(stream) => read_len_prefix_bytes(stream).await
        }
    }
}

async fn write_len_prefix_bytes<W>(writer: &mut W, bytes: &[u8]) -> io::Result<()>
where
    W: AsyncWriteExt + Unpin
{
    writer.write_u32(bytes.len() as u32).await?;
    writer.write_all(bytes).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_len_prefix_bytes<R>(reader: &mut R) -> io::Result<Vec<u8>>
where
    R: AsyncReadExt + Unpin
{
    let len = reader.read_u32().await?;
    let mut buffer =  vec![0; len as usize];
    reader.read_exact(&mut buffer).await?;
    Ok(buffer)
}

#[derive(thiserror::Error, Clone, Debug, Encode, Decode)]
pub enum Error {
    #[error("Invalid signature on voting requests")]
    InvalidSignature,
    #[error("Scale decoding error: {0}")]
    Scale(String),
}
