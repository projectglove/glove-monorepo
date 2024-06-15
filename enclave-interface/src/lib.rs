use std::io;

use parity_scale_codec::{Decode, Encode};
use sp_runtime::MultiSignature;
use sp_runtime::traits::Verify;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use common::VoteRequest;

pub type EnclaveRequest = Vec<SignedVoteRequest>;

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct SignedVoteRequest {
    pub request: VoteRequest,
    pub signature: MultiSignature
}

impl SignedVoteRequest {
    pub fn is_signature_valid(&self) -> bool {
        self.signature.verify(self.request.encode().as_slice(), &self.request.account)
    }
}

pub type EnclaveResponse = Result<Option<MixedVotes>, Error>;

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct MixedVotes {
    pub aye: bool,
    /// The randomized mixed balance for the request at the same index. Note, it's possible for a
    /// value to be zero.
    pub balances: Vec<u128>
}

pub async fn write_len_prefix_bytes<W>(writer: &mut W, bytes: &[u8]) -> Result<(), io::Error>
where
    W: AsyncWriteExt + Unpin
{
    writer.write_u32(bytes.len() as u32).await?;
    writer.write_all(bytes).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_len_prefix_bytes<R>(reader: &mut R) -> Result<Vec<u8>, io::Error>
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
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Scale decoding error: {0}")]
    Scale(String)
}
