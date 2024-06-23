use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use rand::random;
use sp_core::crypto::AccountId32;
use sp_core::ed25519;

pub mod attestation;
pub mod nitro;

pub const ENCODING_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Encode, Decode, MaxEncodedLen)]
pub struct VoteRequest {
    pub account: AccountId32,
    pub poll_index: u32,
    pub nonce: u128,
    pub aye: bool,
    pub balance: u128
}

impl VoteRequest {
    pub fn new(account: AccountId32, poll_index: u32, aye: bool, balance: u128) -> Self {
        Self { account, poll_index, nonce: random(), aye, balance }
    }
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct GloveResult {
    pub mixed_votes: Option<MixedVotes>,
    pub signature: ed25519::Signature
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct MixedVotes {
    pub aye: bool,
    /// The randomized mixed balance for the request at the same index. Note, it's possible for a
    /// value to be zero.
    // TODO This needs to be nonce-balance pairs.
    pub balances: Vec<u128>
}
