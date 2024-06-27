use fmt::Formatter;
use std::fmt;
use std::fmt::Display;

use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use rand::random;
use sp_core::crypto::AccountId32;
use sp_core::{ed25519, H256, Pair};

pub mod attestation;
pub mod nitro;

pub const ENCODING_VERSION: u8 = 1;
pub const AYE: u8 = 128;
pub const NAY: u8 = 0;

#[derive(Debug, Clone, PartialEq, Encode, Decode, MaxEncodedLen)]
pub struct VoteRequest {
    pub account: AccountId32,
    #[codec(compact)]
    pub poll_index: u32,
    /// Nonce value to prevent replay attacks. Only needs to be unique for the same poll.
    pub nonce: u32,
    pub aye: bool,
    pub balance: u128
}

impl VoteRequest {
    pub fn new(account: AccountId32, poll_index: u32, aye: bool, balance: u128) -> Self {
        Self { account, poll_index, nonce: random(), aye, balance }
    }
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct SignedGloveResult {
    pub result: GloveResult,
    pub signature: ed25519::Signature
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct GloveResult {
    #[codec(compact)]
    pub poll_index: u32,
    pub vote: GloveVote,
    pub assigned_balances: Vec<AssignedBalance>
}

impl GloveResult {
    pub fn sign(self, key: &ed25519::Pair) -> SignedGloveResult {
        let signature = key.sign(&self.encode());
        SignedGloveResult { result: self, signature }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Encode, Decode)]
pub enum GloveVote {
    Aye,
    Nay,
    Abstain
}

#[derive(Debug, Clone, PartialEq, Encode, Decode, MaxEncodedLen)]
pub struct AssignedBalance {
    pub account: AccountId32,
    pub nonce: u32,
    pub balance: u128
}

#[derive(Debug, Copy, Clone, PartialEq, Encode, Decode, MaxEncodedLen)]
pub struct ExtrinsicLocation {
    pub block_hash: H256,
    /// Index of the extrinsic within the block.
    #[codec(compact)]
    pub block_index: u32
}

impl Display for ExtrinsicLocation {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}-{}", self.block_hash, self.block_index)
    }
}
