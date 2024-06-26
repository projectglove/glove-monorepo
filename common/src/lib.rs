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

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct SignedGloveResult {
    pub result: GloveResult,
    pub signature: ed25519::Signature
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct GloveResult {
    pub poll_index: u32,
    pub result_type: ResultType
}

impl GloveResult {
    pub fn sign(self, key: &ed25519::Pair) -> SignedGloveResult {
        let signature = key.sign(&self.encode());
        SignedGloveResult { result: self, signature }
    }
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub enum ResultType {
    Standard(StandardResult),
    Abstain(AbstainResult)
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct StandardResult {
    pub aye: bool,
    pub assigned_balances: Vec<AssignedBalance>
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct AbstainResult {
    pub nonces: Vec<u128>
}

#[derive(Debug, Copy, Clone, PartialEq, Encode, Decode, MaxEncodedLen)]
pub struct AssignedBalance {
    pub nonce: u128,
    pub balance: u128
}

#[derive(Debug, Copy, Clone, PartialEq, Encode, Decode, MaxEncodedLen)]
pub struct ExtrinsicLocation {
    pub block_hash: H256,
    /// Index of the extrinsic within the block.
    #[codec(compact)]
    pub block_index: u32,
    /// If present, [block_hash] and [index] point to one of the batch extrinsics, and this is the
    /// index of the extrinsic within the batch.
    pub batch_index: Option<u32>
}
