use fmt::Formatter;
use std::fmt;
use std::fmt::Display;

use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use rand::random;
use serde::{Deserialize, Serialize};
use sp_core::{ed25519, H256, Pair};
use sp_core::crypto::AccountId32;
use sp_runtime::MultiSignature;
use sp_runtime::traits::Verify;

pub mod attestation;
pub mod nitro;

pub const ENCODING_VERSION: u8 = 1;
pub const BASE_AYE: u8 = 128;
pub const BASE_NAY: u8 = 0;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, MaxEncodedLen)]
pub struct SignedVoteRequest {
    #[serde(with = "serde_over_hex_scale")]
    pub request: VoteRequest,
    #[serde(with = "serde_over_hex_scale")]
    pub signature: MultiSignature
}

impl SignedVoteRequest {
    pub fn verify(&self) -> bool {
        self.signature.verify(&*self.request.encode(), &self.request.account)
    }
}

#[derive(Debug, Clone, PartialEq, Encode, Decode, MaxEncodedLen)]
pub struct VoteRequest {
    pub account: AccountId32,
    pub genesis_hash: H256,
    #[codec(compact)]
    pub poll_index: u32,
    /// Nonce value to prevent replay attacks. Only needs to be unique for the same poll.
    pub nonce: u32,
    pub aye: bool,
    pub balance: u128,
    pub conviction: Conviction,
}

#[derive(Debug, Copy, Clone, PartialEq, Encode, Decode, MaxEncodedLen)]
pub enum Conviction {
    None,
    Locked1x,
    Locked2x,
    Locked3x,
    Locked4x,
    Locked5x,
    Locked6x,
}

impl VoteRequest {
    pub fn new(
        account: AccountId32,
        genesis_hash: H256,
        poll_index: u32,
        aye: bool,
        balance: u128,
        conviction: Conviction
    ) -> Self {
        Self { account, genesis_hash, poll_index, nonce: random(), aye, balance, conviction }
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
    pub balance: u128,
    pub conviction: Conviction
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

/// If any field should be serialised by serde in its SCALE encoding, then annotate it with
/// `#[serde(with = "common::serde_over_hex_scale")]`. The binary SCALE encoding will be serialised
/// as a hex string.
pub mod serde_over_hex_scale {
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Deserializer, Serializer};
    use serde::de::Error;

    pub fn serialize<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: Encode,
        S: Serializer
    {
        serializer.serialize_str(&hex::encode(value.encode()))
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where
        T: Decode,
        D: Deserializer<'de>
    {
        let bytes = hex::decode(String::deserialize(deserializer)?).map_err(Error::custom)?;
        T::decode(&mut bytes.as_slice()).map_err(Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use parity_scale_codec::Encode;
    use rand::random;
    use serde_json::{json, Value};
    use sp_core::{Pair, sr25519};

    use Conviction::{Locked3x, Locked6x};

    use super::*;

    #[test]
    fn signed_vote_request_json_verify() {
        let (pair, _) = sr25519::Pair::generate();

        let request = VoteRequest::new(
            pair.public().into(),
            random::<[u8; 32]>().into(),
            11,
            true,
            100,
            Locked3x
        );
        let encoded_request = request.encode();
        let signature: MultiSignature = pair.sign(encoded_request.as_slice()).into();

        let signed_request = SignedVoteRequest { request, signature };
        assert_eq!(signed_request.verify(), true);

        let json = serde_json::to_string(&signed_request).unwrap();
        println!("{}", json);

        assert_eq!(
            serde_json::from_str::<Value>(&json).unwrap(),
            json!({
                "request": hex::encode(&signed_request.request.encode()),
                "signature": hex::encode(&signed_request.signature.encode())
            })
        );

        let deserialized_signed_request: SignedVoteRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized_signed_request, signed_request);
    }

    #[test]
    fn different_signer_to_vote_request_account() {
        let (pair1, _) = sr25519::Pair::generate();
        let (pair2, _) = sr25519::Pair::generate();

        let request = VoteRequest::new(
            pair1.public().into(),
            random::<[u8; 32]>().into(),
            11,
            true,
            100,
            Locked3x
        );
        let encoded_request = request.encode();
        let signature: MultiSignature = pair2.sign(encoded_request.as_slice()).into();

        let signed_request = SignedVoteRequest { request, signature };
        assert_eq!(signed_request.verify(), false);

        let json = serde_json::to_string(&signed_request).unwrap();
        let deserialized_signed_request: SignedVoteRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized_signed_request, signed_request);
        assert_eq!(deserialized_signed_request.verify(), false);
    }

    #[test]
    fn modified_vote_request() {
        let (pair, _) = sr25519::Pair::generate();

        let original_request = VoteRequest::new(
            pair.public().into(),
            random::<[u8; 32]>().into(),
            11,
            true,
            100,
            Locked6x
        );
        let signature: MultiSignature = pair.sign(&original_request.encode()).into();

        let signed_request = SignedVoteRequest {
            request: {
                let mut modified_request = original_request.clone();
                modified_request.aye = !original_request.aye;
                modified_request
            },
            signature
        };
        assert_eq!(signed_request.verify(), false);


        let json = serde_json::to_string(&signed_request).unwrap();
        let deserialized: SignedVoteRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, signed_request);
        assert_eq!(deserialized.verify(), false);
    }
}
