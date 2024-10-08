use fmt::Formatter;
use std::fmt;
use std::fmt::Display;
use std::str::FromStr;

use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use rand::random;
use serde::{Deserialize, Serialize};
use sp_core::crypto::AccountId32;
use sp_core::{ed25519, Pair, H256};
use sp_runtime::traits::Verify;
use sp_runtime::MultiSignature;

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
    pub signature: MultiSignature,
}

impl SignedVoteRequest {
    pub fn verify(&self) -> bool {
        verify_js_payload(&self.signature, &self.request, &self.request.account)
    }
}

const JS_SIGNING_PREFIX: &[u8] = b"<Bytes>";
const JS_SIGNING_POSTFIX: &[u8] = b"</Bytes>";

/// Verify a signed SCALE encoded payload which can possibly orginate from Polkadot JS.
///
/// The `signRaw` function in Polkadot JS wraps the bytes to be signed with `<Bytes>` and
/// `</Bytes>`. So verification needs to be tried with and without this wrapping.
pub fn verify_js_payload<E: Encode>(
    signature: &MultiSignature,
    payload: &E,
    account: &AccountId32,
) -> bool {
    let capacity = JS_SIGNING_PREFIX.len() + payload.size_hint() + JS_SIGNING_POSTFIX.len();
    let mut wrapped_bytes = Vec::with_capacity(capacity);
    wrapped_bytes.extend_from_slice(JS_SIGNING_PREFIX);
    payload.encode_to(&mut wrapped_bytes);
    let before_postfix = wrapped_bytes.len();
    wrapped_bytes.extend_from_slice(JS_SIGNING_POSTFIX);
    let encoded_payload = &wrapped_bytes[JS_SIGNING_PREFIX.len()..before_postfix];
    signature.verify(&*wrapped_bytes, account) || signature.verify(encoded_payload, account)
}

#[derive(Debug, Clone, PartialEq, Encode, Decode, MaxEncodedLen)]
pub struct VoteRequest {
    /// The account on whose behalf the Glove proxy will vote for.
    pub account: AccountId32,
    /// The genesis hash of the substrate chain where the poll is taking place. This is necessary
    /// to ensure the vote is not replayed on a different chain.
    pub genesis_hash: H256,
    /// The index of the poll/referendum.
    #[codec(compact)]
    pub poll_index: u32,
    /// Nonce value to prevent replay attacks. Needs to be unique for the same poll.
    pub nonce: u32,
    /// `true` for aye, `false` for nay.
    pub aye: bool,
    /// The amount of tokens to vote with. The units are in
    /// [Planck](https://wiki.polkadot.network/docs/learn-DOT#the-planck-unit).
    pub balance: u128,
    pub conviction: Conviction,
}

/// Conviction voting multiplier.
///
/// See [here](https://wiki.polkadot.network/docs/learn-polkadot-opengov#voluntary-locking-conviction-voting)
/// for more details.
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
        conviction: Conviction,
    ) -> Self {
        Self {
            account,
            genesis_hash,
            poll_index,
            nonce: random(),
            aye,
            balance,
            conviction,
        }
    }
}

/// Signed Glove result from an enclave. The signature can be verified using `signing_key` from
/// the [`attestation::AttestedData`].
#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct SignedGloveResult {
    pub result: GloveResult,
    /// Signature of `result` in SCALE endoding.
    pub signature: ed25519::Signature,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct GloveResult {
    #[codec(compact)]
    pub poll_index: u32,
    pub direction: VoteDirection,
    pub assigned_balances: Vec<AssignedBalance>,
}

impl GloveResult {
    pub fn sign(self, key: &ed25519::Pair) -> SignedGloveResult {
        let signature = key.sign(&self.encode());
        SignedGloveResult {
            result: self,
            signature,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Encode, Decode)]
pub enum VoteDirection {
    Aye,
    Nay,
    Abstain,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode, MaxEncodedLen)]
pub struct AssignedBalance {
    pub account: AccountId32,
    pub nonce: u32,
    pub balance: u128,
    pub conviction: Conviction,
}

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    MaxEncodedLen,
)]
pub struct ExtrinsicLocation {
    pub block_number: u32,
    /// Index of the extrinsic within the block.
    #[codec(compact)]
    pub extrinsic_index: u32,
}

impl Display for ExtrinsicLocation {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}-{}", self.block_number, self.extrinsic_index)
    }
}

impl FromStr for ExtrinsicLocation {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (block_number, extrinsic_index) = s
            .split_once('-')
            .ok_or("Invalid ExtrinsicLocation format")?;
        let block_number = block_number.parse().map_err(|_| "Invalid block number")?;
        let extrinsic_index = extrinsic_index
            .parse()
            .map_err(|_| "Invalid extrinsic index")?;
        Ok(ExtrinsicLocation {
            block_number,
            extrinsic_index,
        })
    }
}

/// If any field should be serialised by serde in its SCALE encoding, then annotate it with
/// `#[serde(with = "common::serde_over_hex_scale")]`. The binary SCALE encoding will be serialised
/// as a hex string.
pub mod serde_over_hex_scale {
    use parity_scale_codec::{Decode, Encode};
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};
    use sp_core::bytes::from_hex;
    use subxt::utils::to_hex;

    pub fn serialize<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: Encode,
        S: Serializer,
    {
        serializer.serialize_str(&to_hex(value.encode()))
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where
        T: Decode,
        D: Deserializer<'de>,
    {
        let bytes = from_hex(&String::deserialize(deserializer)?).map_err(Error::custom)?;
        T::decode(&mut bytes.as_slice()).map_err(Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use parity_scale_codec::Encode;
    use rand::random;
    use serde_json::{json, Value};
    use sp_core::bytes::to_hex;
    use sp_core::{sr25519, Pair};
    use subxt_signer::sr25519::dev;

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
            Locked3x,
        );
        let encoded_request = request.encode();
        let signature: MultiSignature = pair.sign(encoded_request.as_slice()).into();

        let signed_request = SignedVoteRequest { request, signature };
        assert!(signed_request.verify());

        let json = serde_json::to_string(&signed_request).unwrap();
        println!("{}", json);

        assert_eq!(
            serde_json::from_str::<Value>(&json).unwrap(),
            json!({
                "request": to_hex(&signed_request.request.encode(), false),
                "signature": to_hex(&signed_request.signature.encode(), false)
            })
        );

        let deserialized_signed_request: SignedVoteRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized_signed_request, signed_request);
    }

    #[test]
    fn signed_vote_request_json_using_polkadot_js_keyring() {
        // Produced from test-resources/vote-request-example.mjs
        let json = r#"
{
  "request": "0x8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a486408de7737c59c238890533af25896a2c20608d8b380bb01029acb392781063ee502f5c1912301009c5b3607020000000000000000000002",
  "signature": "0x01ea13f59165bc295d1e99629622dc0c13a1c7163017359178606f0e36d1d2c246c021190cf0508b0d60d292a00ba06ed396d5559fe7334c78c95bf289e84ebc81"
}
"#;

        let signed_request = serde_json::from_str::<SignedVoteRequest>(json).unwrap();
        println!("{:#?}", signed_request);
        assert!(signed_request.verify());
        let request = signed_request.request;
        assert_eq!(request.account, dev::bob().public_key().0.into());
        assert_eq!(request.poll_index, 185);
        assert_eq!(
            request.genesis_hash,
            H256::from_str("6408de7737c59c238890533af25896a2c20608d8b380bb01029acb392781063e")
                .unwrap()
        );
        assert_eq!(request.balance, 2230000000000);
        assert!(request.aye);
        assert_eq!(request.conviction, Conviction::Locked2x);
    }

    #[test]
    fn signed_vote_request_json_using_polkadot_js_signraw() {
        // Produced from Glove frontend
        let json = r#"
{
  "request": "0x28836d6f19d5cd8dd8b26da754c63ae337c6f938a7dc6a12e439ad8a1c69fb0d6408de7737c59c238890533af25896a2c20608d8b380bb01029acb392781063e6503b71b731f0000ac000bf0020000000000000000000004",
  "signature": "0x017ac41d7c8de53116b37e5205ba0c20900fc04f4cf25cfa78bceb2b91e0b1fc26c08c52be1b0d73dd1856b8673d9f878df244bae898d2f22e28029ee51fe20e89"
}
"#;
        let signed_request = serde_json::from_str::<SignedVoteRequest>(json).unwrap();
        println!("{:#?}", signed_request);
        assert!(signed_request.verify());
        let request = signed_request.request;
        assert_eq!(
            request.account,
            AccountId32::from_str("5CyppCnQKiuY9c22yjHbDTpCqeHzAt7GXQpFAURxycWTS8My").unwrap()
        );
        assert_eq!(request.poll_index, 217);
        assert_eq!(
            request.genesis_hash,
            H256::from_str("6408de7737c59c238890533af25896a2c20608d8b380bb01029acb392781063e")
                .unwrap()
        );
        assert_eq!(request.balance, 3230000000000);
        assert!(!request.aye);
        assert_eq!(request.conviction, Conviction::Locked4x);
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
            Locked3x,
        );
        let encoded_request = request.encode();
        let signature: MultiSignature = pair2.sign(encoded_request.as_slice()).into();

        let signed_request = SignedVoteRequest { request, signature };
        assert!(!signed_request.verify());

        let json = serde_json::to_string(&signed_request).unwrap();
        let deserialized_signed_request: SignedVoteRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized_signed_request, signed_request);
        assert!(!deserialized_signed_request.verify());
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
            Locked6x,
        );
        let signature: MultiSignature = pair.sign(&original_request.encode()).into();

        let signed_request = SignedVoteRequest {
            request: {
                let mut modified_request = original_request.clone();
                modified_request.aye = !original_request.aye;
                modified_request
            },
            signature,
        };
        assert!(!signed_request.verify());

        let json = serde_json::to_string(&signed_request).unwrap();
        let deserialized: SignedVoteRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, signed_request);
        assert!(!deserialized.verify());
    }
}
