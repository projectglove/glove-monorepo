use std::io::{Read, Write};

use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use parity_scale_codec::{Decode, DecodeAll, Encode, MaxEncodedLen};
use parity_scale_codec::Error as ScaleError;
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use sp_core::{ed25519, H256, Pair};

use crate::{ExtrinsicLocation, nitro, SignedGloveResult};

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct GloveProof {
    pub signed_result: SignedGloveResult,
    pub attestation_bundle: AttestationBundle
}

impl GloveProof {
    pub fn verify_components(
        signed_result: &SignedGloveResult,
        attestation_bundle: &AttestationBundle
    ) -> Result<EnclaveInfo, Error> {
        // If the attestation bundle is valid, then it means the signing key contained within it is
        // from a genuine secure enclave.
        let enclave_info = attestation_bundle.verify()?;
        // If the signature in the Gkove proof is valid, then it means the result was produced by
        // the enclave.
        let valid = <ed25519::Pair as Pair>::verify(
            &signed_result.signature,
            signed_result.result.encode(),
            &attestation_bundle.attested_data.signing_key
        );
        valid.then_some(enclave_info).ok_or(Error::GloveProof)
    }

    pub fn verify(&self) -> Result<EnclaveInfo, Error> {
        Self::verify_components(&self.signed_result, &self.attestation_bundle)
    }
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct AttestationBundle {
    pub attested_data: AttestedData,
    pub attestation: Attestation
}

/// The current encoding version for the attestation bundle envelope.
///
/// A value of 1 indicates GZipped SCALE encoding.
pub const ATTESTATION_BUNDLE_ENCODING_VERSION: u8 = 1;

impl AttestationBundle {
    ///
    pub fn verify(&self) -> Result<EnclaveInfo, Error> {
        match &self.attestation {
            Attestation::Nitro(nitro_attestation) => {
                let attestation_doc = nitro_attestation.verify()?;
                let image_measurement = attestation_doc.pcrs
                    .get(&0)
                    .filter(|pcr0| pcr0.iter().any(|&byte| byte != 0))  // All zeros means debug mode
                    .map(|pcr0| pcr0.to_vec())
                    .ok_or(Error::InsecureMode)?;
                let attested_data_hash = Sha256::digest(&self.attested_data.encode()).to_vec();
                (attestation_doc.user_data == Some(ByteBuf::from(attested_data_hash)))
                    .then(|| EnclaveInfo::Nitro(nitro::EnclaveInfo { image_measurement }))
                    .ok_or(Error::AttestedData)
            }
            Attestation::Mock => Err(Error::InsecureMode)
        }
    }

    /// Encode with a version prefix byte to indicate the encoding version.
    pub fn encode_envelope(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(ATTESTATION_BUNDLE_ENCODING_VERSION);
        let mut gzip = GzEncoder::new(&mut bytes, Compression::default());
        gzip.write_all(&self.encode()).unwrap();
        gzip.finish().unwrap();
        bytes
    }

    pub fn decode_envelope(bytes: &[u8]) -> Result<Self, ScaleError> {
        let version = bytes
            .get(0)
            .ok_or_else(|| ScaleError::from("Empty bytes"))?;
        if *version != ATTESTATION_BUNDLE_ENCODING_VERSION {
            return Err(ScaleError::from("Unknown encoding version"));
        }
        let mut gunzip = GzDecoder::new(&bytes[1..]);
        let mut uncompressed_bytes = Vec::new();
        gunzip.read_to_end(&mut uncompressed_bytes)?;
        Self::decode_all(&mut uncompressed_bytes.as_slice())
    }
}

#[derive(Debug, Clone, PartialEq, Encode, Decode, MaxEncodedLen)]
pub struct AttestedData {
    pub genesis_hash: H256,
    pub signing_key: ed25519::Public
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub enum Attestation {
    Nitro(nitro::Attestation),
    Mock
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub enum EnclaveInfo {
    Nitro(nitro::EnclaveInfo)
}

/// A version of [GloveProof] that contains a location pointer to the [AttestationBundle] instead of
/// the bundle itself.
#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct GloveProofLite {
    pub signed_result: SignedGloveResult,
    pub attestation_location: AttestationBundleLocation,
}

pub const GLOVE_PROOF_LITE_ENCODING_VERSION: u8 = 1;

impl GloveProofLite {
    pub fn encode_envelope(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1 + self.size_hint());
        bytes.push(GLOVE_PROOF_LITE_ENCODING_VERSION);
        let _ = &self.encode_to(&mut bytes);
        bytes
    }

    pub fn decode_envelope(bytes: &[u8]) -> Result<Self, ScaleError> {
        let version = bytes
            .get(0)
            .ok_or_else(|| ScaleError::from("Empty bytes"))?;
        if *version != GLOVE_PROOF_LITE_ENCODING_VERSION {
            return Err(ScaleError::from("Unknown encoding version"));
        }
        Self::decode_all(&mut &bytes[1..])
    }
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub enum AttestationBundleLocation {
    SubstrateRemark(ExtrinsicLocation),
    // Http(String)
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("AWS Nitro attestation verification error: {0}")]
    Nitro(#[from] nitro::Error),
    #[error("Insecure enclave mode")]
    InsecureMode,
    #[error("Attested data does not match attestation")]
    AttestedData,
    #[error("Invalid Glove proof signature")]
    GloveProof
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use sp_core::crypto::AccountId32;

    use Attestation::Nitro;

    use crate::{AssignedBalance, Conviction, GloveResult, GloveVote, nitro};
    use crate::attestation::Attestation::Mock;

    use super::*;

    static SECURE_NITRO_ATTESTATION_BUNDLE_BYTES: &[u8] = include_bytes!("../test-resources/secure-nitro-attestation-bundle-envelope");
    static DEBUG_NITRO_ATTESTATION_BUNDLE_BYTES: &[u8] = include_bytes!("../test-resources/debug-nitro-attestation-bundle-envelope");
    static GLOVE_PROOF_LITE_BYTES: &[u8] = include_bytes!("../test-resources/glove-proof-lite");
    static RAW_NITRO_ATTESTATION_DOC_BYTES: &[u8] = include_bytes!("../test-resources/raw-aws-nitro-attestation-doc");

    #[test]
    fn secure_nitro_attestation_bundle_sample() {
        let attestation_bundle = AttestationBundle::decode_envelope(SECURE_NITRO_ATTESTATION_BUNDLE_BYTES).unwrap();
        attestation_bundle.verify().unwrap();
        assert_eq!(attestation_bundle.attested_data.genesis_hash, H256::from_str("6408de7737c59c238890533af25896a2c20608d8b380bb01029acb392781063e").unwrap());
        assert!(matches!(attestation_bundle.attestation, Nitro(_)));

        let envelope_encoding = attestation_bundle.encode_envelope();
        let roundtrip = AttestationBundle::decode_envelope(&envelope_encoding).unwrap();
        // Basic check for the compression
        assert!(envelope_encoding.len() < attestation_bundle.encode().len());
        assert_eq!(attestation_bundle, roundtrip);
    }

    #[test]
    fn valid_glove_proof_lite_sample() {
        let glove_proof_lite = GloveProofLite::decode_envelope(GLOVE_PROOF_LITE_BYTES).unwrap();

        assert_eq!(
            glove_proof_lite.signed_result.result,
            GloveResult {
                poll_index: 185,
                vote: GloveVote::Nay,
                assigned_balances: vec![
                    AssignedBalance {
                        account: AccountId32::from_str("28836d6f19d5cd8dd8b26da754c63ae337c6f938a7dc6a12e439ad8a1c69fb0d").unwrap(),
                        nonce: 1406474393,
                        balance: 870545507137,
                        conviction: Conviction::None
                    },
                    AssignedBalance {
                        account: AccountId32::from_str("841f65d84a0ffa95b378923a0d879f188d2a4aa5cb0f97df84fb296788cb6e3e").unwrap(),
                        nonce: 3000217442,
                        balance: 7277014506261,
                        conviction: Conviction::Locked1x
                    },
                    AssignedBalance {
                        account: AccountId32::from_str("ca22927dff5da60838b78763a2b5ebdf080fa4f35bcbfc8c36b3b6c59a85cd6f").unwrap(),
                        nonce:  3352555571,
                        balance: 3691529986602,
                        conviction: Conviction::Locked3x
                    }
                ]
            }
        );

        assert_eq!(
            glove_proof_lite.attestation_location,
            AttestationBundleLocation::SubstrateRemark(ExtrinsicLocation {
                block_hash: H256::from_str("d7663e131edda194eabbec3ac5695e5b31c9e576e144025956e0cdbf90d4f9cb").unwrap(),
                block_index: 2,
            })
        );

        let roundtrip = GloveProofLite::decode_envelope(&glove_proof_lite.encode_envelope()).unwrap();
        assert_eq!(glove_proof_lite, roundtrip);
    }

    #[test]
    fn valid_glove_proof_sample() {
        let attestation_bundle = AttestationBundle::decode_envelope(SECURE_NITRO_ATTESTATION_BUNDLE_BYTES).unwrap();
        let glove_proof_lite = GloveProofLite::decode_envelope(GLOVE_PROOF_LITE_BYTES).unwrap();
        let glove_proof = GloveProof {
            signed_result: glove_proof_lite.signed_result,
            attestation_bundle
        };
        glove_proof.verify().unwrap();
    }

    #[test]
    fn invalid_glove_proof() {
        let attestation_bundle = AttestationBundle::decode_envelope(SECURE_NITRO_ATTESTATION_BUNDLE_BYTES).unwrap();
        let original_glove_result = GloveProofLite::decode_envelope(GLOVE_PROOF_LITE_BYTES).unwrap().signed_result.result;

        let mut modified_glove_result = original_glove_result.clone();
        modified_glove_result.vote = GloveVote::Aye;
        assert_ne!(original_glove_result, modified_glove_result);

        let invalid_glove_proof = GloveProof {
            signed_result: modified_glove_result.sign(&ed25519::Pair::generate().0),
            attestation_bundle
        };
        assert!(matches!(invalid_glove_proof.verify(), Err(Error::GloveProof)));
    }

    #[test]
    fn debug_nitro_attestation_bundle_sample() {
        let attestation_bundle = AttestationBundle::decode_envelope(DEBUG_NITRO_ATTESTATION_BUNDLE_BYTES).unwrap();
        assert!(matches!(attestation_bundle.attestation, Nitro(_)));
        assert!(matches!(attestation_bundle.verify(), Err(Error::InsecureMode)));
    }

    #[test]
    fn mock_attestation_bundle() {
        let attestation_bundle = AttestationBundle {
            attested_data: AttestedData {
                genesis_hash: Default::default(),
                signing_key: ed25519::Pair::generate().0.public()
            },
            attestation: Mock
        };
        assert!(matches!(attestation_bundle.verify(), Err(Error::InsecureMode)));
    }

    #[test]
    fn attested_data_mismatch_in_attestation_bundle() {
        let attestation_bundle = AttestationBundle {
            attested_data: AttestedData {
                genesis_hash: Default::default(),
                signing_key: ed25519::Pair::generate().0.public()
            },
            attestation: Nitro(nitro::Attestation::try_from(RAW_NITRO_ATTESTATION_DOC_BYTES).unwrap())
        };
        assert!(matches!(attestation_bundle.verify(), Err(Error::AttestedData)));
    }
}
