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
    use Attestation::Nitro;

    use crate::{AssignedBalance, GloveResult, GloveVote, nitro};
    use crate::attestation::Attestation::Mock;

    use super::*;

    static SAMPLE_NITRO_ATTESTATION_BYTES: &[u8] = include_bytes!("../sample-aws-nitro-attestation-doc");

    // TODO Test for Nitro debug mode
    // TODO Test valid glove proof
    // TODO Test invalid glove proof

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
            attestation: Nitro(nitro::Attestation::try_from(SAMPLE_NITRO_ATTESTATION_BYTES).unwrap())
        };
        assert!(matches!(attestation_bundle.verify(), Err(Error::AttestedData)));
    }

    #[test]
    fn attestation_bundle_envelope_encoding() {
        let original = AttestationBundle {
            attested_data: AttestedData {
                genesis_hash: Default::default(),
                signing_key: ed25519::Pair::generate().0.public()
            },
            attestation: Nitro(nitro::Attestation::try_from(SAMPLE_NITRO_ATTESTATION_BYTES).unwrap())
        };

        let envelope_encoding = original.encode_envelope();
        let scale_encoding = original.encode();
        let roundtrip = AttestationBundle::decode_envelope(&envelope_encoding).unwrap();
        // Basic check for the compression
        assert!(envelope_encoding.len() < scale_encoding.len());
        assert_eq!(original, roundtrip);
    }

    #[test]
    fn glove_proof_lite_envelope_encoding() {
        let original = GloveProofLite {
            signed_result: SignedGloveResult {
                result: GloveResult {
                    poll_index: 123,
                    vote: GloveVote::Aye,
                    assigned_balances: vec![
                        AssignedBalance { account: [4; 32].into(), nonce: 0, balance: 100 },
                        AssignedBalance { account: [7; 32].into(), nonce: 1, balance: 200 }
                    ]
                },
                signature: Default::default()
            },
            attestation_location: AttestationBundleLocation::SubstrateRemark(ExtrinsicLocation {
                block_hash: Default::default(),
                block_index: 0,
            })
        };
        let roundtrip = GloveProofLite::decode_envelope(&original.encode_envelope()).unwrap();
        assert_eq!(original, roundtrip);
    }
}
