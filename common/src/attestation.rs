use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use sp_core::{ed25519, Pair};

use crate::{GloveResult, nitro};

#[derive(Debug, Clone, Encode, Decode)]
pub struct GloveProof {
    pub result: GloveResult,
    pub attestation_bundle: AttestationBundle
}

impl GloveProof {
    ///
    pub fn verify(&self) -> Result<EnclaveInfo, Error> {
        // If the attestation bundle is valid, then it means the signing key contained within it is
        // from a genuine secure enclave.
        let enclave_info = self.attestation_bundle.verify()?;
        // If the signature in the Gkove proof is valid, then it means the result was produced by
        // the enclave.
        let valid = <ed25519::Pair as Pair>::verify(
            &self.result.signature,
            self.result.mixed_votes.encode(),
            &self.attestation_bundle.attested_data.signing_key
        );
        valid.then_some(enclave_info).ok_or(Error::GloveProof)
    }
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct AttestationBundle {
    pub version: u8,
    pub attested_data: AttestedData,
    pub attestation: Attestation
}

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
}

#[derive(Debug, Clone, Encode, Decode, MaxEncodedLen)]
pub struct AttestedData {
    pub signing_key: ed25519::Public
}

#[derive(Debug, Clone, Encode, Decode)]
pub enum Attestation {
    Nitro(nitro::Attestation),
    Mock
}

#[derive(Debug, Clone, Encode, Decode)]
pub enum EnclaveInfo {
    Nitro(nitro::EnclaveInfo)
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
