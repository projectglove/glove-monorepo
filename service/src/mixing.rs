use std::io;

use tracing::debug;
use tracing::warn;

use common::attestation::Error::InsecureMode;
use common::attestation::{AttestationBundle, GloveProof};
use common::{attestation, SignedGloveResult, SignedVoteRequest};
use enclave_interface::{EnclaveRequest, EnclaveResponse};

use crate::enclave::EnclaveHandle;
use crate::storage;

pub async fn mix_votes_in_enclave(
    enclave_handle: &EnclaveHandle,
    attestation_bundle: &AttestationBundle,
    vote_requests: Vec<SignedVoteRequest>,
) -> Result<SignedGloveResult, Error> {
    let request = EnclaveRequest::MixVotes(vote_requests);
    let response = enclave_handle
        .send_receive::<EnclaveResponse>(&request)
        .await?;
    match response {
        EnclaveResponse::GloveResult(signed_result) => {
            let result = &signed_result.result;
            debug!(
                "Glove result from enclave, poll: {}, direction: {:?}, signature: {:?}",
                result.poll_index, result.direction, signed_result.signature
            );
            for assigned_balance in &result.assigned_balances {
                debug!("  {:?}", assigned_balance);
            }
            // Double-check things all line up before committing on-chain
            let proof = GloveProof {
                signed_result: signed_result.clone(),
                attestation_bundle: attestation_bundle.clone(),
            };
            match proof.verify() {
                Ok(_) => debug!("Glove proof verified"),
                Err(InsecureMode) => warn!("Glove proof from insecure enclave"),
                Err(error) => return Err(error.into()),
            }
            Ok(signed_result)
        }
        EnclaveResponse::Error(enclave_error) => {
            warn!("Mixing error from enclave: {:?}", enclave_error);
            Err(enclave_error.into())
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Enclave error: {0}")]
    Enclave(#[from] enclave_interface::Error),
    #[error("Enclave attestation error: {0}")]
    Attestation(#[from] attestation::Error),
    #[error("Storage error: {0}")]
    Storage(#[from] storage::Error),
}
