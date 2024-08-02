use std::collections::HashMap;

use sp_core::crypto::AccountId32;
use subxt::Error as SubxtError;

use attestation::EnclaveInfo;
use AttestationBundleLocation::SubstrateRemark;
use client_interface::{account, ExtrinsicDetails, SubstrateNetwork};
use client_interface::metadata::runtime_types;
use client_interface::metadata::runtime_types::frame_system::pallet::Call as SystemCall;
use client_interface::metadata::runtime_types::pallet_conviction_voting::pallet::Call as ConvictionVotingCall;
use client_interface::metadata::runtime_types::pallet_conviction_voting::vote::AccountVote;
use client_interface::metadata::runtime_types::pallet_proxy::pallet::Call as ProxyCall;
use client_interface::metadata::runtime_types::polkadot_runtime::RuntimeCall;
use client_interface::metadata::runtime_types::polkadot_runtime::RuntimeCall::ConvictionVoting;
use client_interface::metadata::system::calls::types::Remark;
use client_interface::metadata::utility::calls::types::Batch;
use common::{AssignedBalance, attestation, BASE_AYE, Conviction, ExtrinsicLocation, GloveResult, VoteDirection};
use common::attestation::{AttestationBundle, AttestationBundleLocation, AttestedData, GloveProof, GloveProofLite};
use runtime_types::pallet_conviction_voting::vote::Vote;

#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedGloveProof {
    pub result: GloveResult,
    /// If `None` then enclave was running in insecure mode.
    pub enclave_info: Option<EnclaveInfo>,
    pub attested_data: AttestedData
}

impl VerifiedGloveProof {
    pub fn get_assigned_balance(&self, account: &AccountId32) -> Option<AssignedBalance> {
        self.result
            .assigned_balances
            .iter()
            .find(|assigned_balance| assigned_balance.account == *account)
            .cloned()
    }

    pub fn get_vote_balance(&self, account: &AccountId32, nonce: u32) -> Option<u128> {
        self.result
            .assigned_balances
            .iter()
            .find_map(|ab| (ab.account == *account && ab.nonce == nonce).then_some(ab.balance))
    }
}

/// A result of `Ok(None)` means the extrinsic was not a Glove result.
pub async fn try_verify_glove_result(
    network: &SubstrateNetwork,
    extrinsic: &ExtrinsicDetails,
    proxy_account: &AccountId32,
    poll_index: u32
) -> Result<Option<VerifiedGloveProof>, Error> {
    let Some((glove_proof_lite, batch)) = parse_glove_proof_lite(extrinsic, proxy_account)? else {
        // This extrinsic is not a Glove proof
        return Ok(None);
    };
    let glove_result = &glove_proof_lite.signed_result.result;

    if glove_result.poll_index != poll_index {
        // This proof is for another poll and so let's return early and avoid unnecessary
        // processing, and also avoid any potential errors which wouldn't be relevant to the caller.
        return Ok(None);
    }

    let account_votes: HashMap<AccountId32, &AccountVote<u128>> = batch.calls
        .iter()
        .filter_map(|call| parse_and_validate_proxy_account_vote(call, glove_result.poll_index))
        .collect::<HashMap<_, _>>();
    // TODO Check for duplicate on-chain votes for the same account

    // Make sure each assigned balance from the Glove proof is accounted for on-chain.
    for assigned_balance in &glove_result.assigned_balances {
        account_votes.get(&assigned_balance.account)
            .filter(|&&account_vote| {
                is_account_vote_consistent(account_vote, glove_result.direction, assigned_balance)
            })
            .ok_or(Error::InconsistentVotes)?;
    }

    // It's technically possible for there to be more on-chain votes from the same proxy, for the
    // same poll, which are not in the proof. This is not something the client has to worry about,
    // since they can only confirm their vote request was included in the proof.

    let attestation_bundle = match glove_proof_lite.attestation_location {
        SubstrateRemark(remark_location) =>
            get_attestation_bundle_from_remark(network, remark_location).await?
    };

    if attestation_bundle.attested_data.genesis_hash != network.api.genesis_hash() {
        return Err(Error::ChainMismatch);
    }

    let glove_proof = GloveProof {
        signed_result: glove_proof_lite.signed_result,
        attestation_bundle
    };

    let enclave_info = match glove_proof.verify() {
        Ok(enclave_info) => Some(enclave_info),
        Err(attestation::Error::InsecureMode) => None,
        Err(error) => return Err(error.into())
    };

    Ok(Some(VerifiedGloveProof {
        result: glove_proof.signed_result.result,
        enclave_info,
        attested_data: glove_proof.attestation_bundle.attested_data
    }))
}

fn parse_glove_proof_lite(
    extrinsic: &ExtrinsicDetails,
    proxy_account: &AccountId32
) -> Result<Option<(GloveProofLite, Batch)>, SubxtError> {
    let from_proxy = account(extrinsic).filter(|account| account == proxy_account).is_some();
    if !from_proxy {
        return Ok(None);
    }

    let Some(batch) = extrinsic.as_extrinsic::<Batch>()? else {
        return Ok(None);
    };

    let remarks = batch.calls
        .iter()
        .filter_map(|call| match call {
            RuntimeCall::System(SystemCall::remark { remark }) => Some(remark),
            _ => None
        })
        .collect::<Vec<_>>();

    // Expecting there to be exactly one remark call
    let &[remark] = remarks.as_slice() else {
        return Ok(None);
    };

    Ok(GloveProofLite::decode_envelope(remark).map(|proof| (proof, batch)).ok())
}

fn parse_and_validate_proxy_account_vote(
    call: &RuntimeCall,
    expected_poll_index: u32,
) -> Option<(AccountId32, &AccountVote<u128>)> {
    let RuntimeCall::Proxy(proxy_call) = call else {
        return None;
    };
    let ProxyCall::proxy { real, force_proxy_type: _, call: proxied_call } = proxy_call else {
        return None;
    };
    let subxt_core::utils::MultiAddress::Id(real_account) = real else {
        return None;
    };
    let ConvictionVoting(ConvictionVotingCall::vote { poll_index, ref vote }) = **proxied_call else {
        return None;
    };
    if expected_poll_index != poll_index {
        return None;
    }
    Some((real_account.0.into(), vote))
}

fn is_account_vote_consistent(
    account_vote: &AccountVote<u128>,
    direction: VoteDirection,
    assigned_balance: &AssignedBalance
) -> bool {
    match direction {
        VoteDirection::Aye => {
            parse_standard_account_vote(account_vote) ==
                Some((true, assigned_balance.balance, assigned_balance.conviction))
        },
        VoteDirection::Nay => {
            parse_standard_account_vote(account_vote) ==
                Some((false, assigned_balance.balance, assigned_balance.conviction))
        },
        VoteDirection::Abstain => {
            parse_abstain_account_vote(account_vote) == Some(assigned_balance.balance)
        }
    }
}

fn parse_standard_account_vote(vote: &AccountVote<u128>) -> Option<(bool, u128, Conviction)> {
    let AccountVote::Standard { vote: Vote(direction), balance } = vote else {
        return None;
    };
    if *direction >= BASE_AYE {
        Some((true, *balance, parse_conviction(*direction - BASE_AYE)?))
    } else {
        Some((false, *balance, parse_conviction(*direction)?))
    }
}

fn parse_conviction(offset: u8) -> Option<Conviction> {
    match offset {
        0 => Some(Conviction::None),
        1 => Some(Conviction::Locked1x),
        2 => Some(Conviction::Locked2x),
        3 => Some(Conviction::Locked3x),
        4 => Some(Conviction::Locked4x),
        5 => Some(Conviction::Locked5x),
        6 => Some(Conviction::Locked6x),
        _ => None
    }
}

fn parse_abstain_account_vote(account_vote: &AccountVote<u128>) -> Option<u128> {
    match account_vote {
        AccountVote::SplitAbstain { aye: 0, nay: 0, abstain } => Some(*abstain),
        _ => None
    }
}

async fn get_attestation_bundle_from_remark(
    network: &SubstrateNetwork,
    remark_location: ExtrinsicLocation
) -> Result<AttestationBundle, Error> {
    network.get_extrinsic(remark_location).await?
        .ok_or_else(|| Error::ExtrinsicNotFound(remark_location))?
        .as_extrinsic::<Remark>()?
        .ok_or_else(|| Error::InvalidAttestationBundle(
            format!("Extrinsic at location {:?} is not a Remark", remark_location)
        ))
        .and_then(|remark| {
            AttestationBundle::decode_envelope(&remark.remark).map_err(|scale_error| {
                Error::InvalidAttestationBundle(
                    format!("Error decoding attestation bundle: {}", scale_error)
                )
            })
        })
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Subxt error: {0}")]
    Subxt(#[from] SubxtError),
    #[error("Votes are inconsistent with the Glove proof")]
    InconsistentVotes,
    #[error("Glove proof is for different chain")]
    ChainMismatch,
    #[error("Extrinsic at location {0} does not exist")]
    ExtrinsicNotFound(ExtrinsicLocation),
    #[error("Invalid attestation bundle: {0}")]
    InvalidAttestationBundle(String),
    #[error("Invalid attestation: {0}")]
    Attestation(#[from] attestation::Error)
}
