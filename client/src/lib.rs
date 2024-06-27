use std::collections::HashMap;

use sp_core::crypto::AccountId32;
use sp_core::Decode;
use sp_runtime::MultiAddress;
use subxt::{Error as SubxtError, OnlineClient, PolkadotConfig};
use subxt::blocks::ExtrinsicDetails;
use subxt::error::BlockError;
use subxt::ext::subxt_core::ext::sp_core::hexdisplay::AsBytesRef;

use attestation::EnclaveInfo;
use AttestationBundleLocation::SubstrateRemark;
use client_interface::metadata::runtime_types;
use client_interface::metadata::runtime_types::frame_system::pallet::Call as SystemCall;
use client_interface::metadata::runtime_types::pallet_conviction_voting::pallet::Call as ConvictionVotingCall;
use client_interface::metadata::runtime_types::pallet_conviction_voting::vote::AccountVote;
use client_interface::metadata::runtime_types::pallet_proxy::pallet::Call as ProxyCall;
use client_interface::metadata::runtime_types::polkadot_runtime::RuntimeCall;
use client_interface::metadata::runtime_types::polkadot_runtime::RuntimeCall::ConvictionVoting;
use client_interface::metadata::system::calls::types::Remark;
use client_interface::metadata::utility::calls::types::Batch;
use common::{attestation, AYE, ExtrinsicLocation, GloveResult, GloveVote, NAY};
use common::attestation::{AttestationBundle, AttestationBundleLocation, GloveProof, GloveProofLite};
use runtime_types::pallet_conviction_voting::vote::Vote;

#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedGloveProof {
    pub result: GloveResult,
    pub enclave_info: Option<EnclaveInfo>,
}

// TODO API for checking EnclaveInfo for expected measurements
impl VerifiedGloveProof {
    pub fn get_vote_balance(&self, account: &AccountId32, nonce: u32) -> Option<u128> {
        self.result
            .assigned_balances
            .iter()
            .find_map(|avb| (avb.account == *account && avb.nonce == nonce).then_some(avb.balance))
    }
}

/// A result of `Ok(None)` means the extrinsic was not a Glove result.
pub async fn try_verify_glove_result(
    client: &OnlineClient<PolkadotConfig>,
    extrinsic: &ExtrinsicDetails<PolkadotConfig, OnlineClient<PolkadotConfig>>,
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

    let on_chain_vote_balances: HashMap<AccountId32, u128> = batch.calls
        .iter()
        .filter_map(|call| {
            parse_and_validate_proxy_vote(call, glove_result.poll_index, &glove_result.vote)
        })
        .collect::<HashMap<_, _>>();
    // TODO Check for duplicate on-chain votes for the same account

    // Make sure each assigned balance from the Glove proof is accounted for on-chain.
    for assigned_balance in &glove_result.assigned_balances {
        on_chain_vote_balances.get(&assigned_balance.account)
            .filter(|&balance| *balance == assigned_balance.balance)
            .ok_or(Error::Inconsistent)?;
    }

    // It's technically possible for there to be more on-chain votes from the same proxy, for the
    // same poll, which are not in the proof. This is not something the client has to worry about,
    // since they can only confirm their vote request was included in the proof.

    let attestation_bundle = match glove_proof_lite.attestation_location {
        SubstrateRemark(remark_location) =>
            get_attestation_bundle_from_remark(client, remark_location).await?
    };

    // TODO Check genesis hash

    let glove_verification_result = GloveProof::verify_components(
        &glove_proof_lite.signed_result,
        &attestation_bundle
    );

    let enclave_info = match glove_verification_result {
        Ok(enclave_info) => Some(enclave_info),
        Err(attestation::Error::InsecureMode) => None,
        Err(error) => return Err(error.into())
    };

    Ok(Some(VerifiedGloveProof {
        result: glove_proof_lite.signed_result.result,
        enclave_info
    }))
}

fn parse_glove_proof_lite(
    extrinsic: &ExtrinsicDetails<PolkadotConfig, OnlineClient<PolkadotConfig>>,
    proxy_account: &AccountId32
) -> Result<Option<(GloveProofLite, Batch)>, SubxtError> {
    let from_proxy = extrinsic
        .address_bytes()
        .and_then(parse_multi_address)
        .filter(|account| account == proxy_account)
        .is_some();
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

fn parse_multi_address(bytes: &[u8]) -> Option<AccountId32> {
    type MultiAddress32 = MultiAddress<AccountId32, u32>;

    MultiAddress32::decode(&mut bytes.as_bytes_ref())
        .ok()
        .and_then(|address| match address {
            MultiAddress::Id(account) => Some(account),
            _ => None
        })
}

fn parse_and_validate_proxy_vote(
    call: &RuntimeCall,
    expected_poll_index: u32,
    glove_vote: &GloveVote
) -> Option<(AccountId32, u128)> {
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
    let Some(balance) = check_on_chain_vote_is_consistent(&vote, glove_vote) else {
        return None;
    };
    Some((real_account.0.into(), balance))
}

fn check_on_chain_vote_is_consistent(
    on_chain_vote: &AccountVote<u128>,
    glove_vote: &GloveVote
) -> Option<u128> {
    // TODO Conviction multipliers
    match glove_vote {
        GloveVote::Aye => match on_chain_vote {
            AccountVote::Standard { vote: Vote(direction), balance } =>
                (*direction == AYE).then_some(*balance),
            _ => None
        },
        GloveVote::Nay => match on_chain_vote {
            AccountVote::Standard { vote: Vote(direction), balance } =>
                (*direction == NAY).then_some(*balance),
            _ => None
        },
        GloveVote::Abstain => match on_chain_vote {
            AccountVote::SplitAbstain { aye: 0, nay: 0, abstain } => Some(*abstain),
            _ => None
        }
    }
}

async fn get_attestation_bundle_from_remark(
    client: &OnlineClient<PolkadotConfig>,
    extrinsic_location: ExtrinsicLocation
) -> Result<AttestationBundle, Error> {
    let block_result = client.blocks().at(extrinsic_location.block_hash).await;
    if let Err(SubxtError::Block(BlockError::NotFound(_))) = block_result {
        return Err(Error::ExtrinsicNotFound(extrinsic_location));
    }
    block_result?
        .extrinsics().await?
        .iter()
        .nth(extrinsic_location.block_index as usize)
        .transpose()?
        .ok_or_else(|| Error::ExtrinsicNotFound(extrinsic_location))?
        .as_extrinsic::<Remark>()?
        .ok_or_else(|| Error::InvalidAttestationBundle(
            format!("Extrinsic at location {:?} is not a Remark", extrinsic_location)
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
    Inconsistent,
    #[error("Extrinsic at location {0} does not exist")]
    ExtrinsicNotFound(ExtrinsicLocation),
    #[error("Invalid attestation bundle: {0}")]
    InvalidAttestationBundle(String),
    #[error("Invalid attestation: {0}")]
    Attestation(#[from] attestation::Error)
}

// TODO Tests
