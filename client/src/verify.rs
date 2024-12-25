use std::collections::HashMap;

use sp_core::crypto::AccountId32;

use crate::genesis_hash;
use attestation::EnclaveInfo;
use client_interface::subscan;
use client_interface::subscan::{
    ExtrinsicDetail, HexString, MultiAddress, RuntimeCall, SplitAbstainAccountVote, Subscan,
};
use common::attestation::{
    AttestationBundle, AttestationBundleLocation, AttestedData, GloveProof, GloveProofLite,
};
use common::{
    attestation, AssignedBalance, Conviction, ExtrinsicLocation, GloveResult, VoteDirection,
    BASE_AYE,
};
use subscan::AccountVote;
use AttestationBundleLocation::SubstrateRemark;

#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedGloveProof {
    pub result: GloveResult,
    /// If `None` then enclave was running in insecure mode.
    pub enclave_info: Option<EnclaveInfo>,
    pub attested_data: AttestedData,
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
    subscan: &Subscan,
    vote_extrinsic_location: ExtrinsicLocation,
    proxy_account: AccountId32,
    poll_index: u32,
) -> Result<Option<VerifiedGloveProof>, Error> {
    let Some(extrinsic) = subscan.get_extrinsic(vote_extrinsic_location).await? else {
        return Err(Error::ExtrinsicNotFound(vote_extrinsic_location));
    };
    let Some((glove_proof_lite, batch)) = parse_glove_proof_lite(extrinsic, proxy_account) else {
        // This extrinsic is not a Glove proof
        return Ok(None);
    };
    let glove_result = &glove_proof_lite.signed_result.result;

    if glove_result.poll_index != poll_index {
        // This proof is for another poll and so let's return early and avoid unnecessary
        // processing, and also avoid any potential errors which wouldn't be relevant to the caller.
        return Ok(None);
    }

    let account_votes: HashMap<AccountId32, AccountVote> = batch
        .into_iter()
        .filter_map(|call| parse_and_validate_proxy_account_vote(call, glove_result.poll_index))
        .collect::<HashMap<_, _>>();
    // TODO Check for duplicate on-chain votes for the same account

    // Make sure each assigned balance from the Glove proof is accounted for on-chain.
    for assigned_balance in &glove_result.assigned_balances {
        account_votes
            .get(&assigned_balance.account)
            .filter(|&account_vote| {
                is_account_vote_consistent(account_vote, glove_result.direction, assigned_balance)
            })
            .ok_or(Error::InconsistentVotes)?;
    }

    // It's technically possible for there to be more on-chain votes from the same proxy, for the
    // same poll, which are not in the proof. This is not something the client has to worry about,
    // since they can only confirm their vote request was included in the proof.

    let attestation_bundle = match glove_proof_lite.attestation_location {
        SubstrateRemark(remark_location) => {
            get_attestation_bundle_from_remark(subscan, remark_location).await?
        }
    };

    if Some(attestation_bundle.attested_data.genesis_hash) != genesis_hash(subscan).await.ok() {
        return Err(Error::ChainMismatch);
    }

    let glove_proof = GloveProof {
        signed_result: glove_proof_lite.signed_result,
        attestation_bundle,
    };

    let enclave_info = match glove_proof.verify() {
        Ok(enclave_info) => Some(enclave_info),
        Err(attestation::Error::InsecureMode) => None,
        Err(error) => return Err(error.into()),
    };

    Ok(Some(VerifiedGloveProof {
        result: glove_proof.signed_result.result,
        enclave_info,
        attested_data: glove_proof.attestation_bundle.attested_data,
    }))
}

fn parse_glove_proof_lite(
    extrinsic: ExtrinsicDetail,
    proxy_account: AccountId32,
) -> Option<(GloveProofLite, Vec<RuntimeCall>)> {
    if extrinsic.account_address() != Some(proxy_account) {
        return None;
    }

    let calls = extrinsic.get_param_as::<Vec<RuntimeCall>>("calls")?;

    let remarks = calls
        .iter()
        .filter(|call| call.is_extrinsic("system", "remark"))
        .filter_map(|call| call.get_param_as::<HexString>("remark"))
        .collect::<Vec<_>>();

    // Expecting there to be exactly one remark call
    let [remark] = remarks.as_slice() else {
        return None;
    };

    GloveProofLite::decode_envelope(remark)
        .map(|proof| (proof, calls))
        .ok()
}

fn parse_and_validate_proxy_account_vote(
    batched_call: RuntimeCall,
    expected_poll_index: u32,
) -> Option<(AccountId32, AccountVote)> {
    if !batched_call.is_extrinsic("proxy", "proxy") {
        return None;
    }
    let Some(MultiAddress::Id(real)) = batched_call.get_param_as::<MultiAddress>("real") else {
        return None;
    };
    let proxied_call = batched_call.get_param_as::<RuntimeCall>("call")?;
    if !proxied_call.is_extrinsic("convictionvoting", "vote") {
        return None;
    }
    let poll_index = proxied_call.get_param_as::<u32>("poll_index")?;
    let vote = proxied_call.get_param_as::<AccountVote>("vote")?;
    if expected_poll_index != poll_index {
        return None;
    }
    Some((real.value, vote))
}

fn is_account_vote_consistent(
    account_vote: &AccountVote,
    direction: VoteDirection,
    assigned_balance: &AssignedBalance,
) -> bool {
    match direction {
        VoteDirection::Aye => {
            parse_standard_account_vote(account_vote)
                == Some((true, assigned_balance.balance, assigned_balance.conviction))
        }
        VoteDirection::Nay => {
            parse_standard_account_vote(account_vote)
                == Some((false, assigned_balance.balance, assigned_balance.conviction))
        }
        VoteDirection::Abstain => {
            parse_abstain_account_vote(account_vote) == Some(assigned_balance.balance)
        }
    }
}

fn parse_standard_account_vote(vote: &AccountVote) -> Option<(bool, u128, Conviction)> {
    let AccountVote::Standard(standard) = vote else {
        return None;
    };
    if standard.vote >= BASE_AYE {
        Some((
            true,
            standard.balance,
            parse_conviction(standard.vote - BASE_AYE)?,
        ))
    } else {
        Some((false, standard.balance, parse_conviction(standard.vote)?))
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
        _ => None,
    }
}

fn parse_abstain_account_vote(account_vote: &AccountVote) -> Option<u128> {
    match account_vote {
        AccountVote::SplitAbstain(SplitAbstainAccountVote {
            aye: 0,
            nay: 0,
            abstain,
        }) => Some(*abstain),
        _ => None,
    }
}

async fn get_attestation_bundle_from_remark(
    subscan: &Subscan,
    remark_location: ExtrinsicLocation,
) -> Result<AttestationBundle, Error> {
    let extrinsic_detail = subscan
        .get_extrinsic(remark_location)
        .await?
        .ok_or_else(|| Error::ExtrinsicNotFound(remark_location))?;
    if !extrinsic_detail.is_extrinsic("system", "remark") {
        return Err(Error::InvalidAttestationBundle(format!(
            "Extrinsic at location {:?} is not a Remark",
            remark_location
        )));
    }
    extrinsic_detail
        .get_param_as::<HexString>("remark")
        .and_then(|hex| AttestationBundle::decode_envelope(hex.as_slice()).ok())
        .ok_or_else(|| {
            Error::InvalidAttestationBundle(format!(
                "Extrinsic at location {:?} does not contain a valid AttestationBundle",
                remark_location
            ))
        })
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Subscan error: {0}")]
    Subscan(#[from] subscan::Error),
    #[error("Votes are inconsistent with the Glove proof")]
    InconsistentVotes,
    #[error("Glove proof is for different chain")]
    ChainMismatch,
    #[error("Extrinsic at location {0} does not exist")]
    ExtrinsicNotFound(ExtrinsicLocation),
    #[error("Invalid attestation bundle: {0}")]
    InvalidAttestationBundle(String),
    #[error("Invalid attestation: {0}")]
    Attestation(#[from] attestation::Error),
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use sp_core::bytes::from_hex;

    use super::*;

    // test suite being rewritten with rococo deprecation
    /*
    #[tokio::test]
    async fn verification_of_sample_glove_result() {
        let subscan = Subscan::new("rococo".into(), None);
        let verification_result = try_verify_glove_result(
            &subscan,
            ExtrinsicLocation {
                block_number: 11729890,
                extrinsic_index: 2,
            },
            AccountId32::from_str("5E79AhCNFdcJJ1nWXepeib7BWRbacVbpKvRhcoyv8dRwrmQ3").unwrap(),
            241,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(verification_result.result.assigned_balances.len(), 3);
        let enclave_measuremnt = verification_result
            .enclave_info
            .as_ref()
            .map(|EnclaveInfo::Nitro(info)| info.image_measurement.clone());
        assert_eq!(enclave_measuremnt, Some(from_hex("4d132e40ed8d6db60d01d0116c34a4a92914de73d668821b6e019b72ae152b1180ef7c8a378e6c1925fe2bcb31c0ec80").unwrap()));
        let expected_balances = vec![
            (
                "5CyppCnQKiuY9c22yjHbDTpCqeHzAt7GXQpFAURxycWTS8My",
                33351321,
                1586359369580,
            ),
            (
                "5F3wWFE7TGhpqXhZy18soAa2VjVsfr21VC4PZP3ZuAfM8Dg5",
                4072408713,
                5727210208563,
            ),
            (
                "5GdjoMMME46cTumexM7AJTzkEpPp1xxbXNguEDecNtf7kz2R",
                177757542,
                4525520421857,
            ),
        ];
        for (account, nonce, expected_balance) in expected_balances {
            let account = AccountId32::from_str(account).unwrap();
            assert_eq!(
                verification_result
                    .get_vote_balance(&account, nonce)
                    .unwrap(),
                expected_balance
            );
        }
    }
        */
}
