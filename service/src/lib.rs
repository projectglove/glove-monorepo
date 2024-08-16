use std::collections::{HashMap, HashSet};
use std::collections::hash_map::Entry;
use std::error::Error;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use sp_runtime::AccountId32;
use tokio::sync::{Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};
use tracing::warn;

use client_interface::{account_to_subxt_multi_address, CallableSubstrateNetwork, ReferendumStatus, subscan, SubstrateNetwork};
use client_interface::metadata::runtime_types::pallet_conviction_voting::pallet::Call as ConvictionVotingCall;
use client_interface::metadata::runtime_types::pallet_conviction_voting::vote::{AccountVote, Vote};
use client_interface::metadata::runtime_types::pallet_proxy::pallet::Call as ProxyCall;
use client_interface::metadata::runtime_types::polkadot_runtime::RuntimeCall;
use client_interface::subscan::Subscan;
use common::{AssignedBalance, BASE_AYE, BASE_NAY, Conviction, ExtrinsicLocation, GloveResult, SignedVoteRequest, VoteDirection};
use common::attestation::{AttestationBundle, AttestationBundleLocation};

use crate::enclave::EnclaveHandle;
use crate::storage::GloveStorage;

pub mod enclave;
pub mod mixing;
pub mod dynamodb;
pub mod storage;

pub const BLOCK_TIME_SECS: u32 = 6;
/// The period near the end of decision or confirmation that Glove must mix and submit votes.
const GLOVE_MIX_PERIOD: u32 = (15 * 60) / BLOCK_TIME_SECS;

pub async fn calculate_mixing_time(
    poll_status: ReferendumStatus,
    network: &SubstrateNetwork
) -> Result<MixingTime, subxt::Error> {
    let Some(deciding_status) = poll_status.deciding else {
        return Ok(MixingTime::NotDeciding);
    };
    let decision_period = network.get_tracks()?
        .get(&poll_status.track)
        .map(|track_info| track_info.decision_period)
        .ok_or_else(|| subxt::Error::Other("Track not found".into()))?;
    let decision_end = deciding_status.since + decision_period;
    if let Some(confirming_end) = deciding_status.confirming {
        if confirming_end < decision_end {
            return Ok(MixingTime::Confirming(confirming_end - GLOVE_MIX_PERIOD));
        }
    }
    Ok(MixingTime::Deciding(decision_end - GLOVE_MIX_PERIOD))
}

pub enum MixingTime {
    Deciding(u32),
    Confirming(u32),
    NotDeciding
}

impl MixingTime {
    pub fn block_number(&self) -> Option<u32> {
        match self {
            MixingTime::Deciding(block_number) => Some(*block_number),
            MixingTime::Confirming(block_number) => Some(*block_number),
            MixingTime::NotDeciding => None
        }
    }
}

/// Voter lookup for a poll.
#[derive(Clone)]
pub struct VoterLookup {
    poll_index: u32,
    // get_voters is called frequently, so we want to avoid looking up the same extrinsic every
    // time.
    cache: Arc<Mutex<HashMap<ExtrinsicLocation, Option<AccountId32>>>>
}

impl VoterLookup {
    pub fn new(poll_index: u32) -> Self {
        Self {
            poll_index,
            cache: Arc::default()
        }
    }

    /// Get the all voters. Returns a vector of (`AccountId32`, `AccountId32`) tuples. The first
    /// element is the voter, and the second is sender of the vote extrinsic. They will be different
    /// if the vote was proxied.
    pub async fn get_voters(
        &self,
        subscan: &Subscan
    ) -> Result<Vec<(AccountId32, Option<AccountId32>)>, subscan::Error> {
        let mut result = Vec::new();
        let votes = subscan.get_votes(self.poll_index, None).await?;
        let mut cache = self.cache.lock().await;
        for vote in votes {
            let sender = match cache.entry(vote.extrinsic_index) {
                Entry::Occupied(entry) => entry.get().clone(),
                Entry::Vacant(entry) => {
                    if let Some(extrinsic) = subscan.get_extrinsic(vote.extrinsic_index).await? {
                        entry.insert(extrinsic.account_address()).clone()
                    } else {
                        warn!("Extrinsic not found: {:?}", vote.extrinsic_index);
                        entry.insert(None).clone()
                    }
                }
            };
            result.push((vote.account.address, sender));
        }
        Ok(result)
    }
}

// TODO Deal with mixed_balance of zero
pub fn to_proxied_vote_call(
    result: &GloveResult,
    assigned_balance: &AssignedBalance
) -> RuntimeCall {
    RuntimeCall::Proxy(
        ProxyCall::proxy {
            real: account_to_subxt_multi_address(assigned_balance.account.clone()),
            force_proxy_type: None,
            call: Box::new(RuntimeCall::ConvictionVoting(ConvictionVotingCall::vote {
                poll_index: result.poll_index,
                vote: to_account_vote(result.direction, assigned_balance)
            })),
        }
    )
}

fn to_account_vote(
    direction: VoteDirection,
    assigned_balance: &AssignedBalance
) -> AccountVote<u128> {
    let offset = match assigned_balance.conviction {
        Conviction::None => 0,
        Conviction::Locked1x => 1,
        Conviction::Locked2x => 2,
        Conviction::Locked3x => 3,
        Conviction::Locked4x => 4,
        Conviction::Locked5x => 5,
        Conviction::Locked6x => 6
    };
    let balance = assigned_balance.balance;
    match direction {
        VoteDirection::Aye => AccountVote::Standard { vote: Vote(BASE_AYE + offset), balance },
        VoteDirection::Nay => AccountVote::Standard { vote: Vote(BASE_NAY + offset), balance },
        VoteDirection::Abstain => AccountVote::SplitAbstain { aye: 0, nay: 0, abstain: balance }
    }
}

pub struct GloveContext {
    pub storage: GloveStorage,
    pub enclave_handle: EnclaveHandle,
    pub attestation_bundle: AttestationBundle,
    pub network: CallableSubstrateNetwork,
    pub exclude_tracks: HashSet<u16>,
    pub regular_mix_enabled: bool,
    pub state: GloveState,
}

impl GloveContext {
    pub async fn add_vote_request(
        &self,
        signed_request: SignedVoteRequest
    ) -> Result<bool, storage::Error> {
        let poll_index = signed_request.request.poll_index;
        let poll_state_ref = self.state.get_poll_state_ref(poll_index).await;
        let poll_state = poll_state_ref.read_access().await;
        if poll_state.mix_finalized {
            return Ok(false);
        }
        self.storage.add_vote_request(signed_request).await?;
        poll_state.vote_added.store(true, Ordering::Release);
        Ok(true)
    }

    pub async fn remove_vote_request(
        &self,
        poll_index: u32,
        account: &AccountId32
    ) -> Result<bool, storage::Error> {
        let poll_state_ref = self.state.get_poll_state_ref(poll_index).await;
        let poll_state = poll_state_ref.read_access().await;
        if poll_state.mix_finalized {
            return Ok(false);
        }
        self.storage.remove_vote_request(poll_index, account).await?;
        Ok(true)
    }

    pub async fn remove_poll(&self, poll_index: u32) -> Result<(), storage::Error> {
        self.storage.remove_poll(poll_index).await?;
        self.state.remove_poll_state(poll_index).await;
        Ok(())
    }
}

#[derive(Default)]
pub struct GloveState {
    // There may be a non-trivial cost to storing the attestation bundle location, and so it's done
    // lazily on first poll mixing, rather than eagerly on startup.
    abl: Mutex<Option<AttestationBundleLocation>>,
    poll_states: Mutex<HashMap<u32, PollStateRef>>
}

impl GloveState {
    pub async fn attestation_bundle_location<E: Error, Fut>(
        &self,
        new: impl FnOnce() -> Fut
    ) -> Result<AttestationBundleLocation, E>
    where
        Fut: Future<Output = Result<AttestationBundleLocation, E>>,
    {
        let mut abl_holder = self.abl.lock().await;
        match &*abl_holder {
            None => {
                let abl = new().await?;
                *abl_holder = Some(abl.clone());
                Ok(abl)
            }
            Some(abl) => Ok(abl.clone())
        }
    }

    pub async fn is_non_glove_voter(&self, poll_index: u32, account: &AccountId32) -> bool {
        let poll_state_ref = self.get_poll_state_ref(poll_index).await;
        let poll_state = poll_state_ref.read_access().await;
        poll_state.non_glove_voters.contains(account)
    }

    pub async fn set_non_glove_voters(&self, poll_index: u32, voters: HashSet<AccountId32>) {
        let poll_state_ref = self.get_poll_state_ref(poll_index).await;
        let mut poll_state = poll_state_ref.write_access().await;
        poll_state.non_glove_voters = voters;
    }

    pub async fn is_mix_finalized(&self, poll_index: u32) -> bool {
        let poll_state_ref = self.get_poll_state_ref(poll_index).await;
        let poll_state = poll_state_ref.read_access().await;
        poll_state.mix_finalized
    }

    pub async fn was_vote_added(&self, poll_index: u32) -> bool {
        self.get_poll_state_ref(poll_index).await
            .read_access().await
            .vote_added
            .compare_exchange(true, false, Ordering::Acquire, Ordering::Relaxed)
            .unwrap_or_else(|val| val)
    }

    pub async fn get_poll_state_ref(&self, poll_index: u32) -> PollStateRef {
        let mut poll_states = self.poll_states.lock().await;
        poll_states.entry(poll_index).or_insert_with(|| {
            PollStateRef {
                inner: Arc::default(),
                voter_lookup: VoterLookup::new(poll_index)
            }
        }).clone()
    }

    async fn remove_poll_state(&self, poll_index: u32) {
        self.poll_states.lock().await.remove(&poll_index);
    }
}

#[derive(Clone)]
pub struct PollStateRef {
    // There is a read-write lock here to support concurrent addition/removal of vote requests, but
    // synchronized mixing of the votes.
    inner: Arc<RwLock<PollState>>,
    pub voter_lookup: VoterLookup
}

#[derive(Default)]
pub struct PollState {
    pub non_glove_voters: HashSet<AccountId32>,
    pub mix_finalized: bool,
    vote_added: AtomicBool
}

impl PollStateRef {
    pub async fn write_access(&self) -> RwLockWriteGuard<'_, PollState> {
        self.inner.write().await
    }

    async fn read_access(&self) -> RwLockReadGuard<'_, PollState> {
        self.inner.read().await
    }
}
