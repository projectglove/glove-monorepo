use std::collections::{HashMap, HashSet};
use std::collections::hash_map::Entry;
use std::error::Error;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use sp_runtime::AccountId32;
use tokio::sync::{Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};
use tracing::log::warn;

use client_interface::{account, account_to_subxt_multi_address, CallableSubstrateNetwork, subscan, SubstrateNetwork};
use client_interface::metadata::runtime_types::pallet_conviction_voting::pallet::Call as ConvictionVotingCall;
use client_interface::metadata::runtime_types::pallet_conviction_voting::vote::{AccountVote, Vote};
use client_interface::metadata::runtime_types::pallet_proxy::pallet::Call as ProxyCall;
use client_interface::metadata::runtime_types::polkadot_runtime::RuntimeCall;
use common::{AssignedBalance, BASE_AYE, BASE_NAY, Conviction, ExtrinsicLocation, GloveResult, SignedVoteRequest, VoteDirection};
use common::attestation::{AttestationBundle, AttestationBundleLocation};

use crate::enclave::EnclaveHandle;
use crate::storage::GloveStorage;

pub mod enclave;
pub mod mixing;
pub mod dynamodb;
pub mod storage;

/// Get the voters of a poll. Returns a vector of (`AccountId32`, `AccountId32`) tuples. The first
/// element is the voter, and the second is sender of the vote extrinsic. They will be different if
/// the vote was proxied.
pub async fn get_voters(
    http_client: &reqwest::Client,
    network: &SubstrateNetwork,
    poll_index: u32
) -> anyhow::Result<Vec<(AccountId32, AccountId32)>> {
    let mut result = Vec::new();
    // Avoid looking up the same extrinsic multiple times when we encounter the Glove vote batch
    let mut extrinic_index_to_voter: HashMap<ExtrinsicLocation, AccountId32> = HashMap::new();
    let votes = subscan::get_votes(http_client, &network.network_name, poll_index, None).await?;
    for vote in votes {
        let sender = match extrinic_index_to_voter.entry(vote.extrinsic_index) {
            Entry::Occupied(entry) => entry.get().clone(),
            Entry::Vacant(entry) => {
                let Some(extrinsic) = network.get_extrinsic(vote.extrinsic_index).await? else {
                    warn!("Extrinsic referenced by subscan not found: {:?}", vote);
                    continue;
                };
                match account(&extrinsic) {
                    Some(sender) => entry.insert(sender).clone(),
                    None => continue
                }
            }
        };
        result.push((vote.account.address, sender));
    }
    Ok(result)
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
    pub node_endpoint: String,
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
        poll_states.entry(poll_index).or_default().clone()
    }

    async fn remove_poll_state(&self, poll_index: u32) {
        self.poll_states.lock().await.remove(&poll_index);
    }
}

#[derive(Default, Clone)]
pub struct PollStateRef {
    // There is a read-write lock here to support concurrent addition/removal of vote requests, but
    // synchronized mixing of the votes.
    inner: Arc<RwLock<PollState>>
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
