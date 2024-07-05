use std::collections::HashMap;
use std::error::Error;
use std::future::Future;
use std::sync::Arc;

use itertools::Itertools;
use sp_runtime::AccountId32;
use tokio::sync::Mutex;

use common::attestation::AttestationBundleLocation;
use common::SignedVoteRequest;

pub mod enclave;

#[derive(Default)]
pub struct GloveState {
    // There may be a non-trivial cost to storing the attestation bundle location, and so it's done
    // lazily on first poll mixing, rather than eagerly on startup.
    abl: Mutex<Option<AttestationBundleLocation>>,
    polls: Mutex<HashMap<u32, Poll>>
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

    pub async fn get_poll(&self, poll_index: u32) -> Poll {
        let mut polls = self.polls.lock().await;
        polls
            .entry(poll_index)
            .or_insert_with(|| Poll {
                index: poll_index,
                inner: Arc::default()
            })
            .clone()
    }

    pub async fn get_optional_poll(&self, poll_index: u32) -> Option<Poll> {
        let polls = self.polls.lock().await;
        polls.get(&poll_index).map(Poll::clone)
    }

    pub async fn remove_poll(&self, poll_index: u32) {
        let mut polls = self.polls.lock().await;
        polls.remove(&poll_index);
    }
}

#[derive(Debug, Clone)]
pub struct Poll {
    pub index: u32,
    inner: Arc<Mutex<InnerPoll>>
}

impl Poll {
    /// Returns `true` if vote mixing should be initiated as a background task.
    pub async fn add_vote_request(&self, signed_request: SignedVoteRequest) -> bool {
        if signed_request.request.poll_index != self.index {
            panic!("Request doesn't belong here: {} vs {:?}", self.index, signed_request);
        }
        let mut poll = self.inner.lock().await;
        poll.requests.insert(signed_request.request.account.clone(), signed_request);
        let initiate_mix = !poll.pending_mix;
        poll.pending_mix = true;
        initiate_mix
    }

    pub async fn remove_vote_request(&self, account: AccountId32) -> Option<bool> {
        let mut poll = self.inner.lock().await;
        let _ = poll.requests.remove(&account)?;
        let initiate_mix = !poll.pending_mix;
        poll.pending_mix = true;
        Some(initiate_mix)
    }

    pub async fn begin_mix(&self) -> Option<Vec<SignedVoteRequest>> {
        let mut poll = self.inner.lock().await;
        if !poll.pending_mix {
            return None;
        }
        poll.pending_mix = false;
        Some(
            poll.requests
                .clone()
                .into_values()
                .sorted_by(|a, b| Ord::cmp(&a.request.account, &b.request.account))
                .collect()
        )
    }
}

#[derive(Debug, Default)]
struct InnerPoll {
    requests: HashMap<AccountId32, SignedVoteRequest>,
    /// Initially `false`, this is `true` if a background task has been kicked off to mix the vote
    /// requests and submit the results on-chain. The task will set this back to `false` once it has
    /// started by calling [Poll::begin_mix].
    pending_mix: bool
}

#[cfg(test)]
mod tests {
    use sp_runtime::MultiSignature;
    use sp_runtime::testing::sr25519;
    use subxt::utils::H256;

    use common::{Conviction, VoteRequest};
    use Conviction::Locked1x;

    use super::*;

    #[tokio::test]
    async fn add_new_vote_and_then_remove() {
        let glove_state = GloveState::default();
        let account = AccountId32::from([1; 32]);
        let vote_request = signed_vote_request(account.clone(), 1, true, 10);

        let poll = glove_state.get_poll(1).await;

        let pending_mix = poll.add_vote_request(vote_request.clone()).await;
        assert_eq!(pending_mix, true);
        let vote_requeats = poll.begin_mix().await;
        assert_eq!(vote_requeats, Some(vec![vote_request]));

        let pending_mix = poll.remove_vote_request(account).await;
        assert_eq!(pending_mix, Some(true));
        let vote_requeats = poll.begin_mix().await;
        assert_eq!(vote_requeats, Some(vec![]));
        assert_eq!(poll.begin_mix().await, None);
    }

    #[tokio::test]
    async fn remove_from_non_existent_poll() {
        let glove_state = GloveState::default();
        let account = AccountId32::from([1; 32]);
        let poll = glove_state.get_poll(1).await;
        let pending_mix = poll.remove_vote_request(account).await;
        assert_eq!(pending_mix, None);
    }

    #[tokio::test]
    async fn remove_non_existent_account_within_poll() {
        let glove_state = GloveState::default();
        let account_1 = AccountId32::from([1; 32]);
        let account_2 = AccountId32::from([2; 32]);
        let vote_request = signed_vote_request(account_1.clone(), 1, true, 10);

        let poll = glove_state.get_poll(1).await;
        poll.add_vote_request(vote_request.clone()).await;

        let pending_mix = poll.remove_vote_request(account_2).await;
        assert_eq!(pending_mix, None);
    }

    #[tokio::test]
    async fn replace_vote_before_mixing() {
        let glove_state = GloveState::default();
        let account = AccountId32::from([1; 32]);
        let vote_request_1 = signed_vote_request(account.clone(), 1, true, 10);
        let vote_request_2 = signed_vote_request(account.clone(), 1, true, 20);

        let poll = glove_state.get_poll(1).await;

        let pending_mix = poll.add_vote_request(vote_request_1.clone()).await;
        assert_eq!(pending_mix, true);
        let pending_mix = poll.add_vote_request(vote_request_2.clone()).await;
        assert_eq!(pending_mix, false);

        let vote_requeats = poll.begin_mix().await;
        assert_eq!(vote_requeats, Some(vec![vote_request_2]));
    }

    #[tokio::test]
    async fn votes_from_two_accounts_in_between_mixing() {
        let glove_state = GloveState::default();
        let account_1 = AccountId32::from([1; 32]);
        let account_2 = AccountId32::from([2; 32]);
        let vote_request_1 = signed_vote_request(account_1.clone(), 1, true, 10);
        let vote_request_2 = signed_vote_request(account_2.clone(), 1, false, 20);

        let poll = glove_state.get_poll(1).await;

        let pending_mix = poll.add_vote_request(vote_request_2.clone()).await;
        assert_eq!(pending_mix, true);
        let vote_requeats = poll.begin_mix().await;
        assert_eq!(vote_requeats, Some(vec![vote_request_2.clone()]));

        let pending_mix = poll.add_vote_request(vote_request_1.clone()).await;
        assert_eq!(pending_mix, true);
        let vote_requeats = poll.begin_mix().await;
        assert_eq!(vote_requeats, Some(vec![vote_request_1, vote_request_2]));
    }

    fn signed_vote_request(account: AccountId32, poll_index: u32, aye: bool, balance: u128) -> SignedVoteRequest {
        let request = VoteRequest::new(account, H256::zero(), poll_index, aye, balance, Locked1x);
        let signature = MultiSignature::Sr25519(sr25519::Signature::default());
        SignedVoteRequest { request, signature }
    }
}
