use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use aws_sdk_dynamodb::error::SdkError;
use aws_sdk_dynamodb::operation::delete_item::DeleteItemError;
use aws_sdk_dynamodb::operation::put_item::PutItemError;
use aws_sdk_dynamodb::operation::query::QueryError;
use aws_sdk_dynamodb::operation::scan::ScanError;
use sp_runtime::AccountId32;
use tokio::sync::RwLock;

use common::SignedVoteRequest;

use crate::dynamodb::DynamodbGloveStorage;

#[derive(Clone)]
pub enum GloveStorage {
    InMemory(InMemoryGloveStorage),
    Dynamodb(DynamodbGloveStorage),
}

impl GloveStorage {
    pub async fn add_vote_request(&self, signed_request: SignedVoteRequest) -> Result<(), Error> {
        match self {
            GloveStorage::InMemory(store) => Ok(store.add_vote_request(signed_request).await),
            GloveStorage::Dynamodb(store) => store.add_vote_request(signed_request).await,
        }
    }

    pub async fn remove_vote_request(
        &self,
        poll_index: u32,
        account: &AccountId32,
    ) -> Result<bool, Error> {
        match self {
            GloveStorage::InMemory(store) => {
                Ok(store.remove_vote_request(poll_index, account).await)
            }
            GloveStorage::Dynamodb(store) => store.remove_vote_request(poll_index, account).await,
        }
    }

    pub async fn get_poll(&self, poll_index: u32) -> Result<Vec<SignedVoteRequest>, Error> {
        match self {
            GloveStorage::InMemory(store) => Ok(store.get_poll(poll_index).await),
            GloveStorage::Dynamodb(store) => store.get_poll(poll_index).await,
        }
    }

    pub async fn remove_poll(&self, poll_index: u32) -> Result<(), Error> {
        match self {
            GloveStorage::InMemory(store) => Ok(store.remove_poll(poll_index).await),
            GloveStorage::Dynamodb(store) => store.remove_poll(poll_index).await,
        }
    }

    pub async fn get_poll_indices(&self) -> Result<HashSet<u32>, Error> {
        match self {
            GloveStorage::InMemory(store) => Ok(store.get_poll_indices().await),
            GloveStorage::Dynamodb(store) => store.get_poll_indices().await,
        }
    }
}

#[derive(Clone, Default)]
pub struct InMemoryGloveStorage {
    polls: Arc<RwLock<HashMap<u32, BTreeMap<AccountId32, SignedVoteRequest>>>>,
}

impl InMemoryGloveStorage {
    async fn add_vote_request(&self, signed_request: SignedVoteRequest) {
        let mut polls = self.polls.write().await;
        polls
            .entry(signed_request.request.poll_index)
            .or_default()
            .insert(signed_request.request.account.clone(), signed_request);
    }

    async fn remove_vote_request(&self, poll_index: u32, account: &AccountId32) -> bool {
        let mut polls = self.polls.write().await;
        polls
            .get_mut(&poll_index)
            .map(|poll| poll.remove(account).is_some())
            .unwrap_or(false)
    }

    async fn get_poll(&self, poll_index: u32) -> Vec<SignedVoteRequest> {
        let polls = self.polls.read().await;
        let signed_vote_requests = polls
            .get(&poll_index)
            .map(|poll| poll.values().cloned().collect())
            .unwrap_or_default();
        signed_vote_requests
    }

    async fn remove_poll(&self, poll_index: u32) {
        let mut polls = self.polls.write().await;
        polls.remove(&poll_index);
    }

    async fn get_poll_indices(&self) -> HashSet<u32> {
        let polls = self.polls.read().await;
        polls.keys().cloned().collect()
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("DynamoDB put item error: {0}")]
    DynamodbPutItem(#[from] SdkError<PutItemError>),
    #[error("DynamoDB delete item error: {0}")]
    DynamodbDeleteItem(#[from] SdkError<DeleteItemError>),
    #[error("DynamoDB query error: {0}")]
    DynamodbQuery(#[from] SdkError<QueryError>),
    #[error("DynamoDB scan error: {0}")]
    DynamodbScan(#[from] SdkError<ScanError>),
}

#[cfg(test)]
mod tests {
    use sp_runtime::testing::sr25519;
    use sp_runtime::MultiSignature;
    use subxt::utils::H256;

    use common::{Conviction, VoteRequest};
    use Conviction::Locked1x;

    use super::*;

    #[tokio::test]
    async fn add_new_vote_and_then_remove() {
        let store = InMemoryGloveStorage::default();
        let account = AccountId32::from([1; 32]);
        let vote_request = signed_vote_request(account.clone(), 1, true, 10);

        store.add_vote_request(vote_request.clone()).await;
        assert_eq!(store.get_poll(1).await, vec![vote_request]);

        let removed = store.remove_vote_request(1, &account).await;
        assert!(removed);
        assert!(store.get_poll(1).await.is_empty());
    }

    #[tokio::test]
    async fn remove_from_non_existent_poll() {
        let store = InMemoryGloveStorage::default();
        let account = AccountId32::from([1; 32]);
        let removed = store.remove_vote_request(1, &account).await;
        assert!(!removed);
        assert!(store.get_poll(1).await.is_empty());
    }

    #[tokio::test]
    async fn remove_non_existent_account_within_poll() {
        let store = InMemoryGloveStorage::default();
        let account_1 = AccountId32::from([1; 32]);
        let account_2 = AccountId32::from([2; 32]);
        let vote_request = signed_vote_request(account_1.clone(), 1, true, 10);

        store.add_vote_request(vote_request.clone()).await;

        let removed = store.remove_vote_request(1, &account_2).await;
        assert!(!removed);
        assert_eq!(store.get_poll(1).await, vec![vote_request]);
    }

    #[tokio::test]
    async fn replace_vote() {
        let store = InMemoryGloveStorage::default();
        let account = AccountId32::from([1; 32]);
        let vote_request_1 = signed_vote_request(account.clone(), 1, true, 10);
        let vote_request_2 = signed_vote_request(account.clone(), 1, true, 20);

        store.add_vote_request(vote_request_1.clone()).await;
        assert_eq!(store.get_poll(1).await, vec![vote_request_1]);
        store.add_vote_request(vote_request_2.clone()).await;
        assert_eq!(store.get_poll(1).await, vec![vote_request_2]);
    }

    #[tokio::test]
    async fn vote_on_two_polls() {
        let store = InMemoryGloveStorage::default();
        let account = AccountId32::from([1; 32]);
        let vote_request_1 = signed_vote_request(account.clone(), 1, true, 10);
        let vote_request_2 = signed_vote_request(account.clone(), 2, true, 20);

        store.add_vote_request(vote_request_1.clone()).await;
        store.add_vote_request(vote_request_2.clone()).await;
        assert_eq!(store.get_poll(1).await, vec![vote_request_1]);
        assert_eq!(store.get_poll(2).await, vec![vote_request_2]);
    }

    fn signed_vote_request(
        account: AccountId32,
        poll_index: u32,
        aye: bool,
        balance: u128,
    ) -> SignedVoteRequest {
        let request = VoteRequest::new(account, H256::zero(), poll_index, aye, balance, Locked1x);
        let signature = MultiSignature::Sr25519(sr25519::Signature::default());
        SignedVoteRequest { request, signature }
    }
}
