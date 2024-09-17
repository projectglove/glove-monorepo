use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::storage::Error;
use anyhow::{anyhow, bail};
use aws_config::BehaviorVersion;
use aws_sdk_dynamodb::error::SdkError;
use aws_sdk_dynamodb::operation::query::QueryError;
use aws_sdk_dynamodb::primitives::Blob;
use aws_sdk_dynamodb::types::builders::AttributeDefinitionBuilder;
use aws_sdk_dynamodb::types::{
    AttributeValue, KeyType, ReturnValue, ScalarAttributeType, TableDescription, TableStatus,
};
use aws_sdk_dynamodb::Client;
use common::SignedVoteRequest;
use parity_scale_codec::{Decode, Encode};
use sp_runtime::AccountId32;
use tokio::sync::Mutex;
use tracing::warn;

#[derive(Clone)]
pub struct DynamodbGloveStorage {
    pub table_name: String,
    partition_key: String,
    sort_key: String,
    client: Client,
    #[allow(clippy::type_complexity)]
    cached_vote_accounts: Arc<Mutex<Option<HashMap<u32, HashSet<AccountId32>>>>>,
}

impl DynamodbGloveStorage {
    pub async fn connect(table_name: String) -> anyhow::Result<Self> {
        let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
        let client = Client::new(&config);
        let table_description = client
            .describe_table()
            .table_name(&table_name)
            .send()
            .await?
            .table
            .ok_or_else(|| anyhow!("Table not found"))?;
        if table_description.table_status != Some(TableStatus::Active) {
            bail!(
                "Table is not in active state: {:?}",
                table_description.table_status
            );
        }
        let partition_key = find_schema_element(&table_description, KeyType::Hash)?;
        if !is_attribute_type(&table_description, &partition_key, ScalarAttributeType::S)? {
            bail!("Partition key '{}' is not string", partition_key);
        }
        let sort_key = find_schema_element(&table_description, KeyType::Range)?;
        if !is_attribute_type(&table_description, &sort_key, ScalarAttributeType::S)? {
            bail!("Sort key '{}' is not string", sort_key);
        }
        Ok(Self {
            table_name,
            partition_key,
            sort_key,
            client,
            cached_vote_accounts: Arc::default(),
        })
    }

    pub async fn add_vote_request(&self, signed_request: SignedVoteRequest) -> Result<(), Error> {
        let request = &signed_request.request;

        self.client
            .put_item()
            .table_name(&self.table_name)
            .item(&self.partition_key, poll_index_to_value(request.poll_index))
            .item(&self.sort_key, account_vote_to_value(&request.account))
            // Put the vote fields in separate attributes if ever easy access is needed
            .item("Account", AttributeValue::S(request.account.to_string()))
            .item(
                "GenesisHash",
                AttributeValue::S(format!("{:#x}", request.genesis_hash)),
            )
            .item(
                "PollIndex",
                AttributeValue::N(request.poll_index.to_string()),
            )
            .item("Nonce", AttributeValue::N(request.nonce.to_string()))
            .item("Aye", AttributeValue::Bool(request.aye))
            .item("Balance", AttributeValue::N(request.balance.to_string()))
            .item(
                "Conviction",
                AttributeValue::S(format!("{:?}", request.conviction)),
            )
            .item(
                "SignedVoteRequest",
                AttributeValue::B(Blob::new(signed_request.encode())),
            )
            .send()
            .await?;

        let mut cached_vote_accounts = self.cached_vote_accounts.lock().await;
        if let Some(cached_vote_accounts) = &mut *cached_vote_accounts {
            cached_vote_accounts
                .entry(request.poll_index)
                .or_default()
                .insert(signed_request.request.account);
        }

        Ok(())
    }

    pub async fn remove_vote_request(
        &self,
        poll_index: u32,
        account: &AccountId32,
    ) -> Result<bool, Error> {
        let mut cached_vote_accounts = self.cached_vote_accounts.lock().await;
        if let Some(cached_vote_accounts) = &mut *cached_vote_accounts {
            // This function is called frequently, so there's no need to consume a write capacity
            // unit if the vote is not found in the cache.
            let Some(poll_accounts) = cached_vote_accounts.get_mut(&poll_index) else {
                return Ok(false);
            };
            if !poll_accounts.remove(account) {
                return Ok(false);
            }
            if poll_accounts.is_empty() {
                cached_vote_accounts.remove(&poll_index);
            }
        }

        let delete_item_output = self
            .client
            .delete_item()
            .table_name(&self.table_name)
            .key(&self.partition_key, poll_index_to_value(poll_index))
            .key(&self.sort_key, account_vote_to_value(account))
            .return_values(ReturnValue::AllOld)
            .send()
            .await?;

        Ok(delete_item_output
            .attributes
            .filter(|attrs| !attrs.is_empty())
            .is_some())
    }

    pub async fn get_poll(&self, poll_index: u32) -> Result<Vec<SignedVoteRequest>, Error> {
        let signed_vote_requests = self
            .get_poll_items(poll_index, "SignedVoteRequest")
            .await?
            .iter()
            .filter_map(|item| {
                let value = item.get("SignedVoteRequest");
                if value.is_none() {
                    warn!("SignedVoteRequest not found in item: {:?}", item);
                }
                value
            })
            .filter_map(|value| match value.as_b() {
                Ok(blob) => Some(blob),
                Err(_) => {
                    warn!("SignedVoteRequest is not a blob: {:?}", value);
                    None
                }
            })
            .filter_map(|blob| match SignedVoteRequest::decode(&mut blob.as_ref()) {
                Ok(signed_request) => Some(signed_request),
                Err(error) => {
                    warn!("Failed to decode SignedVoteRequest: {:?}", error);
                    None
                }
            })
            .filter_map(|signed_request| {
                if signed_request.verify() {
                    Some(signed_request)
                } else {
                    warn!("Invalid SignedVoteRequest: {:?}", signed_request);
                    None
                }
            })
            .filter_map(|signed_request| {
                if signed_request.request.poll_index == poll_index {
                    Some(signed_request)
                } else {
                    warn!(
                        "SignedVoteRequest is not for poll {}: {:?}",
                        poll_index, signed_request
                    );
                    None
                }
            })
            .collect::<Vec<_>>();
        Ok(signed_vote_requests)
    }

    pub async fn remove_poll(&self, poll_index: u32) -> Result<(), Error> {
        let poll_value = poll_index_to_value(poll_index);
        let account_values = self
            .get_poll_items(poll_index, &self.sort_key)
            .await?
            .into_iter()
            .filter_map(|item| item.get(&self.sort_key).cloned());
        for account_value in account_values {
            self.client
                .delete_item()
                .table_name(&self.table_name)
                .key(&self.partition_key, poll_value.clone())
                .key(&self.sort_key, account_value)
                .send()
                .await?;
        }

        let mut cached_vote_accounts = self.cached_vote_accounts.lock().await;
        if let Some(cached_vote_accounts) = &mut *cached_vote_accounts {
            cached_vote_accounts.remove(&poll_index);
        }

        Ok(())
    }

    pub async fn get_poll_indices(&self) -> Result<HashSet<u32>, Error> {
        // This function is called frequently so we cache the vote accounts to avoid scanning the
        // entire table repeatedly.
        let mut cached_vote_accounts = self.cached_vote_accounts.lock().await;
        if let Some(cached_vote_accounts) = &*cached_vote_accounts {
            return Ok(cached_vote_accounts.keys().cloned().collect());
        }

        let mut vote_accounts: HashMap<u32, HashSet<AccountId32>> = HashMap::new();
        let mut exclusive_start_key = None;
        loop {
            let scan_output = self
                .client
                .scan()
                .table_name(&self.table_name)
                .set_exclusive_start_key(exclusive_start_key)
                .projection_expression("PollIndex,Account")
                .send()
                .await?;
            for item in scan_output.items() {
                let poll_index = item
                    .get("PollIndex")
                    .and_then(|v| v.as_n().ok())
                    .and_then(|s| s.parse::<u32>().ok());
                let account = item
                    .get("Account")
                    .and_then(|v| v.as_s().ok())
                    .and_then(|s| s.parse::<AccountId32>().ok());
                if let (Some(poll_index), Some(account)) = (poll_index, account) {
                    vote_accounts.entry(poll_index).or_default().insert(account);
                } else {
                    warn!("Invalid vote item: {:?}", item);
                }
            }
            exclusive_start_key = scan_output.last_evaluated_key;
            if exclusive_start_key.is_none() {
                break;
            }
        }

        let poll_indices = vote_accounts.keys().cloned().collect();
        *cached_vote_accounts = Some(vote_accounts);
        Ok(poll_indices)
    }

    async fn get_poll_items(
        &self,
        poll_index: u32,
        projection: &str,
    ) -> Result<Vec<HashMap<String, AttributeValue>>, SdkError<QueryError>> {
        let mut items = Vec::new();
        let mut exclusive_start_key = None;
        loop {
            let query_output = self
                .client
                .query()
                .table_name(&self.table_name)
                .key_condition_expression(format!("{} = :poll", self.partition_key))
                .expression_attribute_values(":poll", poll_index_to_value(poll_index))
                .projection_expression(projection)
                .set_exclusive_start_key(exclusive_start_key)
                .send()
                .await?;
            items.extend(query_output.items.unwrap_or_default());
            exclusive_start_key = query_output.last_evaluated_key;
            if exclusive_start_key.is_none() {
                break;
            }
        }
        Ok(items)
    }
}

fn find_schema_element(
    table_description: &TableDescription,
    key_type: KeyType,
) -> anyhow::Result<String> {
    table_description
        .key_schema()
        .iter()
        .find_map(|kse| (kse.key_type == key_type).then(|| kse.attribute_name.clone()))
        .ok_or_else(|| anyhow!("{} schema element not found", key_type))
}

fn is_attribute_type(
    table_description: &TableDescription,
    attribute_name: impl Into<String>,
    attribute_type: ScalarAttributeType,
) -> anyhow::Result<bool> {
    let attribute_definition = AttributeDefinitionBuilder::default()
        .attribute_name(attribute_name)
        .attribute_type(attribute_type)
        .build()?;
    Ok(table_description
        .attribute_definitions()
        .contains(&attribute_definition))
}

fn poll_index_to_value(poll_index: u32) -> AttributeValue {
    AttributeValue::S(format!("POLL#{}#", poll_index))
}

fn account_vote_to_value(account: &AccountId32) -> AttributeValue {
    AttributeValue::S(format!("VOTE#{}#", account))
}
