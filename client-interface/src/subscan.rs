use std::fmt::Debug;
use std::ops::Deref;
use std::time::Duration;

use reqwest::header::{HeaderMap, RETRY_AFTER};
use serde::{de, Deserialize, Deserializer, Serialize};
use serde::de::DeserializeOwned;
use serde_with::DisplayFromStr;
use serde_with::serde_as;
use sp_core::bytes::from_hex;
use sp_runtime::AccountId32;
use tokio::time::sleep;
use tracing::warn;

use common::ExtrinsicLocation;

#[derive(Clone)]
pub struct Subscan {
    network: String,
    api_key: Option<String>,
    http_client: reqwest::Client,
}

impl Subscan {
    pub fn new(network: String, api_key: Option<String>) -> Self {
        Self {
            network,
            api_key,
            http_client: reqwest::Client::new(),
        }
    }

    pub async fn get_votes(
        &self,
        poll_index: u32,
        account: Option<AccountId32>
    ) -> Result<Vec<ConvictionVote>, Error> {
        let mut all_votes = Vec::new();

        let mut request = VotesRequest {
            referendum_index: poll_index,
            account,
            valid: Valid::Valid,
            row: 100,
            page: 0,
        };

        loop {
            let (headers, votes_response) = self.api_call_for::<VotesResponse>(
                "referenda/votes",
                &request
            ).await?;
            let Some(data) = votes_response.data else {
                handle_error(headers, &votes_response.api_response, &request).await?;
                continue;
            };
            let Some(mut votes) = data.list else {
                break;
            };
            all_votes.append(&mut votes);
            request.page += 1;
        }

        Ok(all_votes)
    }

    pub async fn get_extrinsic(
        &self,
        extrinsic_location: ExtrinsicLocation
    ) -> Result<Option<ExtrinsicDetail>, Error> {
        let request = ExtrinsicRequest {
            events_limit: 1,
            extrinsic_index: extrinsic_location,
            only_extrinsic_event: true,
        };
        loop {
            let (headers, extrinsic_response) = self.api_call_for::<ExtrinsicResponse>(
                "extrinsic",
                &request
            ).await?;
            if extrinsic_response.api_response.code != 0 {
                handle_error(headers, &extrinsic_response.api_response, &request).await?;
                continue;
            }
            return Ok(extrinsic_response.data);
        }
    }

    async fn api_call_for<Resp: DeserializeOwned>(
        &self,
        end_point: &str,
        request: &(impl Serialize + ?Sized)
    ) -> Result<(HeaderMap, Resp), Error> {
        let request_builder = self.http_client
            .post(format!("https://{}.api.subscan.io/api/scan/{}", self.network, end_point));
        let request_builder = match &self.api_key {
            Some(api_key) => request_builder.header("X-API-Key", api_key),
            None => request_builder
        };
        let http_response = request_builder
            .json(&request)
            .send().await?;
        let headers = http_response.headers().clone();
        let response = http_response.json::<Resp>().await?;
        Ok((headers, response))
    }
}

async fn handle_error(
    headers: HeaderMap,
    api_response: &ApiResponse,
    request: &impl Debug
) -> Result<(), Error> {
    let retry_after = headers
        .get(RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .ok_or_else(|| Error::Api {
            code: api_response.code,
            message: api_response.message.clone(),
        })?;
    warn!("Rate limited, retrying after {} seconds ({:?})", retry_after, request);
    sleep(Duration::from_secs(retry_after)).await;
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
struct VotesRequest {
    referendum_index: u32,
    account: Option<AccountId32>,
    valid: Valid,
    page: u32,
    row: u8,
}

#[serde_as]
#[derive(Debug, Clone, Serialize)]
struct ExtrinsicRequest {
    events_limit: u32,
    #[serde_as(as = "DisplayFromStr")]
    extrinsic_index: ExtrinsicLocation,
    only_extrinsic_event: bool
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum Valid {
    Valid,
}

#[derive(Debug, Clone, Deserialize)]
struct ApiResponse {
    code: i64,
    message: String
}

#[derive(Debug, Clone, Deserialize)]
struct VotesResponse {
    #[serde(flatten)]
    api_response: ApiResponse,
    data: Option<VotesData>,
}

#[derive(Debug, Clone, Deserialize)]
struct VotesData {
    list: Option<Vec<ConvictionVote>>,
}

#[serde_as]
#[derive(Debug, Clone, Deserialize)]
pub struct ConvictionVote {
    pub account: Account,
    #[serde_as(as = "DisplayFromStr")]
    pub extrinsic_index: ExtrinsicLocation,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Account {
    pub address: AccountId32,
}

#[derive(Debug, Clone, Deserialize)]
struct ExtrinsicResponse {
    #[serde(flatten)]
    api_response: ApiResponse,
    data: Option<ExtrinsicDetail>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExtrinsicDetail {
    pub account_display: Option<Account>,
    pub call_module: String,
    pub call_module_function: String,
    pub params: Vec<ExtrinsicParam>
}

impl ExtrinsicDetail {
    pub fn account_address(&self) -> Option<AccountId32> {
        self.account_display.as_ref().map(|account| account.address.clone())
    }

    pub fn is_extrinsic(&self, call_module: &str, call_module_function: &str) -> bool {
        self.call_module.to_ascii_lowercase() == call_module &&
            self.call_module_function.to_ascii_lowercase() == call_module_function
    }

    pub fn get_param(&self, name: &str) -> Option<ExtrinsicParam> {
        self.params.iter().find(|param| param.name == name).cloned()
    }

    pub fn get_param_as<T: DeserializeOwned>(&self, name: &str) -> Option<T> {
        self.get_param(name).and_then(|param| param.value_as::<T>().ok())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExtrinsicParam {
    pub name: String,
    pub value: serde_json::Value
}

impl ExtrinsicParam {
    pub fn value_as<T: DeserializeOwned>(self) -> Result<T, serde_json::Error> {
        serde_json::from_value(self.value)
    }
}

#[derive(Deserialize)]
#[serde(transparent)]
pub struct HexString {
    #[serde(deserialize_with = "hex_deserialize")]
    pub value: Vec<u8>
}

impl Deref for HexString {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl AsRef<[u8]> for HexString {
    fn as_ref(&self) -> &[u8] {
        &self.value
    }
}

#[derive(Debug, PartialEq, Deserialize)]
pub enum MultiAddress {
    Id(AccountId32Ext)
}

#[serde_as]
#[derive(Debug, PartialEq, Deserialize)]
#[serde(transparent)]
pub struct AccountId32Ext {
    #[serde_as(as = "DisplayFromStr")]
    pub value: AccountId32
}

impl Deref for AccountId32Ext {
    type Target = AccountId32;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl From<AccountId32> for AccountId32Ext {
    fn from(value: AccountId32) -> Self {
        Self { value }
    }
}

#[derive(Debug, Deserialize)]
pub struct RuntimeCall {
    pub call_module: String,
    pub call_name: String,
    pub params: Vec<ExtrinsicParam>
}

impl RuntimeCall {
    pub fn is_extrinsic(&self, call_module: &str, call_module_function: &str) -> bool {
        self.call_module.to_ascii_lowercase() == call_module &&
            self.call_name.to_ascii_lowercase() == call_module_function
    }

    pub fn get_param(&self, name: &str) -> Option<ExtrinsicParam> {
        self.params.iter().find(|param| param.name == name).cloned()
    }

    pub fn get_param_as<T: DeserializeOwned>(&self, name: &str) -> Option<T> {
        self.get_param(name).and_then(|param| param.value_as::<T>().ok())
    }
}

#[derive(Debug, PartialEq, Deserialize)]
pub enum AccountVote {
    Standard(StandardAccountVote),
    SplitAbstain(SplitAbstainAccountVote)
}

#[serde_as]
#[derive(Debug, PartialEq, Deserialize)]
pub struct StandardAccountVote {
    #[serde_as(as = "DisplayFromStr")]
    pub balance: u128,
    pub vote: u8
}

#[serde_as]
#[derive(Debug, PartialEq, Deserialize)]
pub struct SplitAbstainAccountVote {
    #[serde_as(as = "DisplayFromStr")]
    pub aye: u128,
    #[serde_as(as = "DisplayFromStr")]
    pub nay: u128,
    #[serde_as(as = "DisplayFromStr")]
    pub abstain: u128
}

fn hex_deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    from_hex(&String::deserialize(deserializer)?).map_err(|e| de::Error::custom(e))
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("API error: ({code}) {message}")]
    Api {
        code: i64,
        message: String,
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use subxt_core::utils::to_hex;

    use super::*;

    #[test]
    fn hex_string() {
        let json = r#"
            {
              "name": "remark",
              "type": "Vec<U8>",
              "value": "0x01050301c000965d770664c93693f56f70c9"
            }
"#;
        let extrinsic_param = serde_json::from_str::<ExtrinsicParam>(json).unwrap();
        assert_eq!(extrinsic_param.name, "remark");
        let hex_string = extrinsic_param.value_as::<HexString>().unwrap();
        assert_eq!(to_hex(hex_string), "0x01050301c000965d770664c93693f56f70c9");
    }

    #[test]
    fn multi_address() {
        let json = r#"
            {
              "name": "real",
              "type": "sp_runtime:multiaddress:MultiAddress",
              "value": {
                "Id": "0xf40f4316f0adec098c14637d132a827ce6f36c930aca32a56a2cc65f7177be2b"
              }
            }
"#;
        let extrinsic_param = serde_json::from_str::<ExtrinsicParam>(json).unwrap();
        assert_eq!(extrinsic_param.name, "real");
        let multi_address = extrinsic_param.value_as::<MultiAddress>().unwrap();
        assert_eq!(multi_address, MultiAddress::Id(AccountId32::from_str("0xf40f4316f0adec098c14637d132a827ce6f36c930aca32a56a2cc65f7177be2b").unwrap().into()));
    }

    #[test]
    fn standard_account_vote() {
        let json = r#"
            {
              "name": "vote",
              "type": "pallet_conviction_voting:vote:AccountVote",
              "value": {
                "Standard": {
                  "balance": "420964038408",
                  "vote": 2
                }
              }
            }
"#;
        let extrinsic_param = serde_json::from_str::<ExtrinsicParam>(json).unwrap();
        assert_eq!(extrinsic_param.name, "vote");
        let account_vote = extrinsic_param.value_as::<AccountVote>().unwrap();
        assert_eq!(account_vote, AccountVote::Standard(StandardAccountVote { balance: 420964038408, vote: 2 }));
    }
}
