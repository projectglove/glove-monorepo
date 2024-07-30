use std::fmt::Debug;
use std::time::Duration;

use reqwest::header::{HeaderMap, RETRY_AFTER};
use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;
use serde_with::DisplayFromStr;
use serde_with::serde_as;
use sp_runtime::AccountId32;
use tokio::time::sleep;
use tracing::warn;

use common::ExtrinsicLocation;

#[derive(Clone)]
pub struct Subscan {
    http_client: reqwest::Client,
    network: String,
}

impl Subscan {
    pub fn new(network: String) -> Self {
        Self {
            http_client: reqwest::Client::new(),
            network,
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
        let http_response = self.http_client
            .post(format!("https://{}.api.subscan.io/api/scan/{}", self.network, end_point))
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
        .and_then(|v| v.parse::<u64>().ok());
    match retry_after {
        Some(retry_after) => {
            warn!("Rate limited, retrying after {} seconds ({:?})", retry_after, request);
            sleep(Duration::from_secs(retry_after)).await;
            Ok(())
        }
        None => Err(Error::Api {
            code: api_response.code,
            message: api_response.message.clone(),
        })
    }
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
    pub account_display: Option<Account>
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
