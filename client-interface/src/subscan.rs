use serde::{Deserialize, Serialize};
use serde_with::DisplayFromStr;
use serde_with::serde_as;
use sp_runtime::AccountId32;

use common::ExtrinsicLocation;

pub async fn get_votes(
    http_client: &reqwest::Client,
    network_name: &str,
    poll_index: u32,
    account: Option<AccountId32>
) -> Result<Vec<ConvictionVote>, reqwest::Error> {
    let mut all_votes = Vec::new();

    let mut request = Request {
        referendum_index: poll_index,
        account,
        valid: Valid::Valid,
        row: 100,
        page: 0,
    };

    loop {
        let response = http_client
            .post(&format!("https://{}.api.subscan.io/api/scan/referenda/votes", network_name))
            .json(&request)
            .send().await?
            .json::<Response>().await?;
        let Some(mut votes) = response.data.list else {
            break;
        };
        all_votes.append(&mut votes);
        request.page += 1;
    }

    Ok(all_votes)
}

#[derive(Debug, Clone, Serialize)]
struct Request {
    referendum_index: u32,
    account: Option<AccountId32>,
    valid: Valid,
    page: u32,
    row: u8,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum Valid {
    Valid,
}

#[derive(Debug, Clone, Deserialize)]
struct Response {
    data: Data,
}

#[derive(Debug, Clone, Deserialize)]
struct Data {
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
