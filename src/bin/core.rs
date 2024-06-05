use std::str::FromStr;

use anyhow::{Context, Result};
use rand::random;
use serde::Deserialize;
use sp_core::crypto::{AccountId32, Ss58Codec};
use ss58_registry::{Ss58AddressFormat, Ss58AddressFormatRegistry, Token};
use subxt::blocks::ExtrinsicEvents;
use subxt::OnlineClient;
use subxt_core::config::PolkadotConfig;
use subxt_core::tx::payload::Payload;
use subxt_core::utils::MultiAddress;
use subxt_signer::SecretUri;
use subxt_signer::sr25519::Keypair;

#[subxt::subxt(runtime_metadata_path = "assets/polkadot-metadata.scale")]
pub mod metadata {}

pub fn parse_secret_phrase(str: &str) -> Result<Keypair> {
    Ok(Keypair::from_uri(&SecretUri::from_str(str)?)?)
}

pub struct SubstrateNetwork {
    pub api: OnlineClient<PolkadotConfig>,
    pub ss58_format: Ss58AddressFormat,
    pub token_decimals: u8,
    pub keypair: Keypair,
}

impl SubstrateNetwork {
    pub async fn connect(url: &String, keypair: Keypair) -> Result<Self> {
        let api = OnlineClient::<PolkadotConfig>::from_url(url).await
            .with_context(|| "Unable to connect to network endpoint:")?;
        let ss58_address_format = api.constants()
            .at(&metadata::constants().system().ss58_prefix())
            .map(Ss58AddressFormat::custom)?;
        let ss58 = Ss58AddressFormatRegistry::try_from(ss58_address_format)
            .with_context(|| "Unable to determine network SS58 format")?;
        let token_decimals = ss58.tokens()
            .first()
            .map(|token_registry| Token::from(*token_registry).decimals)
            .unwrap_or(12);
        let network = Self { api, ss58_format: ss58.into(), token_decimals, keypair };
        println!("Address: {}", network.account_string(&network.keypair.public_key().0.into()));
        Ok(network)
    }

    pub async fn call_extrinsic<Call: Payload>(
        &self,
        payload: &Call
    ) -> Result<ExtrinsicEvents<PolkadotConfig>, subxt::Error> {
        Ok(
            self.api.tx()
                .sign_and_submit_then_watch_default(payload, &self.keypair).await?
                .wait_for_finalized_success().await?
        )
    }

    pub fn account_string(&self, account: &AccountId32) -> String {
        account.to_ss58check_with_version(self.ss58_format)
    }
}

pub fn account_to_address(account: AccountId32) -> MultiAddress<subxt_core::utils::AccountId32, ()> {
    // Annoyingly, subxt uses a different AccountId32 to sp-core.
    let account = subxt_core::utils::AccountId32::from(Into::<[u8; 32]>::into(account));
    MultiAddress::Id(account)
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct VoteRequest {
    pub account: AccountId32,
    pub poll_index: u32,
    pub nonce: u128,
    pub aye: bool,
    pub balance: u128
}

impl VoteRequest {
    pub fn new(account: AccountId32, poll_index: u32, aye: bool, balance: u128) -> Self {
        Self { account, poll_index, nonce: random(), aye, balance }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RemoveVoteRequest {
    pub account: AccountId32,
    pub poll_index: u32
}
