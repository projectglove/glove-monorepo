use std::fmt::Debug;
use std::str::FromStr;

use anyhow::{Context, Result};
use rand::random;
use serde::{Deserialize, Serialize};
use sp_core::crypto::{AccountId32, Ss58Codec};
use ss58_registry::{Ss58AddressFormat, Ss58AddressFormatRegistry, Token};
use subxt::blocks::ExtrinsicEvents;
use subxt::Error as SubxtError;
use subxt::ext::scale_decode::DecodeAsType;
use subxt::OnlineClient;
use subxt::utils::AccountId32 as SubxtAccountId32;
use subxt_core::config::PolkadotConfig;
use subxt_core::tx::payload::Payload;
use subxt_core::utils::MultiAddress;
use subxt_signer::SecretUri;
use subxt_signer::sr25519::Keypair;

use metadata::runtime_types::polkadot_runtime::ProxyType;
use metadata::runtime_types::polkadot_runtime::RuntimeCall;
use metadata::runtime_types::polkadot_runtime::RuntimeError;
use metadata::runtime_types::sp_runtime::DispatchError;
use metadata::utility::events::BatchInterrupted;

#[subxt::subxt(runtime_metadata_path = "../assets/polkadot-metadata.scale")]
pub mod metadata {}

pub fn parse_secret_phrase(str: &str) -> Result<Keypair> {
    Ok(Keypair::from_uri(&SecretUri::from_str(str)?)?)
}

#[derive(Clone)]
pub struct SubstrateNetwork {
    pub url: String,
    pub api: OnlineClient<PolkadotConfig>,
    pub ss58_format: Ss58AddressFormat,
    pub token_decimals: u8,
    pub keypair: Keypair,
}

impl SubstrateNetwork {
    pub async fn connect(url: String, keypair: Keypair) -> Result<Self> {
        let api = OnlineClient::<PolkadotConfig>::from_url(url.clone()).await
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
        Ok(Self { url, api, ss58_format: ss58.into(), token_decimals, keypair })
    }

    pub fn account(&self) -> AccountId32 {
        self.keypair.public_key().0.into()
    }

    pub async fn call_extrinsic<Call: Payload>(
        &self,
        payload: &Call
    ) -> Result<ExtrinsicEvents<PolkadotConfig>, SubxtError> {
        Ok(
            self.api.tx()
                .sign_and_submit_then_watch_default(payload, &self.keypair).await?
                .wait_for_finalized_success().await?
        )
    }

    pub async fn batch(&self, calls: Vec<RuntimeCall>) -> Result<ExtrinsicEvents<PolkadotConfig>, BatchError> {
        let payload = metadata::tx().utility().batch(calls).unvalidated();
        let events = self.call_extrinsic(&payload).await?;
        if let Some(batch_interrupted) = events.find_first::<BatchInterrupted>()? {
            if let Some(runtime_error) = self.extract_runtime_error(&batch_interrupted.error) {
                return Err(BatchError::Module(batch_interrupted.index as usize, runtime_error));
            }
            return Err(BatchError::Dispatch(batch_interrupted));
        }
        Ok(events)
    }

    /// This is the equivalent to calling [subxt::error::DispatchError::decode_from] followed by
    /// [subxt::error::ModuleError::as_root_error], but for the `DispatchError` type from the
    /// metadata.
    pub fn extract_runtime_error(&self, error: &DispatchError) -> Option<RuntimeError> {
        if let DispatchError::Module(module_error) = error {
            let bytes = [
                module_error.index,
                module_error.error[0],
                module_error.error[1],
                module_error.error[2],
                module_error.error[3]
            ];
            let metadata = self.api.metadata();
            // Taken from ModuleError::as_root_error
            RuntimeError::decode_as_type(
                &mut &bytes[..],
                metadata.outer_enums().error_enum_ty(),
                metadata.types(),
            ).ok()
        } else {
            None
        }
    }

    pub fn account_string(&self, account: &AccountId32) -> String {
        account.to_ss58check_with_version(self.ss58_format)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum BatchError {
    #[error("Module error from batch index {0}: {1:?}")]
    Module(usize, RuntimeError),
    #[error("Batch of calls did not complete: {0:?}")]
    Dispatch(BatchInterrupted),
    #[error("Internal Subxt error: {0}")]
    Subxt(#[from] SubxtError),
}

pub async fn is_glove_member(
    network: &SubstrateNetwork,
    client_account: AccountId32,
    glove_account: AccountId32
) -> Result<bool, SubxtError> {
    let proxies_query = metadata::storage()
        .proxy()
        .proxies(core_to_subxt(client_account))
        .unvalidated();
    let result = network.api.storage().at_latest().await?.fetch(&proxies_query).await?;
    if let Some(proxies) = result {
        let glove_account = core_to_subxt(glove_account);
        Ok(
            proxies.0.0.iter().any(|proxy| {
                matches!(proxy.proxy_type, ProxyType::Any | ProxyType::Governance) &&
                    proxy.delegate == glove_account
            })
        )
    } else {
        Ok(false)
    }
}

// Annoyingly, subxt uses a different AccountId32 to sp-core.
pub fn core_to_subxt(account: AccountId32) -> SubxtAccountId32 {
    SubxtAccountId32::from(Into::<[u8; 32]>::into(account))
}

pub fn account_to_address(account: AccountId32) -> MultiAddress<SubxtAccountId32, ()> {
    MultiAddress::Id(core_to_subxt(account))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub proxy_account: AccountId32,
    pub network_url: String
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveVoteRequest {
    pub account: AccountId32,
    pub poll_index: u32
}