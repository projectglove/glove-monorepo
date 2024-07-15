use std::fmt;
use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Context, Result};
use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use serde::{Deserialize, Serialize};
use sp_core::crypto::AccountId32;
use sp_runtime::{MultiAddress, MultiSignature};
use sp_runtime::traits::Verify;
use ss58_registry::{Ss58AddressFormat, Ss58AddressFormatRegistry, Token};
use subxt::Error as SubxtError;
use subxt::ext::scale_decode::DecodeAsType;
use subxt::utils::AccountId32 as SubxtAccountId32;
use subxt_core::config::PolkadotConfig;
use subxt_core::ext::sp_core::hexdisplay::AsBytesRef;
use subxt_core::tx::payload::Payload;
use subxt_signer::SecretUri;
use subxt_signer::sr25519;
use tokio::sync::Mutex;

use common::attestation::AttestationBundle;
use common::ExtrinsicLocation;
use metadata::proxy::events::ProxyExecuted;
use metadata::referenda::storage::types::referendum_info_for::ReferendumInfoFor;
use metadata::runtime_types::frame_support::traits::preimages::Bounded;
use metadata::runtime_types::pallet_conviction_voting::types::Tally;
use metadata::runtime_types::polkadot_runtime::OriginCaller;
use metadata::runtime_types::polkadot_runtime::ProxyType;
use metadata::runtime_types::polkadot_runtime::RuntimeCall;
use metadata::runtime_types::polkadot_runtime::RuntimeError;
use metadata::runtime_types::sp_runtime::DispatchError;
use metadata::runtime_types::sp_runtime::traits::BlakeTwo256;
use metadata::storage;
use metadata::utility::events::BatchInterrupted;

#[subxt::subxt(runtime_metadata_path = "../assets/polkadot-metadata.scale")]
pub mod metadata {}

pub type OnlineClient = subxt::OnlineClient<PolkadotConfig>;
pub type Block = subxt::blocks::Block<PolkadotConfig, OnlineClient>;
pub type ExtrinsicDetails = subxt::blocks::ExtrinsicDetails<PolkadotConfig, OnlineClient>;
pub type ExtrinsicEvents = subxt::blocks::ExtrinsicEvents<PolkadotConfig>;
pub type SubxtMultiAddressId32 = subxt::utils::MultiAddress<SubxtAccountId32, ()>;

pub type ReferendumStatus = metadata::runtime_types::pallet_referenda::types::ReferendumStatus<
    u16,
    OriginCaller,
    u32,
    Bounded<RuntimeCall, BlakeTwo256>,
    u128,
    Tally<u128>,
    subxt::utils::AccountId32,
    (u32, u32)
>;

#[derive(Clone)]
pub struct SubstrateNetwork {
    pub url: String,
    pub api: OnlineClient,
    pub network_name: String,
    pub token_decimals: u8,
    pub account_key: sr25519::Keypair,
    submit_lock: Arc<Mutex<()>>
}

impl SubstrateNetwork {
    pub async fn connect(url: String, account_key: sr25519::Keypair) -> Result<Self> {
        let api = OnlineClient::from_url(url.clone()).await
            .with_context(|| "Unable to connect to network endpoint:")?;
        let ss58_address_format = api.constants()
            .at(&metadata::constants().system().ss58_prefix())
            .map(Ss58AddressFormat::custom)?;
        let ss58_address_format_registry = Ss58AddressFormatRegistry::try_from(ss58_address_format)
            .with_context(|| "Unable to determine network SS58 format")?;
        let mut network_name = ss58_address_format.to_string();
        if network_name == "substrate" {
            // For some reason Rococo is mapped to the generic "Substrate" network name.
            network_name = "rococo".to_string();
        }
        let token_decimals = ss58_address_format_registry.tokens()
            .first()
            .map(|token_registry| Token::from(*token_registry).decimals)
            .unwrap_or(12);
        Ok(Self {
            url,
            api,
            network_name,
            token_decimals,
            account_key,
            submit_lock: Arc::default()
        })
    }

    pub fn account(&self) -> AccountId32 {
        self.account_key.public_key().0.into()
    }

    pub async fn get_block(&self, block_number: u32) -> Result<Option<Block>, SubxtError> {
        let block_hash = self.api
            .storage()
            .at_latest().await?
            .fetch(&storage().system().block_hash(block_number)).await?;
        match block_hash {
            Some(block_hash) => Ok(Some(self.api.blocks().at(block_hash).await?)),
            None => Ok(None)
        }
    }

    pub async fn get_extrinsic(
        &self,
        location: ExtrinsicLocation
    ) -> Result<Option<ExtrinsicDetails>, SubxtError> {
        let Some(block) = self.get_block(location.block_number).await? else {
            return Ok(None);
        };
        block.extrinsics().await?
            .iter()
            .nth(location.extrinsic_index as usize)
            .transpose()
    }

    pub async fn call_extrinsic<Call: Payload>(
        &self,
        payload: &Call
    ) -> Result<(ExtrinsicEvents, ExtrinsicLocation), SubxtError> {
        // Submitting concurrent extrinsics causes problems with the nonce
        let guard = self.submit_lock.lock().await;
        let tx_in_block = self.api.tx()
            .sign_and_submit_then_watch_default(payload, &self.account_key).await?
            .wait_for_finalized().await?;
        // Unlock here as it's now OK for another thread to submit an extrinsic
        drop(guard);
        let events = tx_in_block.wait_for_success().await?;
        let location = ExtrinsicLocation {
            block_number: self.api.blocks().at(tx_in_block.block_hash()).await?.number(),
            extrinsic_index: events.extrinsic_index()
        };
        Ok((events, location))
    }

    pub async fn batch(&self, calls: Vec<RuntimeCall>) -> Result<ExtrinsicEvents, BatchError> {
        let payload = metadata::tx().utility().batch(calls).unvalidated();
        let (events, _) = self.call_extrinsic(&payload).await?;
        if let Some(batch_interrupted) = events.find_first::<BatchInterrupted>()? {
            let runtime_error = self.extract_runtime_error(&batch_interrupted.error);
            return if let Some(runtime_error) = runtime_error {
                Err(BatchError::Module(batch_interrupted.index as usize, runtime_error))
            } else {
                Err(BatchError::Dispatch(batch_interrupted))
            }
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

    pub fn confirm_proxy_executed(&self, events: &ExtrinsicEvents) -> Result<(), ProxyError> {
        // Find the first proxy call which failed, if any
        for (batch_index, proxy_executed) in events.find::<ProxyExecuted>().enumerate() {
            match proxy_executed {
                Ok(ProxyExecuted { result: Ok(_) }) => continue,
                Ok(ProxyExecuted { result: Err(dispatch_error) }) => {
                    return self.extract_runtime_error(&dispatch_error)
                        .map_or_else(
                            || Err(ProxyError::Dispatch(batch_index, dispatch_error)),
                            |runtime_error| Err(ProxyError::Module(batch_index, runtime_error))
                        )
                },
                Err(subxt_error) => return Err(subxt_error.into())
            }
        }
        Ok(())
    }

    pub async fn subscribe_successful_extrinsics<F, Fut>(&self, f: F) -> Result<(), SubxtError>
    where
        Fut: Future<Output = Result<(), SubxtError>>,
        F: Fn(ExtrinsicDetails, ExtrinsicEvents) -> Fut
    {
        let mut blocks_sub = self.api.blocks().subscribe_finalized().await?;
        while let Some(block) = blocks_sub.next().await {
            for extrinsic in block?.extrinsics().await?.iter() {
                let extrinsic = extrinsic?;
                let events = extrinsic.events().await?;
                if Self::is_extrinsic_successful(&events)? {
                    f(extrinsic, events).await?;
                }
            }
        }
        Ok(())
    }

    fn is_extrinsic_successful(events: &ExtrinsicEvents) -> Result<bool, SubxtError> {
        for event in events.iter() {
            let event = event?;
            if event.pallet_name() == "System" && event.variant_name() == "ExtrinsicFailed" {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub async fn account_balance(&self, account: AccountId32) -> Result<u128, SubxtError> {
        let balance = self.api
            .storage()
            .at_latest().await?
            .fetch(&storage().system().account(core_to_subxt(account))).await?
            .map_or(0, |account| account.data.free);
        Ok(balance)
    }

    pub async fn get_ongoing_poll(
        &self,
        poll_index: u32
    ) -> Result<Option<ReferendumStatus>, SubxtError> {
        match self.get_poll(poll_index).await? {
            Some(ReferendumInfoFor::Ongoing(status)) => Ok(Some(status)),
            _ => Ok(None),
        }
    }

    pub async fn get_poll(&self, poll_index: u32) -> Result<Option<ReferendumInfoFor>, SubxtError> {
        self.api
            .storage()
            .at_latest().await?
            .fetch(&storage().referenda().referendum_info_for(poll_index).unvalidated()).await
    }
}

impl Debug for SubstrateNetwork {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubstrateNetwork")
            .field("url", &self.url)
            .field("network_name", &self.network_name)
            .field("token_decimals", &self.token_decimals)
            .field("account", &self.account())
            .finish()
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

#[derive(thiserror::Error, Debug)]
pub enum ProxyError {
    #[error("Module error from batch index {0}: {1:?}")]
    Module(usize, RuntimeError),
    #[error("Dispatch error from batch index {0}: {1:?}")]
    Dispatch(usize, DispatchError),
    #[error("Batch error: {0}")]
    Batch(#[from] BatchError),
    #[error("Internal Subxt error: {0}")]
    Subxt(#[from] SubxtError)
}

impl ProxyError {
    pub fn batch_index(&self) -> Option<usize> {
        match self {
            ProxyError::Module(batch_index, _) => Some(*batch_index),
            ProxyError::Dispatch(batch_index, _) => Some(*batch_index),
            ProxyError::Batch(BatchError::Module(batch_index, _)) => Some(*batch_index),
            ProxyError::Batch(BatchError::Dispatch(batch_interrupted)) =>
                Some(batch_interrupted.index as usize),
            _ => None
        }
    }
}

pub async fn is_glove_member(
    network: &SubstrateNetwork,
    client_account: AccountId32,
    glove_account: AccountId32
) -> Result<bool, SubxtError> {
    let proxies_query = storage()
        .proxy()
        .proxies(core_to_subxt(client_account))
        .unvalidated();
    let result = network.api.storage().at_latest().await?.fetch(&proxies_query).await?;
    if let Some(proxies) = result {
        let glove_account = core_to_subxt(glove_account);
        Ok(proxies.0.0
            .iter()
            .any(|proxy| {
                matches!(proxy.proxy_type, ProxyType::Any | ProxyType::Governance) &&
                    proxy.delegate == glove_account
            })
        )
    } else {
        Ok(false)
    }
}

pub fn account(extrinsic: &ExtrinsicDetails) -> Option<AccountId32> {
    extrinsic.address_bytes().and_then(parse_multi_address)
}

pub fn parse_multi_address(bytes: &[u8]) -> Option<AccountId32> {
    type MultiAddress32 = MultiAddress<AccountId32, u32>;

    MultiAddress32::decode(&mut bytes.as_bytes_ref())
        .ok()
        .and_then(|address| match address {
            MultiAddress::Id(account) => Some(account),
            _ => None
        })
}

// Annoyingly, subxt uses a different AccountId32 to sp-core.
pub fn core_to_subxt(account: AccountId32) -> SubxtAccountId32 {
    let bytes: [u8; 32] = account.into();
    bytes.into()
}

pub fn account_to_subxt_multi_address(account: AccountId32) -> SubxtMultiAddressId32 {
    SubxtMultiAddressId32::Id(core_to_subxt(account))
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub proxy_account: AccountId32,
    pub network_name: String,
    pub node_endpoint: String,
    #[serde(with = "common::serde_over_hex_scale")]
    pub attestation_bundle: AttestationBundle
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, MaxEncodedLen)]
pub struct SignedRemoveVoteRequest {
    #[serde(with = "common::serde_over_hex_scale")]
    pub request: RemoveVoteRequest,
    #[serde(with = "common::serde_over_hex_scale")]
    pub signature: MultiSignature
}

impl SignedRemoveVoteRequest {
    pub fn verify(&self) -> bool {
        self.signature.verify(&*self.request.encode(), &self.request.account)
    }
}

#[derive(Debug, Clone, PartialEq, Encode, Decode, MaxEncodedLen)]
pub struct RemoveVoteRequest {
    pub account: AccountId32,
    pub poll_index: u32
}

pub fn parse_secret_phrase(str: &str) -> Result<sr25519::Keypair> {
    Ok(sr25519::Keypair::from_uri(&SecretUri::from_str(str)?)?)
}

#[cfg(test)]
mod tests {
    use parity_scale_codec::Encode;
    use rand::random;
    use serde_json::{json, Value};
    use sp_core::{ed25519, Pair};
    use subxt_signer::sr25519::dev;

    use common::attestation::{Attestation, AttestedData};

    use super::*;

    #[test]
    fn service_info_json() {
        let service_info = ServiceInfo {
            proxy_account: dev::alice().public_key().0.into(),
            network_name: "polkadot".to_string(),
            node_endpoint: "wss://polkadot.api.onfinality.io/public-ws".to_string(),
            attestation_bundle: AttestationBundle {
                attested_data: AttestedData {
                    genesis_hash: random::<[u8; 32]>().into(),
                    signing_key: ed25519::Pair::generate().0.public(),
                },
                attestation: Attestation::Mock
            }
        };

        let json = serde_json::to_string(&service_info).unwrap();
        println!("{}", json);

        assert_eq!(
            serde_json::from_str::<Value>(&json).unwrap(),
            json!({
                "proxy_account": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
                "network_name": "polkadot",
                "node_endpoint": "wss://polkadot.api.onfinality.io/public-ws",
                "attestation_bundle": hex::encode(&service_info.attestation_bundle.encode())
            })
        );

        let deserialized_service_info: ServiceInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized_service_info, service_info);
    }
}
