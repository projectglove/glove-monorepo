use anyhow::{bail, Context, Result};
use bigdecimal::{BigDecimal, ToPrimitive};
use clap::{Parser, Subcommand};
use DispatchError::Module;
use reqwest::{Client, StatusCode, Url};
use subxt::error::DispatchError;
use subxt::Error::Runtime;
use subxt_signer::sr25519::Keypair;

use core::{account_to_address, is_glove_member};
use core::metadata::runtime_types::pallet_proxy::pallet::Error::Duplicate;
use core::metadata::runtime_types::polkadot_runtime::{ProxyType, RuntimeError};
use core::ServiceInfo;
use core::SubstrateNetwork;
use RuntimeError::Proxy;

use crate::core::VoteRequest;

mod core;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let http_client = Client::builder().build()?;

    let service_info = http_client
        .get(url_with_path(&args.glove_url, "info"))
        .send().await?
        .error_for_status()?
        .json::<ServiceInfo>().await?;

    let network = SubstrateNetwork::connect(service_info.network_url.clone(), args.secret_phrase).await?;

    let success_msg = match args.command {
        Command::JoinGlove => join_glove(&service_info, &network).await?,
        Command::Vote { poll_index, aye, balance } =>
            vote(&args.glove_url, &http_client, &network, poll_index, aye, balance).await?
    };
    println!("{}", success_msg);

    Ok(())
}

async fn join_glove(service_info: &ServiceInfo, network: &SubstrateNetwork) -> Result<String, subxt::Error> {
    if is_glove_member(network, network.account(), service_info.proxy_account.clone()).await? {
        return Ok("Account already part of Glove proxy".to_string());
    }
    let add_proxy_call = core::metadata::tx()
        .proxy()
        .add_proxy(account_to_address(service_info.proxy_account.clone()), ProxyType::Governance, 0)
        .unvalidated();
    match network.call_extrinsic(&add_proxy_call).await {
        Ok(_) => Ok("Account added to Glove proxy".to_string()),
        Err(Runtime(Module(module_error))) => {
            match module_error.as_root_error::<RuntimeError>() {
                // Unlikely, but just in case
                Ok(Proxy(Duplicate)) => Ok("Account already part of Glove proxy".to_string()),
                _ => Err(Runtime(Module(module_error)))
            }
        },
        Err(e) => Err(e)
    }
}

async fn vote(
    glove_url: &Url,
    http_client: &Client,
    network: &SubstrateNetwork,
    poll_index: u32,
    aye: bool,
    balance_major_units: BigDecimal
) -> Result<String> {
    let balance = (balance_major_units * 10u128.pow(network.token_decimals as u32))
        .to_u128()
        .context("Vote balance is too big")?;
    let vote_request = VoteRequest::new(network.account(), poll_index, aye, balance);
    let response = http_client
        .post(url_with_path(glove_url, "vote"))
        .json(&vote_request)
        .send().await
        .context("Unable to send vote request")?;
    if response.status() == StatusCode::OK {
        Ok(format!("Vote successfully submitted ({})", vote_request.nonce))
    } else {
        bail!(response.text().await?)
    }
}

fn url_with_path(url: &Url, path: &str) -> Url {
    let mut new_url = url.clone();
    new_url.set_path(path);
    new_url
}

#[derive(Debug, Parser)]
#[command(version, about = "Glove CLI client")]
struct Args {
    /// Secret phrase for the Glove client account
    #[arg(long, value_parser = core::parse_secret_phrase)]
    secret_phrase: Keypair,

    /// The URL of the Glove service
    #[arg(long)]
    glove_url: Url,

    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Add Glove as a goverance proxy to the account. This is a one-time operation.
    JoinGlove,
    // Submit vote
    Vote {
        #[arg(long)]
        poll_index: u32,
        /// Specify this to vote "aye", ommit to vote "nay"
        #[arg(long)]
        aye: bool,
        /// The amount of tokens to lock for the vote (as a decimal in the major token unit)
        #[arg(long)]
        balance: BigDecimal
    }
    // TODO LeaveGlove, which removes the account from the proxy and also remotes any active votes
}

