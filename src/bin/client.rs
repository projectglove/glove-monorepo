use std::process::{ExitCode, Termination};

use anyhow::{bail, Context, Result};
use bigdecimal::{BigDecimal, ToPrimitive};
use clap::{Parser, Subcommand};
use DispatchError::Module;
use reqwest::{Client, StatusCode, Url};
use strum::Display;
use subxt::error::DispatchError;
use subxt::Error::Runtime;
use subxt_signer::sr25519::Keypair;

use core::{account_to_address, is_glove_member};
use core::metadata::runtime_types::pallet_proxy::pallet::Error::Duplicate;
use core::metadata::runtime_types::pallet_proxy::pallet::Error::NotFound;
use core::metadata::runtime_types::polkadot_runtime::{ProxyType, RuntimeError};
use core::ServiceInfo;
use core::SubstrateNetwork;
use RuntimeError::Proxy;

use crate::core::{RemoveVoteRequest, VoteRequest};

mod core;

#[tokio::main]
async fn main() -> Result<SuccessOutput> {
    let args = Args::parse();

    let http_client = Client::builder().build()?;

    let service_info = http_client
        .get(url_with_path(&args.glove_url, "info"))
        .send().await?
        .error_for_status()?
        .json::<ServiceInfo>().await?;

    let network = SubstrateNetwork::connect(service_info.network_url.clone(), args.secret_phrase).await?;

    match args.command {
        Command::JoinGlove =>
            join_glove(&service_info, &network).await,
        Command::Vote { poll_index, aye, balance } =>
            vote(&args.glove_url, &http_client, &network, poll_index, aye, balance).await,
        Command::RemoveVote { poll_index } =>
            remove_vote(&args.glove_url, &http_client, &network, poll_index).await,
        Command::LeaveGlove => leave_glove(&service_info, &network).await
    }
}

async fn join_glove(service_info: &ServiceInfo, network: &SubstrateNetwork) -> Result<SuccessOutput> {
    if is_glove_member(network, network.account(), service_info.proxy_account.clone()).await? {
        return Ok(SuccessOutput::AlreadyGloveMember);
    }
    let add_proxy_call = core::metadata::tx()
        .proxy()
        .add_proxy(account_to_address(service_info.proxy_account.clone()), ProxyType::Governance, 0)
        .unvalidated();
    match network.call_extrinsic(&add_proxy_call).await {
        Ok(_) => Ok(SuccessOutput::JoinedGlove),
        Err(Runtime(Module(module_error))) => {
            match module_error.as_root_error::<RuntimeError>() {
                // Unlikely, but just in case
                Ok(Proxy(Duplicate)) => Ok(SuccessOutput::AlreadyGloveMember),
                _ => Err(Runtime(Module(module_error)).into())
            }
        },
        Err(e) => Err(e.into())
    }
}

async fn vote(
    glove_url: &Url,
    http_client: &Client,
    network: &SubstrateNetwork,
    poll_index: u32,
    aye: bool,
    balance_major_units: BigDecimal
) -> Result<SuccessOutput> {
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
        Ok(SuccessOutput::Voted { nonce: vote_request.nonce })
    } else {
        bail!(response.text().await?)
    }
}

async fn remove_vote(
    glove_url: &Url,
    http_client: &Client,
    network: &SubstrateNetwork,
    poll_index: u32
) -> Result<SuccessOutput> {
    let remove_vote_request = RemoveVoteRequest {
        account: network.account(),
        poll_index
    };
    let response = http_client
        .post(url_with_path(glove_url, "remove-vote"))
        .json(&remove_vote_request)
        .send().await
        .context("Unable to send remove vote request")?;
    if response.status() == StatusCode::OK {
        Ok(SuccessOutput::VoteRemoved)
    } else {
        bail!(response.text().await?)
    }
}

async fn leave_glove(service_info: &ServiceInfo, network: &SubstrateNetwork) -> Result<SuccessOutput> {
    if !is_glove_member(network, network.account(), service_info.proxy_account.clone()).await? {
        return Ok(SuccessOutput::NotGloveMember);
    }
    let add_proxy_call = core::metadata::tx()
        .proxy()
        .remove_proxy(account_to_address(service_info.proxy_account.clone()), ProxyType::Governance, 0)
        .unvalidated();
    match network.call_extrinsic(&add_proxy_call).await {
        Ok(_) => Ok(SuccessOutput::LeftGlove),
        Err(Runtime(Module(module_error))) => {
            match module_error.as_root_error::<RuntimeError>() {
                // Unlikely, but just in case
                Ok(Proxy(NotFound)) => Ok(SuccessOutput::NotGloveMember),
                _ => Err(Runtime(Module(module_error)).into())
            }
        },
        Err(e) => Err(e.into())
    }
}

fn url_with_path(url: &Url, path: &str) -> Url {
    let mut with_path = url.clone();
    with_path.set_path(path);
    with_path
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
    /// Add Glove as a goverance proxy to the account, if it isn't already.
    JoinGlove,

    /// Submit vote for inclusion in Glove mixing. The mixing process is not necessarily immediate.
    /// Voting on the same poll twice will replace the previous vote.
    Vote {
        #[arg(long)]
        poll_index: u32,
        /// Specify this to vote "aye", ommit to vote "nay"
        #[arg(long)]
        aye: bool,
        /// The amount of tokens to lock for the vote (as a decimal in the major token unit)
        #[arg(long)]
        balance: BigDecimal
    },

    /// Remove a previously submitted vote.
    RemoveVote {
        #[arg(long)]
        poll_index: u32
    },

    // TODO Also remove any active votes, which requires a remove-all-votes request?
    /// Remove the account from the Glove proxy.
    LeaveGlove
}

#[derive(Display, Debug)]
enum SuccessOutput {
    #[strum(to_string = "Account has joined Glove proxy")]
    JoinedGlove,
    #[strum(to_string = "Account already a member of Glove proxy")]
    AlreadyGloveMember,
    #[strum(to_string = "Vote successfully submitted ({nonce})")]
    Voted { nonce: u128 },
    #[strum(to_string = "Vote successfully removed")]
    VoteRemoved,
    #[strum(to_string = "Account has left Glove proxy")]
    LeftGlove,
    #[strum(to_string = "Account was not a Glove proxy member")]
    NotGloveMember,
}

impl Termination for SuccessOutput {
    fn report(self) -> ExitCode {
        println!("{}", self);
        ExitCode::SUCCESS
    }
}
