use std::process::{ExitCode, Termination};

use anyhow::{bail, Context, Result};
use bigdecimal::{BigDecimal, RoundingMode, ToPrimitive};
use clap::{Parser, Subcommand};
use DispatchError::Module;
use reqwest::{Client, StatusCode, Url};
use sp_core::crypto::AccountId32;
use sp_core::Encode;
use strum::Display;
use subxt::error::DispatchError;
use subxt::Error::Runtime;
use subxt::utils::MultiSignature;
use subxt_signer::sr25519::Keypair;

use client::{Error, try_verify_glove_result};
use client_interface::{account_to_address, is_glove_member, SignedVoteRequest};
use client_interface::metadata::runtime_types::pallet_proxy::pallet::Error::Duplicate;
use client_interface::metadata::runtime_types::pallet_proxy::pallet::Error::NotFound;
use client_interface::metadata::runtime_types::polkadot_runtime::{ProxyType, RuntimeError};
use client_interface::RemoveVoteRequest;
use client_interface::ServiceInfo;
use client_interface::SubstrateNetwork;
use common::{GloveVote, VoteRequest};
use RuntimeError::Proxy;

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
        Command::Vote(vote_cmd) =>
            vote(&args.glove_url, &http_client, &network, vote_cmd, &service_info.proxy_account).await,
        Command::RemoveVote { poll_index } =>
            remove_vote(&args.glove_url, &http_client, &network, poll_index).await,
        Command::LeaveGlove => leave_glove(&service_info, &network).await
    }
}

async fn join_glove(service_info: &ServiceInfo, network: &SubstrateNetwork) -> Result<SuccessOutput> {
    if is_glove_member(network, network.account(), service_info.proxy_account.clone()).await? {
        return Ok(SuccessOutput::AlreadyGloveMember);
    }
    let add_proxy_call = client_interface::metadata::tx()
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
    vote_cmd: VoteCmd,
    proxy_account: &AccountId32
) -> Result<SuccessOutput> {
    let balance = (&vote_cmd.balance * 10u128.pow(network.token_decimals as u32))
        .to_u128()
        .context("Vote balance is too big")?;
    let request = VoteRequest::new(network.account(), vote_cmd.poll_index, vote_cmd.aye, balance);
    let encoded_request = request.encode();
    let signature = MultiSignature::Sr25519(network.keypair.sign(encoded_request.as_slice()).0);
    let response = http_client
        .post(url_with_path(glove_url, "vote"))
        .json(&SignedVoteRequest { request: encoded_request, signature: signature.encode() })
        .send().await
        .context("Unable to send vote request")?;

    if response.status() != StatusCode::OK {
        bail!(response.text().await?)
    }
    if vote_cmd.await_glove_confirmation {
        listen_for_glove_votes(network, &vote_cmd, request.nonce, proxy_account).await?;
    }
    return Ok(SuccessOutput::Voted { nonce: request.nonce });
}

// TODO Stop waiting when the poll is closed.
async fn listen_for_glove_votes(
    network: &SubstrateNetwork,
    vote_cmd: &VoteCmd,
    nonce: u32,
    proxy_account: &AccountId32
) -> Result<()> {
    let mut blocks_sub = network.api.blocks().subscribe_finalized().await?;

    while let Some(block) = blocks_sub.next().await {
        for extrinsic in block?.extrinsics().await?.iter() {
            let verification_result = try_verify_glove_result(
                &network.api,
                &extrinsic?,
                proxy_account,
                vote_cmd.poll_index,
            ).await;
            let verified_glove_proof = match verification_result {
                Ok(None) => continue, // Not what we're looking for
                Ok(Some(verified_glove_proof)) => verified_glove_proof,
                Err(Error::Subxt(subxt_error)) => return Err(subxt_error.into()),
                Err(error) => {
                    eprintln!("Error verifying Glove proof: {}", error);
                    continue;
                }
            };
            if let Some(balance) = verified_glove_proof.get_vote_balance(&network.account(), nonce) {
                let balance = BigDecimal::new(
                    balance.into(),
                    network.token_decimals as i64
                ).with_scale_round(3, RoundingMode::HalfEven);
                match verified_glove_proof.result.vote {
                    GloveVote::Aye => println!("Glove vote aye with balance {}", balance),
                    GloveVote::Nay => println!("Glove vote nay with balance {}", balance),
                    GloveVote::Abstain => println!("Glove abstained with balance {}", balance),
                }
                if let Some(_) = &verified_glove_proof.enclave_info {
                    // TODO Check measurement
                } else {
                    eprintln!("WARNING: Secure enclave wasn't used");
                }
            } else {
                eprintln!("WARNING: Received Glove proof for poll, but vote was not included");
            }
        }
    }

    Ok(())
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
    let add_proxy_call = client_interface::metadata::tx()
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
    /// The secret phrase for the Glove client account. This is a secret seed with optional
    /// derivation paths. An Sr25519 key will be derived from this for signing.
    ///
    /// See https://wiki.polkadot.network/docs/learn-account-advanced#derivation-paths for more
    /// details.
    #[arg(long, value_parser = client_interface::parse_secret_phrase)]
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
    Vote(VoteCmd),

    /// Remove a previously submitted vote.
    RemoveVote {
        #[arg(long)]
        poll_index: u32
    },

    // TODO Also remove any active votes, which requires a remove-all-votes request?
    /// Remove the account from the Glove proxy.
    LeaveGlove

    // TODO Command to resume waiting for Glove vote, based on stored nonce. It will first check
    //  storage to see if the vote has already been mixed, and then continue listening. If the poll
    //  is closed then it should verify the vote was mixed by Glove and then exit.
}

#[derive(Debug, Parser)]
struct VoteCmd {
    #[arg(long)]
    poll_index: u32,
    /// Specify this to vote "aye", ommit to vote "nay"
    #[arg(long)]
    aye: bool,
    /// The amount of tokens to lock for the vote (as a decimal in the major token unit)
    #[arg(long)]
    balance: BigDecimal,
    /// Wait for the vote to be included in the Glove mixing process and confirmation received.
    #[arg(long)]
    await_glove_confirmation: bool
}

#[derive(Display, Debug)]
enum SuccessOutput {
    #[strum(to_string = "Account has joined Glove proxy")]
    JoinedGlove,
    #[strum(to_string = "Account already a member of Glove proxy")]
    AlreadyGloveMember,
    #[strum(to_string = "Vote successfully submitted ({nonce})")]
    Voted { nonce: u32 },
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
