use std::process::{ExitCode, Termination};

use anyhow::{bail, Context, Result};
use bigdecimal::{BigDecimal, RoundingMode, ToPrimitive};
use clap::{Parser, Subcommand};
use DispatchError::Module;
use reqwest::{Client, StatusCode, Url};
use sp_core::crypto::AccountId32;
use sp_core::Encode;
use sp_runtime::MultiSignature;
use strum::Display;
use subxt::error::DispatchError;
use subxt::Error::Runtime;
use subxt_signer::sr25519::Keypair;

use client::{Error, try_verify_glove_result};
use client_interface::{account_to_subxt_multi_address, is_glove_member};
use client_interface::metadata::runtime_types::pallet_proxy::pallet::Error::Duplicate;
use client_interface::metadata::runtime_types::pallet_proxy::pallet::Error::NotFound;
use client_interface::metadata::runtime_types::polkadot_runtime::{ProxyType, RuntimeError};
use client_interface::RemoveVoteRequest;
use client_interface::ServiceInfo;
use client_interface::SubstrateNetwork;
use common::{attestation, Conviction, VoteDirection, SignedVoteRequest, VoteRequest};
use common::attestation::{Attestation, EnclaveInfo};
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

    let network = SubstrateNetwork::connect(
        service_info.node_endpoint.clone(),
        args.secret_phrase
    ).await?;

    match args.command {
        Command::JoinGlove => {
            join_glove(&service_info, &network).await
        }
        Command::Vote(vote_cmd) => {
            vote(&args.glove_url, &http_client, &network, vote_cmd, &service_info.proxy_account).await
        },
        Command::RemoveVote { poll_index } => {
            remove_vote(&args.glove_url, &http_client, &network, poll_index).await
        },
        Command::LeaveGlove => {
            leave_glove(&service_info, &network).await
        }
        Command::Info => {
            info(&service_info)
        }
    }
}

async fn join_glove(service_info: &ServiceInfo, network: &SubstrateNetwork) -> Result<SuccessOutput> {
    if is_glove_member(network, network.account(), service_info.proxy_account.clone()).await? {
        return Ok(SuccessOutput::AlreadyGloveMember);
    }
    let add_proxy_call = client_interface::metadata::tx()
        .proxy()
        .add_proxy(account_to_subxt_multi_address(service_info.proxy_account.clone()), ProxyType::Governance, 0)
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
    let request = VoteRequest::new(
        network.account(),
        network.api.genesis_hash(),
        vote_cmd.poll_index,
        vote_cmd.aye,
        balance,
        parse_conviction(vote_cmd.conviction)?
    );
    let nonce = request.nonce;

    let signature = MultiSignature::Sr25519(network.account_key.sign(&request.encode()).0.into());
    let signed_request = SignedVoteRequest { request, signature };
    if !signed_request.verify() {
        bail!("Something has gone wrong with the signature")
    }
    let response = http_client
        .post(url_with_path(glove_url, "vote"))
        .json(&signed_request)
        .send().await
        .context("Unable to send vote request")?;

    if response.status() != StatusCode::OK {
        bail!(response.text().await?)
    }
    if vote_cmd.await_glove_confirmation {
        listen_for_glove_votes(network, &vote_cmd, nonce, proxy_account).await?;
    }
    return Ok(SuccessOutput::Voted { nonce });
}

// TODO Stop waiting when the poll is closed.
async fn listen_for_glove_votes(
    network: &SubstrateNetwork,
    vote_cmd: &VoteCmd,
    nonce: u32,
    proxy_account: &AccountId32
) -> Result<()> {
    network.subscribe_successful_extrinsics(|extrinsic, _| async move {
        let verification_result = try_verify_glove_result(
            &network,
            &extrinsic,
            proxy_account,
            vote_cmd.poll_index,
        ).await;
        let verified_glove_proof = match verification_result {
            Ok(None) => return Ok(()), // Not what we're looking for
            Ok(Some(verified_glove_proof)) => verified_glove_proof,
            Err(Error::Subxt(subxt_error)) => return Err(subxt_error.into()),
            Err(error) => {
                eprintln!("Error verifying Glove proof: {}", error);
                return Ok(());
            }
        };
        if let Some(balance) = verified_glove_proof.get_vote_balance(&network.account(), nonce) {
            let balance = BigDecimal::new(
                balance.into(),
                network.token_decimals as i64
            ).with_scale_round(3, RoundingMode::HalfEven);
            match verified_glove_proof.result.direction {
                VoteDirection::Aye => println!("Glove vote aye with balance {}", balance),
                VoteDirection::Nay => println!("Glove vote nay with balance {}", balance),
                VoteDirection::Abstain => println!("Glove abstained with balance {}", balance),
            }
            if let Some(_) = &verified_glove_proof.enclave_info {
                // TODO Check measurement
            } else {
                eprintln!("WARNING: Secure enclave wasn't used");
            }
        } else {
            eprintln!("WARNING: Received Glove proof for poll, but vote was not included");
        }
        Ok(())
    }).await?;
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
        .remove_proxy(account_to_subxt_multi_address(service_info.proxy_account.clone()), ProxyType::Governance, 0)
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

fn info(service_info: &ServiceInfo) -> Result<SuccessOutput> {
    let ab = &service_info.attestation_bundle;
    let enclave_info = match ab.verify() {
        Ok(EnclaveInfo::Nitro(enclave_info)) => {
            &format!("AWS Nitro Enclave ({})", hex::encode(enclave_info.image_measurement))
        },
        Err(attestation::Error::InsecureMode) => match ab.attestation {
            Attestation::Nitro(_) => "Debug AWS Nitro Enclave (INSECURE)",
            Attestation::Mock => "Mock (INSECURE)"
        },
        Err(attestation_error) => &format!("Error verifying attestation: {}", attestation_error)
    };

    println!("Glove proxy account: {}", service_info.proxy_account);
    println!("Enclave:             {}", enclave_info);
    println!("Substrate Network:   {}", service_info.network_name);
    println!("Genesis hash:        {}", hex::encode(ab.attested_data.genesis_hash));

    Ok(SuccessOutput::None)
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
    LeaveGlove,

    /// Print information about the Glove service.
    Info

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
    /// The vote conviction multiplier
    #[arg(long, default_value_t = 0)]
    conviction: u8,
    /// Wait for the vote to be included in the Glove mixing process and confirmation received.
    #[arg(long)]
    await_glove_confirmation: bool
}

fn parse_conviction(value: u8) -> Result<Conviction> {
    match value {
        0 => Ok(Conviction::None),
        1 => Ok(Conviction::Locked1x),
        2 => Ok(Conviction::Locked2x),
        3 => Ok(Conviction::Locked3x),
        4 => Ok(Conviction::Locked4x),
        5 => Ok(Conviction::Locked5x),
        6 => Ok(Conviction::Locked6x),
        _ => bail!("Conviction must be between 0 and 6 inclusive")
    }
}

#[derive(Display, Debug, PartialEq)]
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
    None
}

impl Termination for SuccessOutput {
    fn report(self) -> ExitCode {
        if self != SuccessOutput::None {
            println!("{}", self);
        }
        ExitCode::SUCCESS
    }
}
