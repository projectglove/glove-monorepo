use std::ffi::OsString;
use std::process::{ExitCode, Termination};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use bigdecimal::{BigDecimal, ToPrimitive};
use clap::{Parser, Subcommand};
use reqwest::{Client, StatusCode, Url};
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::policies::ExponentialBackoff;
use reqwest_retry::{Jitter, RetryTransientMiddleware};
use sp_core::bytes::from_hex;
use sp_core::crypto::AccountId32;
use sp_core::{Encode, H256};
use sp_runtime::MultiSignature;
use strum::Display;
use subxt::error::DispatchError;
use subxt::Error::Runtime;
use subxt_core::utils::to_hex;
use subxt_signer::sr25519::Keypair;
use DispatchError::Module;

use client_interface::metadata::runtime_types::pallet_proxy::pallet::Error::Duplicate;
use client_interface::metadata::runtime_types::pallet_proxy::pallet::Error::NotFound;
use client_interface::metadata::runtime_types::polkadot_runtime::{ProxyType, RuntimeError};
use client_interface::subscan::{PollStatus, Subscan};
use client_interface::RemoveVoteRequest;
use client_interface::ServiceInfo;
use client_interface::{
    account_to_subxt_multi_address, is_glove_member, CallableSubstrateNetwork,
    SignedRemoveVoteRequest,
};
use common::attestation::{Attestation, EnclaveInfo};
use common::{attestation, Conviction, SignedVoteRequest, VoteRequest};
use verify::try_verify_glove_result;
use Command::{Info, JoinGlove, LeaveGlove, RemoveVote, VerifyVote, Vote};
use RuntimeError::Proxy;

pub mod verify;

pub async fn run<I, T>(input: I) -> Result<SuccessOutput>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let args = Args::parse_from(input);

    let retry_policy = ExponentialBackoff::builder()
        .retry_bounds(Duration::from_secs(1), Duration::from_secs(60))
        .jitter(Jitter::Bounded)
        .base(2)
        .build_with_total_retry_duration(Duration::from_secs(2 * 60));
    let http_client = ClientBuilder::new(Client::builder().build()?)
        .with(RetryTransientMiddleware::new_with_policy(retry_policy))
        .build();

    let service_info = http_client
        .get(url_with_path(&args.glove_url, "info"))
        .send()
        .await?
        .error_for_status()?
        .json::<ServiceInfo>()
        .await?;

    match args.command {
        JoinGlove(cmd) => join_glove(service_info, cmd).await,
        Vote(cmd) => vote(service_info, cmd, args.glove_url, http_client).await,
        RemoveVote(cmd) => remove_vote(cmd, args.glove_url, http_client).await,
        VerifyVote(cmd) => verify_vote(service_info, cmd).await,
        LeaveGlove(cmd) => leave_glove(service_info, cmd).await,
        Info => info(service_info),
    }
}

async fn join_glove(service_info: ServiceInfo, cmd: JoinCmd) -> Result<SuccessOutput> {
    let network = connect_to_network(cmd.secret_phrase_args, cmd.node_endpoint_args).await?;
    if is_glove_member(
        &network,
        network.account(),
        service_info.proxy_account.clone(),
    )
    .await?
    {
        return Ok(SuccessOutput::AlreadyGloveMember);
    }
    let add_proxy_call = client_interface::metadata::tx()
        .proxy()
        .add_proxy(
            account_to_subxt_multi_address(service_info.proxy_account.clone()),
            ProxyType::Governance,
            0,
        )
        .unvalidated();
    match network.call_extrinsic(&add_proxy_call).await {
        Ok(_) => Ok(SuccessOutput::JoinedGlove),
        Err(Runtime(Module(module_error))) => {
            match module_error.as_root_error::<RuntimeError>() {
                // Unlikely, but just in case
                Ok(Proxy(Duplicate)) => Ok(SuccessOutput::AlreadyGloveMember),
                _ => Err(Runtime(Module(module_error)).into()),
            }
        }
        Err(e) => Err(e.into()),
    }
}

async fn vote(
    service_info: ServiceInfo,
    cmd: VoteCmd,
    glove_url: Url,
    http_client: ClientWithMiddleware,
) -> Result<SuccessOutput> {
    let subscan = Subscan::new(
        service_info.network_name.clone(),
        cmd.subscan_api_key.clone(),
    );
    let token = subscan.get_token().await?;
    let keypair = cmd.secret_phrase_args.secret_phrase.clone();
    let balance = (&cmd.balance * 10u128.pow(token.decimals as u32))
        .to_u128()
        .context("Vote balance is too big")?;
    let request = VoteRequest::new(
        keypair.public_key().0.into(),
        genesis_hash(&subscan).await?,
        cmd.poll_index,
        cmd.aye,
        balance,
        cmd.parse_conviction()?,
    );
    let nonce = request.nonce;

    let signature = MultiSignature::Sr25519(keypair.sign(&request.encode()).0.into());
    let signed_request = SignedVoteRequest { request, signature };
    if !signed_request.verify() {
        bail!("Something has gone wrong with the signature")
    }
    let response = http_client
        .post(url_with_path(&glove_url, "vote"))
        .json(&signed_request)
        .send()
        .await
        .context("Unable to send vote request")?;
    if response.status() != StatusCode::OK {
        bail!(response.text().await?)
    }
    Ok(SuccessOutput::Voted { nonce })
}

async fn remove_vote(
    cmd: RemoveVoteCmd,
    glove_url: Url,
    http_client: ClientWithMiddleware,
) -> Result<SuccessOutput> {
    let keypair = cmd.secret_phrase_args.secret_phrase;
    let request = RemoveVoteRequest {
        account: keypair.public_key().0.into(),
        poll_index: cmd.poll_index,
    };
    let signature = MultiSignature::Sr25519(keypair.sign(&request.encode()).0.into());
    let signed_request = SignedRemoveVoteRequest { request, signature };
    if !signed_request.verify() {
        bail!("Something has gone wrong with the signature")
    }
    let response = http_client
        .post(url_with_path(&glove_url, "remove-vote"))
        .json(&signed_request)
        .send()
        .await
        .context("Unable to send remove vote request")?;
    if response.status() == StatusCode::OK {
        Ok(SuccessOutput::VoteRemoved)
    } else {
        bail!(response.text().await?)
    }
}

async fn verify_vote(service_info: ServiceInfo, cmd: VerifyVoteCmd) -> Result<SuccessOutput> {
    let subscan = Subscan::new(service_info.network_name.clone(), cmd.subscan_api_key);
    let active_polls = subscan.get_polls(PollStatus::Active).await?;
    let votes = subscan
        .get_votes(cmd.poll_index, Some(cmd.account.clone()))
        .await?;
    let Some(vote) = votes.first() else {
        if active_polls
            .iter()
            .any(|poll| poll.referendum_index == cmd.poll_index)
        {
            bail!("Glove proxy has not yet voted")
        } else {
            bail!("Poll is no longer active and Glove proxy did not vote")
        }
    };
    let verification_result = try_verify_glove_result(
        &subscan,
        vote.extrinsic_index,
        service_info.proxy_account,
        cmd.poll_index,
    )
    .await;
    let verified_glove_proof = match verification_result {
        Ok(Some(verified_glove_proof)) => verified_glove_proof,
        Ok(None) => bail!("Vote was not cast by Glove proxy"),
        Err(error) => bail!("Glove proof failed verification: {}", error),
    };
    let assigned_balance = verified_glove_proof
        .get_assigned_balance(&cmd.account)
        .ok_or_else(|| anyhow!("Account is not in Glove proof"))?;
    let image_measurement = match verified_glove_proof.enclave_info {
        Some(EnclaveInfo::Nitro(nitro_enclave_info)) => nitro_enclave_info.image_measurement,
        None => bail!("INSECURE enclave was used to mix votes, so result cannot be trusted"),
    };

    if let Some(nonce) = cmd.nonce {
        if nonce != assigned_balance.nonce {
            bail!(
                "Nonce in Glove proof ({}) does not match expected value. \
            Glove proxy has used an older vote request.",
                assigned_balance.nonce
            )
        }
    } else {
        eprintln!(
            "Nonce was not provided so cannot check if most recent vote request was used by \
        Glove proxy"
        );
    }

    let token = subscan.get_token().await?;

    if !cmd.enclave_measurement.is_empty() {
        let enclave_match = cmd
            .enclave_measurement
            .iter()
            .any(|str| from_hex(str).ok() == Some(image_measurement.clone()));
        if !enclave_match {
            bail!(
                "Unknown enclave encountered in Glove proof ({})",
                to_hex(&image_measurement)
            )
        }
        println!(
            "Vote mixed by VERIFIED Glove enclave: {:?} using {} with conviction {:?}",
            verified_glove_proof.result.direction,
            token.display_amount(assigned_balance.balance),
            assigned_balance.conviction
        );
    } else {
        println!(
            "Vote mixed by POSSIBLE Glove enclave: {:?} using {} with conviction {:?}",
            verified_glove_proof.result.direction,
            token.display_amount(assigned_balance.balance),
            assigned_balance.conviction
        );
        println!();
        println!("To verify this is a Glove enclave, first audit the code:");
        println!(
            "git clone --depth 1 --branch v{} {}",
            verified_glove_proof.attested_data.version,
            env!("CARGO_PKG_REPOSITORY")
        );
        println!();
        println!(
            "And then check 'PCR0' output is '{}' by running:",
            to_hex(&image_measurement)
        );
        println!("./build.sh");
    }

    Ok(SuccessOutput::None)
}

// TODO Also remove any active votes, which requires a remove-all-votes request?
async fn leave_glove(service_info: ServiceInfo, cmd: LeaveCmd) -> Result<SuccessOutput> {
    let network = connect_to_network(cmd.secret_phrase_args, cmd.node_endpoint_args).await?;
    if !is_glove_member(
        &network,
        network.account(),
        service_info.proxy_account.clone(),
    )
    .await?
    {
        return Ok(SuccessOutput::NotGloveMember);
    }
    let add_proxy_call = client_interface::metadata::tx()
        .proxy()
        .remove_proxy(
            account_to_subxt_multi_address(service_info.proxy_account.clone()),
            ProxyType::Governance,
            0,
        )
        .unvalidated();
    match network.call_extrinsic(&add_proxy_call).await {
        Ok(_) => Ok(SuccessOutput::LeftGlove),
        Err(Runtime(Module(module_error))) => {
            match module_error.as_root_error::<RuntimeError>() {
                // Unlikely, but just in case
                Ok(Proxy(NotFound)) => Ok(SuccessOutput::NotGloveMember),
                _ => Err(Runtime(Module(module_error)).into()),
            }
        }
        Err(e) => Err(e.into()),
    }
}

fn info(service_info: ServiceInfo) -> Result<SuccessOutput> {
    let ab = &service_info.attestation_bundle;
    let enclave_info = match ab.verify() {
        Ok(EnclaveInfo::Nitro(enclave_info)) => &format!(
            "AWS Nitro Enclave ({})",
            to_hex(enclave_info.image_measurement)
        ),
        Err(attestation::Error::InsecureMode) => match ab.attestation {
            Attestation::Nitro(_) => "Debug AWS Nitro Enclave (INSECURE)",
            Attestation::Mock => "Mock (INSECURE)",
        },
        Err(attestation_error) => &format!("Error verifying attestation: {}", attestation_error),
    };

    println!("Glove proxy account: {}", service_info.proxy_account);
    println!("Enclave:             {}", enclave_info);
    println!("Substrate Network:   {}", service_info.network_name);
    println!(
        "Genesis hash:        {}",
        to_hex(ab.attested_data.genesis_hash)
    );

    Ok(SuccessOutput::None)
}

pub fn url_with_path(url: &Url, path: &str) -> Url {
    let mut with_path = url.clone();
    with_path.set_path(path);
    with_path
}

pub async fn genesis_hash(subscan: &Subscan) -> Result<H256> {
    let genesis_hash = subscan.get_block(0).await?.expect("Genesis block").hash;
    if genesis_hash.len() != H256::len_bytes() {
        bail!("Genesis hash is not 32 bytes")
    }
    Ok(H256::from_slice(&genesis_hash))
}

#[derive(Debug, Parser)]
#[command(version, about = "Glove CLI client")]
struct Args {
    /// The URL of the Glove service
    #[arg(long, short, verbatim_doc_comment)]
    glove_url: Url,

    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, clap::Args)]
struct SecretPhraseArgs {
    /// The secret phrase for the Glove client account. This is a secret seed with optional
    /// derivation paths. An Sr25519 key will be derived from this for signing.
    ///
    /// See https://wiki.polkadot.network/docs/learn-account-advanced#derivation-paths for more
    /// details.
    #[arg(long, verbatim_doc_comment, value_parser = client_interface::parse_secret_phrase)]
    secret_phrase: Keypair,
}

#[derive(Debug, Clone, clap::Args)]
struct NodeEndpointArgs {
    /// URL to a Substrate node endpoint for interacting with the network.
    ///
    /// See https://wiki.polkadot.network/docs/maintain-endpoints for more information.
    #[arg(long, verbatim_doc_comment)]
    node_endpoint: String,
}

async fn connect_to_network(
    secret_phrase_args: SecretPhraseArgs,
    node_endpoint_args: NodeEndpointArgs,
) -> Result<CallableSubstrateNetwork> {
    CallableSubstrateNetwork::connect(
        node_endpoint_args.node_endpoint,
        secret_phrase_args.secret_phrase,
    )
    .await
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Add Glove as a goverance proxy to the account, if it isn't already.
    #[command(verbatim_doc_comment)]
    JoinGlove(JoinCmd),
    /// Submit vote for inclusion in Glove mixing. The mixing process is not necessarily immediate.
    /// Voting on the same poll twice will replace the previous vote.
    #[command(verbatim_doc_comment)]
    Vote(VoteCmd),
    /// Remove a previously submitted vote.
    #[command(verbatim_doc_comment)]
    RemoveVote(RemoveVoteCmd),
    /// Verify on-chain vote was mixed by a genuine Glove enclave
    #[command(verbatim_doc_comment)]
    VerifyVote(VerifyVoteCmd),
    /// Remove the account from the Glove proxy.
    #[command(verbatim_doc_comment)]
    LeaveGlove(LeaveCmd),
    /// Print information about the Glove service.
    #[command(verbatim_doc_comment)]
    Info,
}

#[derive(Debug, Parser)]
struct JoinCmd {
    #[command(flatten)]
    secret_phrase_args: SecretPhraseArgs,
    #[command(flatten)]
    node_endpoint_args: NodeEndpointArgs,
}

#[derive(Debug, Parser)]
struct VoteCmd {
    #[command(flatten)]
    secret_phrase_args: SecretPhraseArgs,
    #[arg(long, short)]
    poll_index: u32,
    /// Specify this to vote "aye", ommit to vote "nay"
    #[arg(long, verbatim_doc_comment)]
    aye: bool,
    /// The amount of tokens to lock for the vote (as a decimal in the major token unit)
    #[arg(long, short, verbatim_doc_comment)]
    balance: BigDecimal,
    /// The vote conviction multiplier
    #[arg(long, short, verbatim_doc_comment, default_value_t = 0)]
    conviction: u8,
    /// Optional, API key to use with Subscan
    #[arg(long, short, verbatim_doc_comment)]
    subscan_api_key: Option<String>,
}

impl VoteCmd {
    fn parse_conviction(&self) -> Result<Conviction> {
        match self.conviction {
            0 => Ok(Conviction::None),
            1 => Ok(Conviction::Locked1x),
            2 => Ok(Conviction::Locked2x),
            3 => Ok(Conviction::Locked3x),
            4 => Ok(Conviction::Locked4x),
            5 => Ok(Conviction::Locked5x),
            6 => Ok(Conviction::Locked6x),
            _ => bail!("Conviction must be between 0 and 6 inclusive"),
        }
    }
}

#[derive(Debug, Parser)]
struct RemoveVoteCmd {
    #[command(flatten)]
    secret_phrase_args: SecretPhraseArgs,
    #[arg(long, short)]
    poll_index: u32,
}

#[derive(Debug, Parser)]
struct VerifyVoteCmd {
    /// The account on whose behalf the Glove proxy mixed the vote
    #[arg(long, short, verbatim_doc_comment)]
    account: AccountId32,
    /// The index of the poll/referendum
    #[arg(long, short, verbatim_doc_comment)]
    poll_index: u32,
    /// Whitelisted Glove enclave measurements. Each measurement represents a different enclave
    /// version. The on-chain Glove proof associated with the vote will be checked against this
    /// list. It is assumed the versions of the enclave these measurement represent have been
    /// audited.
    ///
    /// If no enclave measurement is specified, the measurement of the Glove proof will displayed,
    /// along with enclave code location, for auditing.
    #[arg(long, short, verbatim_doc_comment)]
    enclave_measurement: Vec<String>,
    /// Optional, the nonce value used in the most recent vote request.
    #[arg(long, short, verbatim_doc_comment)]
    nonce: Option<u32>,
    /// Optional, API key to use with Subscan
    #[arg(long, short, verbatim_doc_comment)]
    subscan_api_key: Option<String>,
}

#[derive(Debug, Parser)]
struct LeaveCmd {
    #[command(flatten)]
    secret_phrase_args: SecretPhraseArgs,
    #[command(flatten)]
    node_endpoint_args: NodeEndpointArgs,
}

#[derive(Display, Debug, PartialEq)]
pub enum SuccessOutput {
    #[strum(to_string = "Account has joined Glove proxy")]
    JoinedGlove,
    #[strum(to_string = "Account already a member of Glove proxy")]
    AlreadyGloveMember,
    #[strum(to_string = "Vote successfully submitted ({nonce})")]
    Voted {
        nonce: u32,
    },
    #[strum(to_string = "Vote successfully removed")]
    VoteRemoved,
    #[strum(to_string = "Account has left Glove proxy")]
    LeftGlove,
    #[strum(to_string = "Account was not a Glove proxy member")]
    NotGloveMember,
    None,
}

impl Termination for SuccessOutput {
    fn report(self) -> ExitCode {
        if self != SuccessOutput::None {
            println!("{}", self);
        }
        ExitCode::SUCCESS
    }
}
