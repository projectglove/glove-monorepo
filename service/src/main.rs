use std::collections::HashSet;
use std::error::Error;
use std::future::Future;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context};
use axum::extract::{Json, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Router;
use axum::routing::{get, post};
use cfg_if::cfg_if;
use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;
use sp_runtime::AccountId32;
use subxt::Error as SubxtError;
use subxt_signer::sr25519::Keypair;
use tokio::net::TcpListener;
use tokio::spawn;
use tokio::sync::Mutex;
use tokio::time::sleep;
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info, trace};
use tracing::log::warn;
use tracing_subscriber::filter::{EnvFilter, LevelFilter};

use attestation::Error::InsecureMode;
use client_interface::{account, CallableSubstrateNetwork, is_glove_member, ProxyError, ServiceInfo, SignedRemoveVoteRequest, subscan};
use client_interface::account_to_subxt_multi_address;
use client_interface::BatchError;
use client_interface::metadata::runtime_types::frame_system::pallet::Call as SystemCall;
use client_interface::metadata::runtime_types::pallet_conviction_voting::pallet::Call as ConvictionVotingCall;
use client_interface::metadata::runtime_types::pallet_conviction_voting::pallet::Error::{InsufficientFunds, NotOngoing};
use client_interface::metadata::runtime_types::pallet_conviction_voting::vote::AccountVote;
use client_interface::metadata::runtime_types::pallet_conviction_voting::vote::Vote;
use client_interface::metadata::runtime_types::pallet_proxy::pallet::Call as ProxyCall;
use client_interface::metadata::runtime_types::pallet_proxy::pallet::Error::NotProxy;
use client_interface::metadata::runtime_types::polkadot_runtime::RuntimeCall;
use client_interface::metadata::runtime_types::polkadot_runtime::RuntimeError;
use client_interface::metadata::runtime_types::polkadot_runtime::RuntimeError::Proxy;
use common::{AssignedBalance, attestation, BASE_AYE, BASE_NAY, Conviction, GloveResult, SignedGloveResult, SignedVoteRequest, VoteDirection};
use common::attestation::{AttestationBundle, AttestationBundleLocation, GloveProofLite};
use RuntimeError::ConvictionVoting;
use service::{mixing, storage};
use service::dynamodb::DynamodbGloveStorage;
use service::enclave::EnclaveHandle;
use service::storage::{GloveStorage, InMemoryGloveStorage};

#[derive(Parser, Debug)]
#[command(version, about = "Glove proxy service")]
struct Args {
    /// Secret phrase for the Glove proxy account. This is a secret seed with optional derivation
    /// paths. The account will be an Sr25519 key.
    ///
    /// See https://wiki.polkadot.network/docs/learn-account-advanced#derivation-paths for more
    /// details.
    #[arg(long, verbatim_doc_comment, value_parser = client_interface::parse_secret_phrase)]
    proxy_secret_phrase: Keypair,

    /// Address the service will listen on.
    #[arg(long, verbatim_doc_comment)]
    address: String,

    /// URL to a substrate node endpoint. The Glove service will use the API exposed by this to
    /// interact with the network.
    ///
    /// See https://wiki.polkadot.network/docs/maintain-endpoints for more information.
    #[arg(long, verbatim_doc_comment)]
    node_endpoint: String,

    /// The storage to use for the service.
    #[clap(subcommand, verbatim_doc_comment)]
    storage: Storage,

    /// Which mode the Glove enclave should run in.
    #[arg(long, value_enum, verbatim_doc_comment, default_value_t = EnclaveMode::Nitro)]
    enclave_mode: EnclaveMode
}

#[derive(Debug, Subcommand)]
enum Storage {
    /// Store all state in an AWS DynamoDB table.
    ///
    /// The service will need write permissions on the table. This can be achieved by attaching
    /// the relevant IAM role to the EC2 instance running the service.
    #[command(verbatim_doc_comment)]
    Dynamodb {
        /// The name of the DynamoDB table to use. The table must have a sort key, and both the
        /// partition key and sort key must be of strings. They can both have any name.
        #[arg(long, verbatim_doc_comment)]
        table_name: String
    },
    /// Store all state in memory. This is only useful for testing and development purposes. Do not
    /// use in production.
    #[command(verbatim_doc_comment)]
    InMemory
}

#[derive(Debug, Clone, ValueEnum)]
enum EnclaveMode {
    /// Run the enclave inside a secure AWS Nitro enclave environment.
    #[value(verbatim_doc_comment)]
    Nitro,
    /// Run the AWS Nitro enclave in debug mode. Enclave logging will be enabled. This is INSECURE
    /// and Glove proofs will be marked as such.
    #[value(verbatim_doc_comment)]
    Debug,
    /// Run the enclave as a normal process. This is only useful for testing and development
    /// purposes as an AWS Nitro instance is not required. This is INSECURE and Glove proofs will be
    /// marked as such.
    #[value(verbatim_doc_comment)]
    Mock
}

// TODO Test what an actual limit is on batched votes
// TODO Load test with ~100 accounts voting on a single poll
// TODO Sign the enclave image
// TODO Persist voting requests
// TODO Restoring state on startup from private store and on-chain
// TODO When does the mixing occur? Is it configurable?

// TODO Deal with RPC disconnect:
//  2024-06-19T11:41:42.195924Z  WARN request{method=POST uri=/vote version=HTTP/1.1}: service: Subxt(Rpc(ClientError(RestartNeeded(Transport(connection closed
//  Caused by:
//  connection closed)))))

// TODO Permantely ban accounts which vote directly
// TODO Endpoint for poll end time and other info?
// TODO No more votes after on-chain votes

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::try_new(
        "subxt_core::events=info,hyper_util=info,reqwest::connect=info,aws=info,hyper::proto::h1=info")?
        // Set the base level to debug
        .add_directive(LevelFilter::DEBUG.into());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();

    let args = Args::parse();

    let storage = match args.storage {
        Storage::Dynamodb { table_name } => {
            let storage = DynamodbGloveStorage::connect(table_name).await
                .context("Failed to connect to DynamoDB table")?;
            info!("Connected to DynamoDB table");
            GloveStorage::Dynamodb(storage)
        }
        Storage::InMemory => {
            warn!("No DynamoDB table specified, so state will not be persisted");
            GloveStorage::InMemory(InMemoryGloveStorage::default())
        }
    };

    let enclave_handle = initialize_enclave(args.enclave_mode).await
        .context("Unable to connect to enclave")?;

    let network = CallableSubstrateNetwork::connect(
        args.node_endpoint.clone(),
        args.proxy_secret_phrase
    ).await?;
    debug!("Connected: {:?}", network);

    let attestation_bundle = enclave_handle.send_receive::<AttestationBundle>(
        &network.api.genesis_hash()
    ).await?;

    if attestation_bundle.attested_data.version != env!("CARGO_PKG_VERSION") {
        bail!("Version mismatch with enclave. Expected {:?}, got {:?}",
            env!("CARGO_PKG_VERSION"), attestation_bundle.attested_data.version);
    }

    // Just double-check everything is OK. A failure here prevents invalid Glove proofs from being
    // submitted on-chain.
    match attestation_bundle.verify() {
        Ok(_) | Err(InsecureMode) => debug!("Received attestation bundle from enclave"),
        Err(error) => return Err(error.into())
    }

    let glove_context = Arc::new(GloveContext {
        storage,
        enclave_handle,
        attestation_bundle,
        network,
        node_endpoint: args.node_endpoint,
        state: GloveState::default()
    });

    start_background_checker(glove_context.clone());

    let router = Router::new()
        .route("/info", get(info))
        .route("/vote", post(vote))
        .route("/remove-vote", post(remove_vote))
        .layer(TraceLayer::new_for_http())
        .with_state(glove_context);
    let listener = TcpListener::bind(args.address).await?;
    info!("Listening for requests...");
    axum::serve(listener, router).await?;

    Ok(())
}

/// Start a background task which polls for Glove violators and removes them.
fn start_background_checker(context: Arc<GloveContext>) {
    spawn(async move {
        let http_client = reqwest::Client::builder().build().unwrap();
        loop {
            trace!("Checking for Glove violators...");
            if let Err(error) = context.remove_glove_violators(&http_client).await {
                warn!("Error when checking for Glove violators: {:?}", error)
            }
            sleep(Duration::from_secs(60)).await
        }
    });
}

async fn initialize_enclave(enclave_mode: EnclaveMode) -> io::Result<EnclaveHandle> {
    match enclave_mode {
        EnclaveMode::Nitro => {
            cfg_if! {
                if #[cfg(target_os = "linux")] {
                    service::enclave::nitro::connect(false).await
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "AWS Nitro enclaves are only supported on Linux"
                    ));
                }
            }
        }
        EnclaveMode::Debug => {
            cfg_if! {
                if #[cfg(target_os = "linux")] {
                    warn!("Starting the enclave in debug mode, which is insecure");
                    service::enclave::nitro::connect(true).await
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "AWS Nitro enclaves are only supported on Linux"
                    ));
                }
            }
        }
        EnclaveMode::Mock => {
            warn!("Starting the enclave in mock mode, which is insecure");
            service::enclave::mock::spawn().await
        }
    }
}

async fn info(context: State<Arc<GloveContext>>) -> Json<ServiceInfo> {
    Json(ServiceInfo {
        proxy_account: context.network.account(),
        network_name: context.network.network_name.clone(),
        node_endpoint: context.node_endpoint.clone(),
        attestation_bundle: context.attestation_bundle.clone(),
        version: env!("CARGO_PKG_VERSION").to_string()
    })
}

// TODO Reject for zero balance
// TODO Reject if new vote request reaches max batch size limit for poll
// TODO Reject if voted directly or via another proxy already
// TODO Reject polls for certain tracks based on config
async fn vote(
    State(context): State<Arc<GloveContext>>,
    Json(signed_request): Json<SignedVoteRequest>
) -> Result<(), VoteError> {
    let network = &context.network;
    let request = &signed_request.request;
    let poll_index = request.poll_index;

    if !signed_request.verify() {
        return Err(BadVoteRequestError::InvalidSignature.into());
    }
    if request.genesis_hash != network.api.genesis_hash() {
        return Err(BadVoteRequestError::ChainMismatch.into());
    }
    if !is_glove_member(network, request.account.clone(), network.account()).await? {
        return Err(BadVoteRequestError::NotMember.into());
    }
    if network.get_ongoing_poll(poll_index).await?.is_none() {
        return Err(BadVoteRequestError::PollNotOngoing.into());
    }
    // In a normal poll with multiple votes on both sides, the on-chain vote balance can be
    // significantly less than the vote request balance. A malicious actor could use this to scew
    // the poll by passing a balance value much higher than they have, knowing there's a good chance
    // it won't be fully utilised.
    if network.account_balance(request.account.clone()).await? < request.balance {
        return Err(BadVoteRequestError::InsufficientBalance.into());
    }
    context.storage.add_vote_request(signed_request.clone()).await?;
    debug!("Vote request added to storage: {:?}", signed_request.request);
    schedule_vote_mixing(context, poll_index).await;
    Ok(())
}

async fn remove_vote(
    State(context): State<Arc<GloveContext>>,
    Json(signed_request): Json<SignedRemoveVoteRequest>
) -> Result<(), RemoveVoteError> {
    let network = &context.network;
    let account = &signed_request.request.account;
    let poll_index = signed_request.request.poll_index;

    if !signed_request.verify() {
        return Err(BadRemoveVoteRequestError::InvalidSignature.into());
    }
    if !is_glove_member(network, account.clone(), network.account()).await? {
        return Err(BadRemoveVoteRequestError::NotMember.into());
    }
    if !context.storage.remove_vote_request(poll_index, account).await? {
        debug!("Vote request not found for removal: {:?}", signed_request.request);
        // Removing a non-existent vote request is a no-op
        return Ok(());
    }
    debug!("Vote request removed from storage: {:?}", signed_request.request);

    spawn(async move {
        let remove_result = proxy_remove_vote(
            &context.network,
            signed_request.request.account,
            poll_index
        ).await;
        if let Err(error) = remove_result {
            warn!("Error removing vote: {:?}", error);
        }
        // TODO Only do the mixing if the votes were previously submitted on-chain
        schedule_vote_mixing(context, poll_index).await;
    });

    Ok(())
}

/// Schedule a background task to mix the votes and submit them on-chain after a delay. Any voting
//  requests which are received in the interim will be included in the mix.
async fn schedule_vote_mixing(context: Arc<GloveContext>, poll_index: u32) {
    if !context.state.acquire_mix_semaphore(poll_index).await {
        debug!("Vote mixing for poll {} already scheduled", poll_index);
        return;
    }
    debug!("Scheduling vote mixing for poll {}", poll_index);
    spawn(async move {
        // TODO Figure out the policy for submitting on-chain
        sleep(Duration::from_secs(10)).await;
        mix_votes(&context, poll_index).await;
    });
}

async fn mix_votes(context: &GloveContext, poll_index: u32) {
    loop {
        match try_mix_votes(context, poll_index).await {
            Ok(true) => continue,
            Ok(false) => break,
            Err(mixing_error) => {
                // TODO Reconnect on NotConnected IO error: Io(Os { code: 107, kind: NotConnected, message: "Transport endpoint is not connected" })
                warn!("Error mixing votes: {:?}", mixing_error);
                break;
            }
        }
    }
}

/// Returns `true` if the mixing should be retried.
async fn try_mix_votes(context: &GloveContext, poll_index: u32) -> Result<bool, mixing::Error> {
    if !context.state.release_mix_semaphore(poll_index).await {
        debug!("Vote mixing for poll {} already in progress", poll_index);
        return Ok(false);
    }

    info!("Mixing votes for poll {}", poll_index);
    let poll_requests = context.storage.get_poll(poll_index).await?;

    let signed_glove_result = mixing::mix_votes_in_enclave(
        &context.enclave_handle,
        &context.attestation_bundle,
        poll_requests.clone()
    ).await?;

    let result = submit_glove_result_on_chain(&context, &poll_requests, signed_glove_result).await;
    if result.is_ok() {
        info!("Vote mixing for poll {} succeeded", poll_index);
        return Ok(false);
    }

    match result.unwrap_err() {
        ProxyError::Module(_, ConvictionVoting(NotOngoing)) => {
            info!("Poll {} is no longer ongoing, and will be removed", poll_index);
            context.storage.remove_poll(poll_index).await?;
            Ok(false)
        }
        ProxyError::Module(batch_index, ConvictionVoting(InsufficientFunds)) => {
            let request = &poll_requests[batch_index].request;
            warn!("Insufficient funds for {:?}. Removing it from poll and trying again", request);
            // TODO On-chain vote needs to be removed as well
            context.storage.remove_vote_request(poll_index, &request.account).await?;
            Ok(true)
        }
        ProxyError::Batch(BatchError::Module(batch_index, Proxy(NotProxy))) => {
            let request = &poll_requests[batch_index].request;
            warn!("Account is no longer part of Glove, removing it from poll and trying again: {:?}",
                request);
            context.storage.remove_vote_request(poll_index, &request.account).await?;
            Ok(true)
        }
        proxy_error => {
            if let Some(batch_index) = proxy_error.batch_index() {
                warn!("Error submitting mixed votes for {:?}: {:?}",
                    poll_requests[batch_index].request, proxy_error)
            } else {
                warn!("Error submitting mixed votes: {:?}", proxy_error)
            }
            Ok(false)
        }
    }
}

async fn submit_glove_result_on_chain(
    context: &GloveContext,
    signed_requests: &Vec<SignedVoteRequest>,
    signed_glove_result: SignedGloveResult
) -> Result<(), ProxyError> {
    // TODO Should the enclave produce the extrinic calls structs? It would prove the enclave
    //  intiated the abstain votes. Otherwise, users are trusting the host service is correctly
    //  interpreting the enclave's None mixing output.
    let mut batched_calls = Vec::with_capacity(signed_requests.len() + 1);

    let glove_result = &signed_glove_result.result;
    // Add a proxied vote call for each signed vote request
    for assigned_balance in &glove_result.assigned_balances {
        batched_calls.push(to_proxied_vote_call(glove_result, assigned_balance));
    }

    let attestation_location = context.state.attestation_bundle_location(|| async {
        submit_attestation_bundle_location_on_chain(&context).await
    }).await?;

    let glove_proof_lite = GloveProofLite {
        signed_result: signed_glove_result,
        attestation_location
    };

    // Add the Glove result, along with the location of the attestation bundle, to the batch
    batched_calls.push(RuntimeCall::System(SystemCall::remark {
        remark: glove_proof_lite.encode_envelope()
    }));

    // We can't use `batchAll` to submit the votes atomically, because it doesn't work with the
    // `proxy` extrinsic. `proxy` doesn't propagate any errors from the proxied call (it captures
    // the error in a ProxyExecuted event), and so `batchAll` doesn't receive any errors to
    // terminate the batch.
    //
    // Even if that did work, there is another issue with `batchAll` if there are multiple calls of
    // the same extrinsic in the batch - there's no way of knowing which of them failed. The
    // `ItemCompleted` events can't be issued, since they're rolled back in light of the error.
    let events = context.network.batch(batched_calls).await?;
    context.network.confirm_proxy_executed(&events)
}

// TODO Deal with mixed_balance of zero
fn to_proxied_vote_call(result: &GloveResult, assigned_balance: &AssignedBalance) -> RuntimeCall {
    RuntimeCall::Proxy(
        ProxyCall::proxy {
            real: account_to_subxt_multi_address(assigned_balance.account.clone()),
            force_proxy_type: None,
            call: Box::new(RuntimeCall::ConvictionVoting(ConvictionVotingCall::vote {
                poll_index: result.poll_index,
                vote: to_account_vote(result.direction, assigned_balance)
            })),
        }
    )
}

fn to_account_vote(
    direction: VoteDirection,
    assigned_balance: &AssignedBalance
) -> AccountVote<u128> {
    let offset = match assigned_balance.conviction {
        Conviction::None => 0,
        Conviction::Locked1x => 1,
        Conviction::Locked2x => 2,
        Conviction::Locked3x => 3,
        Conviction::Locked4x => 4,
        Conviction::Locked5x => 5,
        Conviction::Locked6x => 6
    };
    let balance = assigned_balance.balance;
    match direction {
        VoteDirection::Aye => AccountVote::Standard { vote: Vote(BASE_AYE + offset), balance },
        VoteDirection::Nay => AccountVote::Standard { vote: Vote(BASE_NAY + offset), balance },
        VoteDirection::Abstain => AccountVote::SplitAbstain { aye: 0, nay: 0, abstain: balance }
    }
}

async fn submit_attestation_bundle_location_on_chain(
    context: &GloveContext
) -> Result<AttestationBundleLocation, SubxtError> {
    let encoded = context.attestation_bundle.encode_envelope();
    let result = context.network
        .call_extrinsic(&client_interface::metadata::tx().system().remark(encoded)).await
        .map(|(_, location)| AttestationBundleLocation::SubstrateRemark(location));
    info!("Stored attestation bundle: {:?}", result);
    result
}

async fn proxy_remove_vote(
    network: &CallableSubstrateNetwork,
    account: AccountId32,
    poll_index: u32
) -> Result<(), ProxyError> {
    // This doesn't need to be a batch call, but using `batch_proxy_calls` lets us reuse the
    // error handling.
    let events = network.batch(vec![RuntimeCall::Proxy(
        ProxyCall::proxy {
            real: account_to_subxt_multi_address(account),
            force_proxy_type: None,
            call: Box::new(RuntimeCall::ConvictionVoting(ConvictionVotingCall::remove_vote {
                class: None,
                index: poll_index
            })),
        }
    )]).await?;
    network.confirm_proxy_executed(&events)
}

struct GloveContext {
    storage: GloveStorage,
    enclave_handle: EnclaveHandle,
    attestation_bundle: AttestationBundle,
    network: CallableSubstrateNetwork,
    node_endpoint: String,
    state: GloveState
}

impl GloveContext {
    /// Check for voters who have voted outside of Glove and remove them.
    async fn remove_glove_violators(&self, http_client: &reqwest::Client) -> anyhow::Result<()> {
        let mut polls_need_mixing = HashSet::new();

        for poll_index in self.storage.get_poll_indices().await? {
            // Use this opportunity to do some garbage collection and remove any expired polls
            if self.network.get_ongoing_poll(poll_index).await?.is_none() {
                debug!("Removing poll {} as it is no longer ongoing", poll_index);
                self.storage.remove_poll(poll_index).await?;
                continue;
            }
            for non_glove_voter in self.non_glove_voters(http_client, poll_index).await? {
                // Remove the voter from the poll if they have submitted a Glove vote
                if self.storage.remove_vote_request(poll_index, &non_glove_voter).await? {
                    info!("Account {} has voted on poll {} outside of Glove and so removing them",
                        non_glove_voter, poll_index);
                    polls_need_mixing.insert(poll_index);
                }
            }
        }

        // TODO Should only be mixed if there are on-chain votes to replace
        for poll_index in polls_need_mixing {
            mix_votes(self, poll_index).await;
        }

        Ok(())
    }

    async fn non_glove_voters(
        &self,
        http_client: &reqwest::Client,
        poll_index: u32
    ) -> anyhow::Result<Vec<AccountId32>> {
        let mut voters = Vec::new();
        let votes = subscan::get_votes(
            http_client,
            &self.network.network_name,
            poll_index,
            None
        ).await?;
        for vote in votes {
            let Some(extrinsic) = self.network.get_extrinsic(vote.extrinsic_index).await? else {
                warn!("Extrinsic referenced by subscan not found: {:?}", vote);
                continue;
            };
            let extrinsic_account = account(&extrinsic);
            if extrinsic_account.is_some() && extrinsic_account.unwrap() != self.network.account() {
                // The vote wasn't cast by the Glove proxy
                voters.push(vote.account.address);
            }
        }
        Ok(voters)
    }
}

#[derive(Default)]
struct GloveState {
    // There may be a non-trivial cost to storing the attestation bundle location, and so it's done
    // lazily on first poll mixing, rather than eagerly on startup.
    abl: Mutex<Option<AttestationBundleLocation>>,
    /// Initially `false`, this is `true` if a background task has been kicked off to mix the vote
    /// requests and submit the results on-chain. The task will set this back to `false` once it has
    /// started by calling [Poll::begin_mix].
    mix_semaphore: Mutex<HashSet<u32>>
}

impl GloveState {
    async fn attestation_bundle_location<E: Error, Fut>(
        &self,
        new: impl FnOnce() -> Fut
    ) -> Result<AttestationBundleLocation, E>
    where
        Fut: Future<Output = Result<AttestationBundleLocation, E>>,
    {
        let mut abl_holder = self.abl.lock().await;
        match &*abl_holder {
            None => {
                let abl = new().await?;
                *abl_holder = Some(abl.clone());
                Ok(abl)
            }
            Some(abl) => Ok(abl.clone())
        }
    }

    async fn acquire_mix_semaphore(&self, poll_index: u32) -> bool {
        self.mix_semaphore.lock().await.insert(poll_index)
    }

    async fn release_mix_semaphore(&self, poll_index: u32) -> bool {
        self.mix_semaphore.lock().await.remove(&poll_index)
    }
}

#[derive(thiserror::Error, Debug)]
enum InternalError {
    #[error("Subxt error: {0}")]
    Subxt(#[from] SubxtError),
    #[error("Proxy error: {0}")]
    Proxy(#[from] ProxyError),
    #[error("Storage error: {0}")]
    Storage(#[from] storage::Error),
}

#[derive(Serialize)]
struct BadRequestResponse {
    error: String,
    description: String
}

#[derive(thiserror::Error, Debug)]
enum BadVoteRequestError {
    #[error("Signature on signed vote request is invalid")]
    InvalidSignature,
    #[error("Vote request is for a different chain")]
    ChainMismatch,
    #[error("Glove proxy is not assigned as a Governance proxy to the account")]
    NotMember,
    #[error("Poll is not ongoing or does not exist")]
    PollNotOngoing,
    #[error("Insufficient account balance for vote")]
    InsufficientBalance
}

#[derive(thiserror::Error, Debug)]
enum VoteError {
    #[error("Bad request: {0}")]
    BadRequest(#[from] BadVoteRequestError),
    #[error("Internal error: {0}")]
    Internal(#[from] InternalError)
}

impl From<SubxtError> for VoteError {
    fn from(error: SubxtError) -> Self {
        VoteError::Internal(error.into())
    }
}

impl From<ProxyError> for VoteError {
    fn from(error: ProxyError) -> Self {
        VoteError::Internal(error.into())
    }
}

impl From<storage::Error> for VoteError {
    fn from(error: storage::Error) -> Self {
        VoteError::Internal(error.into())
    }
}

impl IntoResponse for VoteError {
    fn into_response(self) -> Response {
        match self {
            VoteError::BadRequest(error) => {
                let error_variant = match error {
                    BadVoteRequestError::InvalidSignature => "InvalidSignature",
                    BadVoteRequestError::ChainMismatch => "ChainMismatch",
                    BadVoteRequestError::NotMember => "NotMember",
                    BadVoteRequestError::PollNotOngoing => "PollNotOngoing",
                    BadVoteRequestError::InsufficientBalance => "InsufficientBalance",
                }.to_string();
                (
                    StatusCode::BAD_REQUEST,
                    Json(BadRequestResponse { error: error_variant, description: error.to_string() })
                ).into_response()
            },
            VoteError::Internal(error) => {
                warn!("Error with vote request: {:?}", error);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string()
                ).into_response()
            }
        }
    }
}

#[derive(thiserror::Error, Debug)]
enum BadRemoveVoteRequestError {
    #[error("Signature on signed vote request is invalid")]
    InvalidSignature,
    #[error("Glove proxy is not assigned as a Governance proxy to the account")]
    NotMember
}

#[derive(thiserror::Error, Debug)]
enum RemoveVoteError {
    #[error("Bad request: {0}")]
    BadRequest(#[from] BadRemoveVoteRequestError),
    #[error("Internal error: {0}")]
    Internal(#[from] InternalError)
}

impl From<SubxtError> for RemoveVoteError {
    fn from(error: SubxtError) -> Self {
        RemoveVoteError::Internal(error.into())
    }
}

impl From<ProxyError> for RemoveVoteError {
    fn from(error: ProxyError) -> Self {
        RemoveVoteError::Internal(error.into())
    }
}

impl From<storage::Error> for RemoveVoteError {
    fn from(error: storage::Error) -> Self {
        RemoveVoteError::Internal(error.into())
    }
}

impl IntoResponse for RemoveVoteError {
    fn into_response(self) -> Response {
        match self {
            RemoveVoteError::BadRequest(error) => {
                let error_variant = match error {
                    BadRemoveVoteRequestError::InvalidSignature => "InvalidSignature",
                    BadRemoveVoteRequestError::NotMember => "NotMember",
                }.to_string();
                (
                    StatusCode::BAD_REQUEST,
                    Json(BadRequestResponse {
                        error: error_variant,
                        description: error.to_string()
                    })
                ).into_response()
            },
            RemoveVoteError::Internal(error) => {
                warn!("Error with remove-vote request: {:?}", error);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string()
                ).into_response()
            }
        }
    }
}
