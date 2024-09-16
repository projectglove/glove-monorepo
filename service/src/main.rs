use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use aws_sdk_dynamodb::error::SdkError;
use aws_sdk_dynamodb::operation::delete_item::DeleteItemError;
use aws_sdk_dynamodb::operation::put_item::PutItemError;
use aws_sdk_dynamodb::operation::query::QueryError;
use aws_sdk_dynamodb::operation::scan::ScanError;
use axum::extract::{Json, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use cfg_if::cfg_if;
use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;
use sp_runtime::AccountId32;
use subxt::Error as SubxtError;
use subxt_signer::sr25519::Keypair;
use tokio::net::TcpListener;
use tokio::spawn;
use tokio::time::sleep;
use tower_http::trace::TraceLayer;
use tracing::warn;
use tracing::{debug, error, info};
use tracing_subscriber::filter::{EnvFilter, LevelFilter};

use attestation::Error::InsecureMode;
use client_interface::account_to_subxt_multi_address;
use client_interface::metadata::runtime_types::frame_system::pallet::Call as SystemCall;
use client_interface::metadata::runtime_types::pallet_conviction_voting::pallet::Call as ConvictionVotingCall;
use client_interface::metadata::runtime_types::pallet_conviction_voting::pallet::Error::InsufficientFunds;
use client_interface::metadata::runtime_types::pallet_conviction_voting::pallet::Error::NotVoter;
use client_interface::metadata::runtime_types::pallet_proxy::pallet::Call as ProxyCall;
use client_interface::metadata::runtime_types::pallet_proxy::pallet::Error::NotProxy;
use client_interface::metadata::runtime_types::polkadot_runtime::RuntimeError::Proxy;
use client_interface::metadata::runtime_types::polkadot_runtime::{RuntimeCall, RuntimeError};
use client_interface::subscan::Subscan;
use client_interface::BatchError;
use client_interface::{
    is_glove_member, CallableSubstrateNetwork, ProxyError, ReferendumStatus, ServiceInfo,
    SignedRemoveVoteRequest, SubstrateNetwork,
};
use common::attestation::{AttestationBundle, AttestationBundleLocation, GloveProofLite};
use common::{attestation, SignedGloveResult, SignedVoteRequest};
use service::dynamodb::DynamodbGloveStorage;
use service::enclave::EnclaveHandle;
use service::storage::{GloveStorage, InMemoryGloveStorage};
use service::{
    calculate_mixing_time, mixing, storage, to_proxied_vote_call, GloveContext, GloveState,
    MixingTime, BLOCK_TIME_SECS,
};
use storage::Error as StorageError;
use RuntimeError::ConvictionVoting;

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

    /// URL to a Substrate node endpoint. The Glove service will use the API exposed by this to
    /// interact with the network.
    ///
    /// See https://wiki.polkadot.network/docs/maintain-endpoints for more information.
    #[arg(long, verbatim_doc_comment)]
    node_endpoint: String,

    /// API key to use when querying Subscan.
    #[arg(long, verbatim_doc_comment)]
    subscan_api_key: Option<String>,

    /// The storage to use for the service.
    #[clap(subcommand, verbatim_doc_comment)]
    storage: Storage,

    /// Which mode the Glove enclave should run in.
    #[arg(long, value_enum, verbatim_doc_comment, default_value_t = EnclaveMode::Nitro)]
    enclave_mode: EnclaveMode,

    /// List of track IDs, seperated by comma, for which polls are not allowed to be voted on.
    ///
    /// See https://wiki.polkadot.network/docs/learn-polkadot-opengov-origins#origins-and-tracks-info
    /// for list of track IDs.
    #[arg(long, verbatim_doc_comment, value_delimiter = ',')]
    exclude_tracks: Vec<u16>,

    /// If specified, will mix vote requests at a regular interval.
    ///
    /// This is only useful for testing and development purposes. Otherwise, in production this
    /// MUST NOT be used. Extra mixing risks leaking information about the private vote requests.
    ///
    /// When this is not specified (the default), the service will aim to only mix votes and submit
    /// the results on-chain once. After this, any further vote requests for the same poll will be
    /// rejected.
    #[arg(long, verbatim_doc_comment)]
    regular_mix: bool,
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
        table_name: String,
    },
    /// Store all state in memory. This is only useful for testing and development purposes. Do not
    /// use in production.
    #[command(verbatim_doc_comment)]
    InMemory,
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
    Mock,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let version = env!("CARGO_PKG_VERSION");
    info!("Starting Glove service v{}", version);

    let filter = EnvFilter::try_new(
        "subxt_core::events=info,hyper_util=info,reqwest::connect=info,aws=info,hyper::proto::h1=info")?
        // Set the base level to debug
        .add_directive(LevelFilter::DEBUG.into());
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let args = Args::parse();

    let storage = match args.storage {
        Storage::Dynamodb { table_name } => {
            let storage = DynamodbGloveStorage::connect(table_name)
                .await
                .context("Failed to connect to DynamoDB table")?;
            info!("Connected to DynamoDB table");
            GloveStorage::Dynamodb(storage)
        }
        Storage::InMemory => {
            warn!("No DynamoDB table specified, so state will not be persisted");
            GloveStorage::InMemory(InMemoryGloveStorage::default())
        }
    };

    let enclave_handle = initialize_enclave(args.enclave_mode)
        .await
        .context("Unable to connect to enclave")?;

    let network =
        CallableSubstrateNetwork::connect(args.node_endpoint.clone(), args.proxy_secret_phrase)
            .await?;
    debug!("Connected: {:?}", network);

    let attestation_bundle = enclave_handle
        .send_receive::<AttestationBundle>(&network.api.genesis_hash())
        .await?;

    if attestation_bundle.attested_data.version != version {
        bail!(
            "Version mismatch with enclave: {}",
            attestation_bundle.attested_data.version
        );
    }

    // Just double-check everything is OK. A failure here prevents invalid Glove proofs from being
    // submitted on-chain.
    match attestation_bundle.verify() {
        Ok(_) | Err(InsecureMode) => debug!("Received attestation bundle from enclave"),
        Err(error) => return Err(error.into()),
    }

    let glove_context = Arc::new(GloveContext {
        storage,
        enclave_handle,
        attestation_bundle,
        network,
        exclude_tracks: args.exclude_tracks.into_iter().collect(),
        regular_mix_enabled: args.regular_mix,
        state: GloveState::default(),
    });

    check_excluded_tracks(&glove_context).await?;

    let subscan = Subscan::new(
        glove_context.network.network_name.clone(),
        args.subscan_api_key,
    );
    if args.regular_mix {
        warn!("Regular mixing of votes is enabled. This is not suitable for production.");
    } else {
        mark_voted_polls_as_final(glove_context.clone(), &subscan).await?;
    }
    start_background_thread(glove_context.clone(), subscan);

    let router = Router::new()
        .route("/info", get(info))
        .route("/vote", post(vote))
        .route("/remove-vote", post(remove_vote))
        .route("/poll-info/:poll_index", get(poll_info))
        .layer(TraceLayer::new_for_http())
        .with_state(glove_context);
    let listener = TcpListener::bind(args.address).await?;
    info!("Listening for requests...");
    axum::serve(listener, router).await?;

    Ok(())
}

async fn check_excluded_tracks(context: &Arc<GloveContext>) -> anyhow::Result<()> {
    let track_infos = context.network.get_tracks()?;
    let mut excluded_track_infos = HashMap::new();
    for exclude_track_id in &context.exclude_tracks {
        let track_info = track_infos
            .get(exclude_track_id)
            .ok_or_else(|| anyhow!("Excluded track {} not found", exclude_track_id))?;
        excluded_track_infos.insert(exclude_track_id, &track_info.name);
    }

    info!("Excluded tracks: {:?}", excluded_track_infos);

    for poll_index in context.storage.get_poll_indices().await? {
        let Some(poll_info) = context.network.get_ongoing_poll(poll_index).await? else {
            continue;
        };
        if excluded_track_infos.contains_key(&poll_info.track) {
            warn!(
                "Poll {} belongs to track {} which has been excluded. Existing vote requests \
                will be mixed, but further requests will not be accepted.",
                poll_index, poll_info.track
            );
        }
    }

    Ok(())
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

async fn mark_voted_polls_as_final(
    context: Arc<GloveContext>,
    subscan: &Subscan,
) -> anyhow::Result<()> {
    let glove_proxy = Some(context.network.account());
    let poll_indices = context.storage.get_poll_indices().await?;
    debug!("Polls with requests: {:?}", poll_indices);
    for poll_index in poll_indices {
        let voter_lookup = context
            .state
            .get_poll_state_ref(poll_index)
            .await
            .voter_lookup;
        let proxy_has_voted = voter_lookup
            .get_voters(subscan)
            .await?
            .into_iter()
            .any(|(_, sender)| sender == glove_proxy);
        if proxy_has_voted {
            info!("Glove proxy has already voted on poll {}", poll_index);
            let poll_state_ref = context.state.get_poll_state_ref(poll_index).await;
            poll_state_ref.write_access().await.mix_finalized = true;
        }
    }
    Ok(())
}

fn start_background_thread(context: Arc<GloveContext>, subscan: Subscan) {
    spawn(async move {
        loop {
            debug!("Running background task...");
            if let Err(error) = run_background_task(context.clone(), subscan.clone()).await {
                warn!("Error from background task: {:?}", error)
            }
            sleep(Duration::from_secs(60)).await;
        }
    });
}

async fn run_background_task(context: Arc<GloveContext>, subscan: Subscan) -> anyhow::Result<()> {
    let network = &context.network;
    let storage = &context.storage;
    let regular_mix_enabled = context.regular_mix_enabled;

    for poll_index in storage.get_poll_indices().await? {
        let Some(status) = network.get_ongoing_poll(poll_index).await? else {
            info!("Removing poll {} as it is no longer active", poll_index);
            context.remove_poll(poll_index).await?;
            continue;
        };
        let mut mix_required =
            regular_mix_enabled && context.state.was_vote_added(poll_index).await;
        if check_non_glove_voters(&subscan, &context, poll_index).await? {
            mix_required = true;
        }
        if context.state.is_mix_finalized(poll_index).await {
            if mix_required && !regular_mix_enabled {
                warn!(
                    "Poll {} has already been mixed and submitted on-chain, but due to Glove \
                violators, it will need to be re-mixed",
                    poll_index
                );
            }
        } else if !mix_required && is_poll_ready_for_final_mix(poll_index, status, network).await? {
            mix_required = true;
        }
        if mix_required {
            mix_votes(&context, poll_index).await;
        }
    }

    Ok(())
}

async fn check_non_glove_voters(
    subscan: &Subscan,
    context: &GloveContext,
    poll_index: u32,
) -> anyhow::Result<bool> {
    let glove_proxy = Some(context.network.account());
    let mut non_glove_voters = HashSet::new();
    let mut mix_required = false;
    let voter_lookup = context
        .state
        .get_poll_state_ref(poll_index)
        .await
        .voter_lookup;
    for (voter, sender) in voter_lookup.get_voters(subscan).await? {
        if sender == glove_proxy {
            continue;
        }
        if context
            .storage
            .remove_vote_request(poll_index, &voter)
            .await?
        {
            warn!("Vote request from {} for poll {} has been removed as they have voted outside of Glove",
                    voter, poll_index);
            mix_required = true; // Re-mix without the offender
        }
        non_glove_voters.insert(voter);
    }
    context
        .state
        .set_non_glove_voters(poll_index, non_glove_voters)
        .await;
    Ok(mix_required)
}

async fn is_poll_ready_for_final_mix(
    poll_index: u32,
    poll_status: ReferendumStatus,
    network: &SubstrateNetwork,
) -> Result<bool, SubxtError> {
    let now = network.current_block_number().await?;
    let mixing_time = calculate_mixing_time(poll_status, network).await?;
    debug!(
        "Mixing time for {} @ now={}: {:?}",
        poll_index, now, mixing_time
    );
    match mixing_time {
        MixingTime::Deciding(block_number) if now >= block_number => {
            info!(
                "Poll {} is nearing the end of its decision period and will be mixed",
                poll_index
            );
            Ok(true)
        }
        MixingTime::Confirming(block_number) if now >= block_number => {
            info!(
                "Poll {} is nearing the end of its confirmation period and will be mixed",
                poll_index
            );
            Ok(true)
        }
        _ => Ok(false),
    }
}

async fn info(context: State<Arc<GloveContext>>) -> Result<Json<ServiceInfo>, InternalError> {
    // Make sure the RPC connection is still alive
    let current_block_number = context.network.current_block_number().await?;
    debug!("Current block number: {}", current_block_number);
    Ok(Json(ServiceInfo {
        proxy_account: context.network.account(),
        network_name: context.network.network_name.clone(),
        attestation_bundle: context.attestation_bundle.clone(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    }))
}

// TODO Reject for zero balance
// TODO Reject if new vote request reaches max batch size limit for poll
async fn vote(
    State(context): State<Arc<GloveContext>>,
    Json(signed_request): Json<SignedVoteRequest>,
) -> Result<(), VoteError> {
    let network = &context.network;
    let request = &signed_request.request;

    if !signed_request.verify() {
        return Err(BadVoteRequestError::InvalidSignature.into());
    }
    if !is_glove_member(network, request.account.clone(), network.account()).await? {
        return Err(BadVoteRequestError::NotMember.into());
    }
    if request.genesis_hash != network.api.genesis_hash() {
        return Err(BadVoteRequestError::ChainMismatch.into());
    }
    let Some(poll_info) = network.get_ongoing_poll(request.poll_index).await? else {
        return Err(BadVoteRequestError::PollNotOngoing.into());
    };
    if context.exclude_tracks.contains(&poll_info.track) {
        return Err(BadVoteRequestError::TrackNotAllowed.into());
    }
    if context
        .state
        .is_non_glove_voter(request.poll_index, &request.account)
        .await
    {
        return Err(BadVoteRequestError::VotedOutsideGlove.into());
    }
    // In a normal poll with multiple votes on both sides, the on-chain vote balance can be
    // significantly less than the vote request balance. A malicious actor could use this to scew
    // the poll by passing a balance value much higher than they have, knowing there's a good chance
    // it won't be fully utilised.
    if network.account_balance(request.account.clone()).await? < request.balance {
        return Err(BadVoteRequestError::InsufficientBalance.into());
    }
    if !context.add_vote_request(signed_request.clone()).await? {
        return Err(BadVoteRequestError::PollAlreadyMixed.into());
    }
    debug!(
        "Vote request added to storage: {:?}",
        signed_request.request
    );
    Ok(())
}

async fn remove_vote(
    State(context): State<Arc<GloveContext>>,
    Json(signed_request): Json<SignedRemoveVoteRequest>,
) -> Result<(), RemoveVoteError> {
    let network = &context.network;
    let account = &signed_request.request.account;
    let poll_index = signed_request.request.poll_index;

    if !is_glove_member(network, account.clone(), network.account()).await? {
        return Err(BadRemoveVoteRequestError::NotMember.into());
    }
    if !signed_request.verify() {
        return Err(BadRemoveVoteRequestError::InvalidSignature.into());
    }
    if !context.remove_vote_request(poll_index, account).await? {
        return Err(BadRemoveVoteRequestError::PollAlreadyMixed.into());
    }
    debug!("Vote request removed: {:?}", signed_request.request);

    if context.regular_mix_enabled {
        // Edge-case if regular mixing is enabled, where there might be an on-chain vote that also
        // needs removing.
        spawn(async move {
            let remove_result = proxy_remove_vote(
                &context.network,
                signed_request.request.account.clone(),
                poll_index,
            )
            .await;
            match remove_result {
                Err(ProxyError::Module(_, ConvictionVoting(NotVoter))) => {
                    debug!("Vote not found on-chain: {:?}", signed_request.request);
                }
                Err(error) => warn!("Error removing vote: {:?}", error),
                Ok(_) => info!("Vote removed on-chain: {:?}", signed_request.request),
            }
        });
    }

    Ok(())
}

async fn poll_info(
    State(context): State<Arc<GloveContext>>,
    Path(poll_index): Path<u32>,
) -> Result<Json<PollInfo>, PollInfoError> {
    if context.regular_mix_enabled {
        return Err(PollInfoError::RegularMixEnabled);
    }
    let Some(status) = context.network.get_ongoing_poll(poll_index).await? else {
        return Err(PollInfoError::PollNotActive);
    };
    let current_block = context.network.current_block_number().await?;
    let current_time = context.network.current_time().await? / 1000;
    let mixing_time = calculate_mixing_time(status, &context.network)
        .await?
        .block_number()
        .map(|block_number| {
            let timestamp = if block_number > current_block {
                current_time + ((block_number - current_block) * BLOCK_TIME_SECS) as u64
            } else {
                // Mixing time has already passed, which can occur either because:
                // 1. The mixing block number has been reached but the service background thread
                //    has yet to wake up from its 60s sleep
                // 2. There are no vote requests for this poll, there won't be a mixing event, and
                //    we're in the 15 min mixing buffer period at the end of the decision period
                // 3. Some test networks can have really short decision periods, smaller even than
                //    the mixing buffer period
                current_time
                    .saturating_sub(((current_block - block_number) * BLOCK_TIME_SECS) as u64)
            };
            MixingTimeJson {
                block_number,
                timestamp,
            }
        });
    Ok(Json(PollInfo { mixing_time }))
}

#[derive(Debug, Clone, Serialize)]
struct PollInfo {
    mixing_time: Option<MixingTimeJson>,
}

#[derive(Debug, Clone, Serialize)]
struct MixingTimeJson {
    block_number: u32,
    timestamp: u64,
}

async fn mix_votes(context: &GloveContext, poll_index: u32) {
    loop {
        match try_mix_votes(context, poll_index).await {
            Ok(true) => continue,
            Ok(false) => break,
            Err(mixing_error) => {
                warn!("Error mixing votes: {:?}", mixing_error);
                break;
            }
        }
    }
}

/// Returns `true` if the mixing should be retried.
async fn try_mix_votes(context: &GloveContext, poll_index: u32) -> Result<bool, mixing::Error> {
    info!("Mixing votes for poll {}", poll_index);
    let poll_state_ref = context.state.get_poll_state_ref(poll_index).await;
    // First acquire the mutex on the poll to prevent any race conditions with new vote requests
    // being added at the same time.
    let mut poll_state_guard = poll_state_ref.write_access().await;
    let poll_requests = context.storage.get_poll(poll_index).await?;

    let signed_glove_result = mixing::mix_votes_in_enclave(
        &context.enclave_handle,
        &context.attestation_bundle,
        poll_requests.clone(),
    )
    .await?;

    let result = submit_glove_result_on_chain(context, &poll_requests, signed_glove_result).await;
    if result.is_ok() {
        info!(
            "Successfully submitted mixed votes for poll {} on-chain",
            poll_index
        );
        if !context.regular_mix_enabled {
            poll_state_guard.mix_finalized = true;
        }
        return Ok(false);
    }

    match result.unwrap_err() {
        ProxyError::Module(batch_index, ConvictionVoting(InsufficientFunds)) => {
            let request = &poll_requests[batch_index].request;
            warn!(
                "Insufficient funds for {:?}. Removing it from poll and trying again",
                request
            );
            let removed = context
                .storage
                .remove_vote_request(poll_index, &request.account)
                .await?;
            if removed && context.state.is_mix_finalized(poll_index).await {
                // If the vote was already submitted on-chain, we need to remove it from there too
                let remove_result =
                    proxy_remove_vote(&context.network, request.account.clone(), poll_index).await;
                if let Err(error) = remove_result {
                    warn!("Error removing vote: {:?}", error);
                }
            }
            Ok(true)
        }
        ProxyError::Batch(BatchError::Module(batch_index, Proxy(NotProxy))) => {
            let request = &poll_requests[batch_index].request;
            warn!(
                "Account is no longer part of Glove, removing its request and trying again: {:?}",
                request
            );
            context
                .storage
                .remove_vote_request(poll_index, &request.account)
                .await?;
            Ok(true)
        }
        proxy_error => {
            if let Some(batch_index) = proxy_error.batch_index() {
                warn!(
                    "Error submitting mixed votes for {:?}: {:?}",
                    poll_requests[batch_index].request, proxy_error
                )
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
    signed_glove_result: SignedGloveResult,
) -> Result<(), ProxyError> {
    let mut batched_calls = Vec::with_capacity(signed_requests.len() + 1);

    let glove_result = &signed_glove_result.result;
    // Add a proxied vote call for each signed vote request
    for assigned_balance in &glove_result.assigned_balances {
        batched_calls.push(to_proxied_vote_call(glove_result, assigned_balance));
    }

    let attestation_location = context
        .state
        .attestation_bundle_location(|| async {
            submit_attestation_bundle_location_on_chain(context).await
        })
        .await?;

    let glove_proof_lite = GloveProofLite {
        signed_result: signed_glove_result,
        attestation_location,
    };

    // Add the Glove result, along with the location of the attestation bundle, to the batch
    batched_calls.push(RuntimeCall::System(SystemCall::remark {
        remark: glove_proof_lite.encode_envelope(),
    }));

    // We can't use `batchAll` to submit the votes atomically, because it doesn't work with the
    // `proxy` extrinsic. `proxy` doesn't propagate any errors from the proxied call (it captures
    // the error in a ProxyExecuted event), and so `batchAll` doesn't receive any errors to
    // terminate the batch.
    //
    // Even if that did work, there is another issue with `batchAll` if there are multiple calls of
    // the same extrinsic in the batch - there's no way of knowing which of them failed. The
    // `ItemCompleted` events can't be used, since they're rolled back in light of the error.
    let events = context.network.batch(batched_calls).await?;
    context.network.confirm_proxy_executed(&events)
}

async fn submit_attestation_bundle_location_on_chain(
    context: &GloveContext,
) -> Result<AttestationBundleLocation, SubxtError> {
    let encoded = context.attestation_bundle.encode_envelope();
    let result = context
        .network
        .call_extrinsic(&client_interface::metadata::tx().system().remark(encoded))
        .await
        .map(|(_, location)| AttestationBundleLocation::SubstrateRemark(location));
    info!("Stored attestation bundle: {:?}", result);
    result
}

async fn proxy_remove_vote(
    network: &CallableSubstrateNetwork,
    account: AccountId32,
    poll_index: u32,
) -> Result<(), ProxyError> {
    // This doesn't need to be a batch call, but using `batch_proxy_calls` lets us reuse the
    // error handling.
    let events = network
        .batch(vec![RuntimeCall::Proxy(ProxyCall::proxy {
            real: account_to_subxt_multi_address(account),
            force_proxy_type: None,
            call: Box::new(RuntimeCall::ConvictionVoting(
                ConvictionVotingCall::remove_vote {
                    class: None,
                    index: poll_index,
                },
            )),
        })])
        .await?;
    network.confirm_proxy_executed(&events)
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

impl InternalError {
    fn is_too_many_requests(&self) -> bool {
        let InternalError::Storage(storage_error) = self else {
            return false;
        };
        match storage_error {
            StorageError::DynamodbPutItem(SdkError::ServiceError(error)) => matches!(
                error.err(),
                PutItemError::ProvisionedThroughputExceededException(_)
                    | PutItemError::RequestLimitExceeded(_)
            ),
            StorageError::DynamodbDeleteItem(SdkError::ServiceError(error)) => matches!(
                error.err(),
                DeleteItemError::ProvisionedThroughputExceededException(_)
                    | DeleteItemError::RequestLimitExceeded(_)
            ),
            StorageError::DynamodbQuery(SdkError::ServiceError(error)) => matches!(
                error.err(),
                QueryError::ProvisionedThroughputExceededException(_)
                    | QueryError::RequestLimitExceeded(_)
            ),
            StorageError::DynamodbScan(SdkError::ServiceError(error)) => matches!(
                error.err(),
                ScanError::ProvisionedThroughputExceededException(_)
                    | ScanError::RequestLimitExceeded(_)
            ),
            _ => false,
        }
    }

    fn is_service_unavailable(&self) -> bool {
        match self {
            InternalError::Subxt(error) => error.is_disconnected_will_reconnect(),
            _ => false,
        }
    }
}

impl IntoResponse for InternalError {
    fn into_response(self) -> Response {
        if self.is_too_many_requests() {
            warn!("Too many requests: {:?}", self);
            (
                StatusCode::TOO_MANY_REQUESTS,
                "Too many requests, please try again later".to_string(),
            )
                .into_response()
        } else if self.is_service_unavailable() {
            warn!("Service unavailable: {:?}", self);
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "Unable to service request, please try again later".to_string(),
            )
                .into_response()
        } else {
            warn!("Unable to service request: {:?}", self);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            )
                .into_response()
        }
    }
}

#[derive(Serialize)]
struct BadRequestResponse {
    error: String,
    description: String,
}

#[derive(thiserror::Error, Debug)]
enum BadVoteRequestError {
    #[error("Signature on signed vote request is invalid")]
    InvalidSignature,
    #[error("Vote request is for a different chain")]
    ChainMismatch,
    #[error("Glove proxy is not assigned as a Governance proxy to the account")]
    NotMember,
    #[error("Account has already voted outside of Glove for this poll")]
    VotedOutsideGlove,
    #[error("Poll is not ongoing or does not exist")]
    PollNotOngoing,
    #[error("Poll belongs to a track which is not allowed for voting")]
    TrackNotAllowed,
    #[error("Votes for poll has already been mixed and submitted on-chain")]
    PollAlreadyMixed,
    #[error("Insufficient account balance for vote")]
    InsufficientBalance,
}

impl IntoResponse for BadVoteRequestError {
    fn into_response(self) -> Response {
        let error_variant = match self {
            BadVoteRequestError::InvalidSignature => "InvalidSignature",
            BadVoteRequestError::ChainMismatch => "ChainMismatch",
            BadVoteRequestError::NotMember => "NotMember",
            BadVoteRequestError::VotedOutsideGlove => "VotedOutsideGlove",
            BadVoteRequestError::PollNotOngoing => "PollNotOngoing",
            BadVoteRequestError::TrackNotAllowed => "TrackNotAllowed",
            BadVoteRequestError::PollAlreadyMixed => "PollAlreadyMixed",
            BadVoteRequestError::InsufficientBalance => "InsufficientBalance",
        }
        .to_string();
        (
            StatusCode::BAD_REQUEST,
            Json(BadRequestResponse {
                error: error_variant,
                description: self.to_string(),
            }),
        )
            .into_response()
    }
}

#[derive(thiserror::Error, Debug)]
enum VoteError {
    #[error("Bad request: {0}")]
    BadRequest(#[from] BadVoteRequestError),
    #[error("Internal error: {0}")]
    Internal(#[from] InternalError),
}

impl IntoResponse for VoteError {
    fn into_response(self) -> Response {
        match self {
            VoteError::BadRequest(error) => error.into_response(),
            VoteError::Internal(error) => error.into_response(),
        }
    }
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

#[derive(thiserror::Error, Debug)]
enum BadRemoveVoteRequestError {
    #[error("Signature on signed vote request is invalid")]
    InvalidSignature,
    #[error("Glove proxy is not assigned as a Governance proxy to the account")]
    NotMember,
    #[error("Votes for poll has already been mixed and submitted on-chain")]
    PollAlreadyMixed,
}

impl IntoResponse for BadRemoveVoteRequestError {
    fn into_response(self) -> Response {
        let error_variant = match self {
            BadRemoveVoteRequestError::InvalidSignature => "InvalidSignature",
            BadRemoveVoteRequestError::NotMember => "NotMember",
            BadRemoveVoteRequestError::PollAlreadyMixed => "PollAlreadyMixed",
        }
        .to_string();
        (
            StatusCode::BAD_REQUEST,
            Json(BadRequestResponse {
                error: error_variant,
                description: self.to_string(),
            }),
        )
            .into_response()
    }
}

#[derive(thiserror::Error, Debug)]
enum RemoveVoteError {
    #[error("Bad request: {0}")]
    BadRequest(#[from] BadRemoveVoteRequestError),
    #[error("Internal error: {0}")]
    Internal(#[from] InternalError),
}

impl IntoResponse for RemoveVoteError {
    fn into_response(self) -> Response {
        match self {
            RemoveVoteError::BadRequest(error) => error.into_response(),
            RemoveVoteError::Internal(error) => error.into_response(),
        }
    }
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

#[derive(thiserror::Error, Debug)]
enum PollInfoError {
    #[error("Regular mixing is enabled")]
    RegularMixEnabled,
    #[error("Poll is not active")]
    PollNotActive,
    #[error("Internal error: {0}")]
    Internal(#[from] InternalError),
}

impl IntoResponse for PollInfoError {
    fn into_response(self) -> Response {
        match self {
            PollInfoError::RegularMixEnabled => (
                StatusCode::NOT_FOUND,
                "Regular mixing is enabled".to_string(),
            )
                .into_response(),
            PollInfoError::PollNotActive => (
                StatusCode::BAD_REQUEST,
                Json(BadRequestResponse {
                    error: "PollNotActive".into(),
                    description: self.to_string(),
                }),
            )
                .into_response(),
            PollInfoError::Internal(error) => error.into_response(),
        }
    }
}

impl From<SubxtError> for PollInfoError {
    fn from(error: SubxtError) -> Self {
        PollInfoError::Internal(error.into())
    }
}
