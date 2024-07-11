use io::Error as IoError;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Json, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Router;
use axum::routing::{get, post};
use cfg_if::cfg_if;
use clap::{Parser, ValueEnum};
use sp_runtime::AccountId32;
use subxt::Error as SubxtError;
use subxt_signer::sr25519::Keypair;
use tokio::net::TcpListener;
use tokio::spawn;
use tokio::time::sleep;
use tower_http::trace::TraceLayer;
use tracing::{debug, info};
use tracing::log::warn;
use tracing_subscriber::filter::{EnvFilter, LevelFilter};

use attestation::Error::InsecureMode;
use client_interface::{account, is_glove_member, ProxyError, ServiceInfo, SubstrateNetwork};
use client_interface::account_to_subxt_multi_address;
use client_interface::BatchError;
use client_interface::metadata::runtime_types::frame_system::pallet::Call as SystemCall;
use client_interface::metadata::runtime_types::pallet_conviction_voting::pallet::Call as ConvictionVotingCall;
use client_interface::metadata::runtime_types::pallet_conviction_voting::pallet::Error::{InsufficientFunds, NotOngoing, NotVoter};
use client_interface::metadata::runtime_types::pallet_conviction_voting::vote::AccountVote;
use client_interface::metadata::runtime_types::pallet_conviction_voting::vote::Vote;
use client_interface::metadata::runtime_types::pallet_proxy::pallet::Call as ProxyCall;
use client_interface::metadata::runtime_types::pallet_proxy::pallet::Error::NotProxy;
use client_interface::metadata::runtime_types::polkadot_runtime::RuntimeCall;
use client_interface::metadata::runtime_types::polkadot_runtime::RuntimeError;
use client_interface::metadata::runtime_types::polkadot_runtime::RuntimeError::Proxy;
use client_interface::RemoveVoteRequest;
use common::{AssignedBalance, attestation, BASE_AYE, BASE_NAY, Conviction, GloveResult, SignedGloveResult, SignedVoteRequest, VoteDirection};
use common::attestation::{AttestationBundle, AttestationBundleLocation, GloveProof, GloveProofLite};
use enclave_interface::{EnclaveRequest, EnclaveResponse};
use RuntimeError::ConvictionVoting;
use service::{GloveState, Poll, subscan};
use service::enclave::EnclaveHandle;
use ServiceError::{NotMember, PollNotOngoing};
use ServiceError::ChainMismatch;
use ServiceError::InsufficientBalance;
use ServiceError::InvalidSignature;

#[derive(Parser, Debug)]
#[command(version, about = "Glove proxy service")]
struct Args {
    /// Secret phrase for the Glove proxy account. This is a secret seed with optional derivation
    /// paths. The account will be an Sr25519 key.
    ///
    /// See https://wiki.polkadot.network/docs/learn-account-advanced#derivation-paths for more
    /// details.
    #[arg(long, value_parser = client_interface::parse_secret_phrase)]
    proxy_secret_phrase: Keypair,

    /// Address the service will listen on.
    #[arg(long)]
    address: String,

    /// URL to a substrate node endpoint. The Glove service will use the API exposed by this to
    /// interact with the network.
    ///
    /// See https://wiki.polkadot.network/docs/maintain-endpoints for more information.
    #[arg(long)]
    node_endpoint: String,

    /// Which mode the Glove enclave should run in.
    #[arg(long, value_enum, default_value_t = EnclaveMode::Nitro)]
    enclave_mode: EnclaveMode
}

#[derive(ValueEnum, Debug, Clone)]
enum EnclaveMode {
    /// Run the enclave inside a secure AWS Nitro enclave environment.
    Nitro,
    /// Run the AWS Nitro enclave in debug mode. Enclave logging will be enabled. This is INSECURE
    /// and Glove proofs will be marked as such.
    Debug,
    /// Run the enclave as a normal process. This is only useful for testing and development
    /// purposes as an AWS Nitro instance is not required. This is INSECURE and Glove proofs will be
    /// marked as such.
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
// TODO Update client to make it easy to verify on-chain vote
// TODO No more votes after on-chain votes


#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::try_new("subxt_core::events=info,hyper_util=info,reqwest::connect=info")?
        // Set the base level to debug
        .add_directive(LevelFilter::DEBUG.into());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();

    let args = Args::parse();

    let enclave_handle = initialize_enclave(args.enclave_mode).await?;

    let network = SubstrateNetwork::connect(args.node_endpoint, args.proxy_secret_phrase).await?;
    info!("Connected: {:?}", network);

    let attestation_bundle = enclave_handle.send_receive::<AttestationBundle>(
        &network.api.genesis_hash()
    ).await?;
    // Just double-check everything is OK. A failure here prevents invalid Glove proofs from being
    // submitted on-chain.
    match attestation_bundle.verify() {
        Ok(_) | Err(InsecureMode) => debug!("Received attestation bundle from enclave"),
        Err(error) => return Err(error.into())
    }

    let glove_context = Arc::new(GloveContext {
        enclave_handle,
        attestation_bundle,
        network,
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
    axum::serve(listener, router).await?;

    Ok(())
}

/// Start a background task which polls for Glove violators and removes them.
fn start_background_checker(context: Arc<GloveContext>) {
    spawn(async move {
        loop {
            debug!("Checking for Glove violators...");
            if let Err(error) = context.remove_glove_violators().await {
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
                    return Err(IoError::new(
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
                    return Err(IoError::new(
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
        network_url: context.network.url.clone(),
        attestation_bundle: context.attestation_bundle.clone()
    })
}

// TODO Reject for zero balance
// TODO Reject if new vote request reaches max batch size limit for poll
// TODO Reject if voted directly or via another proxy already
// TODO Reject polls for certain tracks based on config
async fn vote(
    State(context): State<Arc<GloveContext>>,
    Json(signed_request): Json<SignedVoteRequest>
) -> Result<(), ServiceError> {
    let network = &context.network;
    let request = &signed_request.request;

    if !signed_request.verify() {
        return Err(InvalidSignature);
    }
    if request.genesis_hash != network.api.genesis_hash() {
        return Err(ChainMismatch);
    }
    if !is_glove_member(network, request.account.clone(), network.account()).await? {
        return Err(NotMember);
    }
    if network.get_ongoing_poll(request.poll_index).await?.is_none() {
        return Err(PollNotOngoing);
    }
    // In a normal poll with multiple votes on both sides, the on-chain vote balance can be
    // significantly less than the vote request balance. A malicious actor could use this to scew
    // the poll by passing a balance value much higher than they have, knowing there's a good chance
    // it won't be fully utilised.
    if network.account_balance(request.account.clone()).await? < request.balance {
        return Err(InsufficientBalance);
    }
    let poll = context.state.get_poll(request.poll_index);
    let initiate_mix = poll.add_vote_request(signed_request).await;
    if initiate_mix {
        schedule_vote_mixing(context, poll);
    }
    Ok(())
}

async fn remove_vote(
    State(context): State<Arc<GloveContext>>,
    Json(payload): Json<RemoveVoteRequest>
) -> Result<(), ServiceError> {
    let network = &context.network;
    let account = &payload.account;
    if !is_glove_member(network, account.clone(), network.account()).await? {
        return Err(NotMember);
    }
    let Some(poll) = context.state.get_optional_poll(payload.poll_index) else {
        // Removing a non-existent vote request is a no-op
        return Ok(());
    };
    let Some(initiate_mix) = poll.remove_vote_request(&account).await else {
        // Another task has already started mixing the votes
        return Ok(());
    };

    let remove_result = proxy_remove_vote(network, payload.account, payload.poll_index).await;
    match remove_result {
        // Unlikely since we've just checked above, but just in case
        Err(ProxyError::Module(_, ConvictionVoting(NotVoter))) => return Ok(()),
        Err(ProxyError::Batch(BatchError::Module(_, Proxy(NotProxy)))) => return Err(NotMember),
        Err(error) => return Err(error.into()),
        Ok(_) => {}
    }

    if initiate_mix {
        // TODO Only do the mixing if the votes were previously submitted on-chain
        schedule_vote_mixing(context, poll);
    }

    Ok(())
}

/// Schedule a background task to mix the votes and submit them on-chain after a delay. Any voting
//  requests which are received in the interim will be included in the mix.
fn schedule_vote_mixing(context: Arc<GloveContext>, poll: Poll) {
    debug!("Scheduling vote mixing for poll {}", poll.index);
    spawn(async move {
        // TODO Figure out the policy for submitting on-chain
        sleep(Duration::from_secs(10)).await;
        mix_votes(&context, &poll).await;
    });
}

async fn mix_votes(context: &GloveContext, poll: &Poll) {
    loop {
        match try_mix_votes(context, poll).await {
            Ok(true) => break,
            Ok(false) => continue,
            Err(mixing_error) => {
                // TODO Reconnect on NotConnected IO error: Io(Os { code: 107, kind: NotConnected, message: "Transport endpoint is not connected" })
                warn!("Error mixing votes: {:?}", mixing_error);
                break;
            }
        }
    }
}

async fn try_mix_votes(context: &GloveContext, poll: &Poll) -> Result<bool, MixingError> {
    info!("Mixing votes for poll {}", poll.index);
    let Some(poll_requests) = poll.begin_mix().await else {
        // Another task has already started mixing the votes
        return Ok(true);
    };

    let signed_glove_result = mix_votes_in_enclave(&context, poll_requests.clone()).await?;

    let result = submit_glove_result_on_chain(&context, &poll_requests, signed_glove_result).await;
    if result.is_ok() {
        info!("Vote mixing for poll {} succeeded", poll.index);
        return Ok(true);
    }

    match result.unwrap_err() {
        ProxyError::Module(_, ConvictionVoting(NotOngoing)) => {
            // The background thread will eventually remove the poll
            info!("Poll {} is no longer ongoing, and will be removed", poll.index);
            Ok(true)
        }
        ProxyError::Module(batch_index, ConvictionVoting(InsufficientFunds)) => {
            let request = &poll_requests[batch_index].request;
            warn!("Insufficient funds for {:?}. Removing it from poll and trying again", request);
            // TODO On-chain vote needs to be removed as well
            poll.remove_vote_request(&request.account).await;
            Ok(false)
        }
        ProxyError::Batch(BatchError::Module(batch_index, Proxy(NotProxy))) => {
            let request = &poll_requests[batch_index].request;
            warn!("Account is no longer part of Glove, removing it from poll and trying again: {:?}",
                request);
            poll.remove_vote_request(&request.account).await;
            Ok(false)
        }
        proxy_error => {
            if let Some(batch_index) = proxy_error.batch_index() {
                warn!("Error submitting mixed votes for {:?}: {:?}",
                    poll_requests[batch_index].request, proxy_error)
            } else {
                warn!("Error submitting mixed votes: {:?}", proxy_error)
            }
            Ok(true)
        }
    }
}

async fn mix_votes_in_enclave(
    context: &GloveContext,
    vote_requests: Vec<SignedVoteRequest>
) -> Result<SignedGloveResult, MixingError> {
    let request = EnclaveRequest::MixVotes(vote_requests);
    let response = context.enclave_handle.send_receive::<EnclaveResponse>(&request).await?;
    match response {
        EnclaveResponse::GloveResult(signed_result) => {
            let result = &signed_result.result;
            debug!("Glove result from enclave, poll: {}, direction: {:?}, signature: {:?}",
                result.poll_index, result.direction, signed_result.signature);
            for assigned_balance in &result.assigned_balances {
                debug!("  {:?}", assigned_balance);
            }
            // Double-check things all line up before committing on-chain
            match GloveProof::verify_components(&signed_result, &context.attestation_bundle) {
                Ok(_) => debug!("Glove proof verified"),
                Err(InsecureMode) => warn!("Glove proof from insecure enclave"),
                Err(error) => return Err(error.into())
            }
            Ok(signed_result)
        }
        EnclaveResponse::Error(enclave_error) => {
            warn!("Mixing error from enclave: {:?}", enclave_error);
            Err(enclave_error.into())
        },
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
    network: &SubstrateNetwork,
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
    enclave_handle: EnclaveHandle,
    attestation_bundle: AttestationBundle,
    network: SubstrateNetwork,
    state: GloveState
}

impl GloveContext {
    /// Check for voters who have voted outside of Glove and remove them.
    async fn remove_glove_violators(&self) -> anyhow::Result<()> {
        let mut polls_need_mixing = Vec::new();

        for poll in self.state.get_polls() {
            // Use this opportunity to do some garbage collection and remove any expired polls
            if self.network.get_ongoing_poll(poll.index).await?.is_none() {
                self.state.remove_poll(poll.index);
                continue;
            }
            for non_glove_voter in self.non_glove_voters(poll.index).await? {
                // Remove the voter from the poll if they have submitted a Glove vote
                let initiate_mix = match poll.remove_vote_request(&non_glove_voter).await {
                    Some(initiate_mix) => {
                        info!("Account {} has voted on poll {} outside of Glove and so removing them",
                            non_glove_voter, poll.index);
                        initiate_mix
                    },
                    None => false
                };
                if initiate_mix {
                    polls_need_mixing.push(poll.clone());
                }
            }
        }

        // TODO Should only be mixed if there are on-chain votes to replace
        for poll in polls_need_mixing {
            mix_votes(self, &poll).await;
        }

        Ok(())
    }

    async fn non_glove_voters(&self, poll_index: u32) -> anyhow::Result<Vec<AccountId32>> {
        let mut voters = Vec::new();
        for vote in subscan::get_votes(&self.network, poll_index).await? {
            let extrinsic_account = self.network.get_extrinsic(vote.extrinsic_index).await?
                .as_ref()
                .and_then(account);
            if extrinsic_account != Some(self.network.account()) {
                // The vote wasn't cast by the Glove proxy
                voters.push(vote.account.address);
            }
        }
        Ok(voters)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum MixingError {
    #[error("IO error: {0}")]
    Io(#[from] IoError),
    #[error("Enclave error: {0}")]
    Enclave(#[from] enclave_interface::Error),
    #[error("Enclave attestation error: {0}")]
    Attestation(#[from] attestation::Error)
}

#[derive(thiserror::Error, Debug)]
enum ServiceError {
    #[error("Signature on signed vote request is invalid")]
    InvalidSignature,
    #[error("Vote request is for a different chain")]
    ChainMismatch,
    #[error("Client is not a member of the Glove proxy")]
    NotMember,
    #[error("Poll is not ongoing or does not exist")]
    PollNotOngoing,
    #[error("Insufficient account balance for vote")]
    InsufficientBalance,
    #[error("Proxy error: {0}")]
    Proxy(#[from] ProxyError),
    #[error("Internal Subxt error: {0}")]
    Subxt(#[from] SubxtError),
}

impl IntoResponse for ServiceError {
    fn into_response(self) -> Response {
        match self {
            ChainMismatch => (StatusCode::BAD_REQUEST, self.to_string()),
            NotMember => (StatusCode::BAD_REQUEST, self.to_string()),
            PollNotOngoing => (StatusCode::BAD_REQUEST, self.to_string()),
            InsufficientBalance => (StatusCode::BAD_REQUEST, self.to_string()),
            _ => {
                warn!("{:?}", self);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
            }
        }.into_response()
    }
}
