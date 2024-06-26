use io::Error as IoError;
use io::ErrorKind;
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
use parity_scale_codec::Error as ScaleError;
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
use client_interface::{ExtrinsicEvents, is_glove_member, ServiceInfo, SubstrateNetwork};
use client_interface::account_to_address;
use client_interface::BatchError;
use client_interface::core_to_subxt;
use client_interface::metadata::proxy::events::ProxyExecuted;
use client_interface::metadata::runtime_types::frame_system::pallet::Call as SystemCall;
use client_interface::metadata::runtime_types::pallet_conviction_voting::pallet::Call as ConvictionVotingCall;
use client_interface::metadata::runtime_types::pallet_conviction_voting::pallet::Error::{InsufficientFunds, NotOngoing, NotVoter};
use client_interface::metadata::runtime_types::pallet_conviction_voting::vote::AccountVote;
use client_interface::metadata::runtime_types::pallet_conviction_voting::vote::Vote;
use client_interface::metadata::runtime_types::pallet_proxy::pallet::Call as ProxyCall;
use client_interface::metadata::runtime_types::pallet_proxy::pallet::Error::NotProxy;
use client_interface::metadata::runtime_types::pallet_referenda::types::ReferendumInfo;
use client_interface::metadata::runtime_types::polkadot_runtime::RuntimeCall;
use client_interface::metadata::runtime_types::polkadot_runtime::RuntimeError;
use client_interface::metadata::runtime_types::polkadot_runtime::RuntimeError::Proxy;
use client_interface::metadata::runtime_types::sp_runtime::DispatchError as MetadataDispatchError;
use client_interface::metadata::storage;
use client_interface::RemoveVoteRequest;
use common::{attestation, AYE, ExtrinsicLocation, NAY, ResultType, SignedGloveResult};
use common::attestation::{AttestationBundle, AttestationBundleLocation, GloveProof, GloveProofLite};
use enclave_interface::{EnclaveRequest, EnclaveResponse, SignedVoteRequest};
use RuntimeError::ConvictionVoting;
use service::{GloveState, Poll};
use service::enclave::EnclaveHandle;
use ServiceError::{NotMember, PollNotOngoing, Scale};
use ServiceError::InsufficientBalance;
use ServiceError::InvalidRequestSignature;

#[derive(Parser, Debug)]
#[command(version, about = "Glove proxy service")]
struct Args {
    /// Secret phrase for the Glove proxy account
    #[arg(long, value_parser = client_interface::parse_secret_phrase)]
    proxy_secret_phrase: Keypair,

    /// Address the service will listen on.
    #[arg(long)]
    address: String,

    /// URL for the network endpoint.
    ///
    /// See https://wiki.polkadot.network/docs/maintain-endpoints for more information.
    #[arg(long)]
    network_url: String,

    /// Which mode the Glove enclave should run in.
    #[arg(long, value_enum, default_value_t = EnclaveMode::Nitro)]
    enclave_mode: EnclaveMode
}

#[derive(ValueEnum, Debug, Clone)]
enum EnclaveMode {
    /// Run the enclave inside a AWS Nitro enclave environment.
    Nitro,
    /// Run the AWS Nitro enclave in debug mode. Note, this is insecure.
    Debug,
    /// Run the enclave as a normal process. Note, this is insecure.
    Mock
}

// TODO Listen, or poll, for any member who votes directly
// TODO Test what an actual limit is on batched votes

// TODO Deal with RPC disconnect:
// 2024-06-19T11:36:12.533696Z DEBUG rustls::common_state: Sending warning alert CloseNotify
// 2024-06-19T11:36:12.533732Z DEBUG soketto::connection: 2d71fa53: cannot receive, connection is closed
// 2024-06-19T11:36:12.533743Z DEBUG jsonrpsee-client: Failed to read message: connection closed
// 2024-06-19T11:41:41.247725Z DEBUG request{method=GET uri=/info version=HTTP/1.1}: tower_http::trace::on_request: started processing request
// 2024-06-19T11:41:41.247763Z DEBUG request{method=GET uri=/info version=HTTP/1.1}: tower_http::trace::on_response: finished processing request latency=0 ms status=200
// 2024-06-19T11:41:42.195777Z DEBUG request{method=POST uri=/vote version=HTTP/1.1}: tower_http::trace::on_request: started processing request
// 2024-06-19T11:41:42.195924Z  WARN request{method=POST uri=/vote version=HTTP/1.1}: service: Subxt(Rpc(ClientError(RestartNeeded(Transport(connection closed
//
// Caused by:
// connection closed)))))
// 2024-06-19T11:41:42.195944Z DEBUG request{method=POST uri=/vote version=HTTP/1.1}: tower_http::trace::on_response: finished processing request latency=0 ms status=500
// 2024-06-19T11:41:42.195957Z ERROR request{method=POST uri=/vote version=HTTP/1.1}: tower_http::trace::on_failure: response failed classification=Status code: 500 Internal Server Error latency=0 ms

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::try_new("subxt_core::events=info")?
        // Set the base level to debug
        .add_directive(LevelFilter::DEBUG.into());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();

    let args = Args::parse();

    let enclave_handle = initialize_enclave(args.enclave_mode).await?;

    let attestation_bundle = retrieve_attestation(&enclave_handle).await?;
    // Just double-check everything is OK. A failure here prevents invalid Glove proofs from being
    // submitted on-chain.
    match attestation_bundle.verify() {
        Ok(_) | Err(InsecureMode) => {}
        Err(error) => return Err(error.into())
    }

    let network = SubstrateNetwork::connect(args.network_url, args.proxy_secret_phrase).await?;
    info!("Connected to Substrate network: {}", network.url);

    let glove_context = Arc::new(GloveContext {
        enclave_handle,
        attestation_bundle,
        network,
        state: GloveState::default()
    });

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

struct GloveContext {
    enclave_handle: EnclaveHandle,
    attestation_bundle: AttestationBundle,
    network: SubstrateNetwork,
    state: GloveState
}

async fn initialize_enclave(enclave_mode: EnclaveMode) -> io::Result<EnclaveHandle> {
    match enclave_mode {
        EnclaveMode::Nitro => {
            cfg_if! {
                if #[cfg(target_os = "linux")] {
                    service::enclave::nitro::connect(false).await
                } else {
                    return Err(IoError::new(
                        ErrorKind::Unsupported,
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
                        ErrorKind::Unsupported,
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

async fn retrieve_attestation(enclave_handle: &EnclaveHandle) -> io::Result<AttestationBundle> {
    let response = enclave_handle.send_request(&EnclaveRequest::Attestation).await?;
    match response {
        EnclaveResponse::Attestation(attestation_bundle) => Ok(attestation_bundle),
        _ => Err(IoError::new(ErrorKind::InvalidData, format!("{:?}", response)))
    }
}

async fn info(context: State<Arc<GloveContext>>) -> Json<ServiceInfo> {
    Json(ServiceInfo {
        proxy_account: (&context.network).account(),
        network_url: context.network.url.clone()
    })
}

// TODO Reject for zero balance
// TODO Reject if new vote request reaches max batch size limit for poll
async fn vote(
    State(context): State<Arc<GloveContext>>,
    Json(payload): Json<client_interface::SignedVoteRequest>
) -> Result<(), ServiceError> {
    let network = &context.network;
    // Receive the signed vote request as a JSON payload represented by `client_interface::SignedVoteRequest`.
    // Decode it into the `enclave_interface::SignedVoteRequest` version which is better typed and
    // used by the enclave. In the process we end up verifying the signature, which whilst is not
    // necessary since the enclave will do it, is a good sanity check.
    let (request, signature) = payload.decode()?.ok_or(InvalidRequestSignature)?;
    let signed_request = SignedVoteRequest { request, signature };
    let request = &signed_request.request;

    if !is_glove_member(network, request.account.clone(), network.account()).await? {
        return Err(NotMember);
    }
    if !is_poll_ongoing(network, request.poll_index).await? {
        return Err(PollNotOngoing);
    }
    // In a normal poll with multiple votes on both sides, the on-chain vote balance can be
    // significantly less than the vote request balance. A malicious actor could use this to scew
    // the poll by passing a balance value much higher than they have, knowing there's a good chance
    // it won't be fully utilised.
    if account_balance(network, request.account.clone()).await? < request.balance {
        return Err(InsufficientBalance);
    }
    let poll = context.state.get_poll(request.poll_index).await;
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
    // TODO Does it matter if they're no longer a member? Can we remove the vote regardless?
    if !is_glove_member(network, payload.account.clone(), network.account()).await? {
        return Err(NotMember);
    }
    // Removing a non-existent vote request is a no-op
    let Some(poll) = context.state.get_optional_poll(payload.poll_index).await else {
        return Ok(());
    };
    let Some(initiate_mix) = poll.remove_vote_request(payload.account.clone()).await else {
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

async fn is_poll_ongoing(network: &SubstrateNetwork, poll_index: u32) -> Result<bool, SubxtError> {
    Ok(
        network.api
            .storage()
            .at_latest().await?
            .fetch(&storage().referenda().referendum_info_for(poll_index).unvalidated()).await?
            .map_or(false, |info| matches!(info, ReferendumInfo::Ongoing(_)))
    )
}

async fn account_balance(network: &SubstrateNetwork, account: AccountId32) -> Result<u128, SubxtError> {
    Ok(
        network.api
            .storage()
            .at_latest().await?
            .fetch(&storage().system().account(core_to_subxt(account))).await?
            .map_or(0, |account| account.data.free)
    )
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

// TODO Add another endpoint which a client can query with their nonce to see the status of
//  of their on-chain vote.
// TODO If it's a success then it could include the extrinsic coordinates.
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

    let signed_glove_result = mix_votes_in_enclave(&context, &poll_requests).await?;

    let result = submit_glove_result_on_chain(
        &context,
        poll.index,
        &poll_requests,
        signed_glove_result
    ).await;
    if result.is_ok() {
        info!("Vote mixing for poll {} succeeded", poll.index);
        return Ok(true);
    }

    match result.unwrap_err() {
        ProxyError::Module(_, ConvictionVoting(NotOngoing)) => {
            info!("Poll {} has been detected as no longer ongoing, and so removing it", poll.index);
            context.state.remove_poll(poll.index).await;
            Ok(true)
        }
        ProxyError::Module(batch_index, ConvictionVoting(InsufficientFunds)) => {
            let request = &poll_requests[batch_index].request;
            warn!("Insufficient funds for {:?}. Removing it from poll and trying again", request);
            // TODO On-chain vote needs to be removed as well
            poll.remove_vote_request(request.account.clone()).await;
            Ok(false)
        }
        ProxyError::Batch(BatchError::Module(batch_index, Proxy(NotProxy))) => {
            let request = &poll_requests[batch_index].request;
            warn!("Account is no longer part of the proxy, removing it from poll and trying again: {:?}",
                request);
            // TODO How to remove on-chain vote if the account is no longer part of the proxy?
            poll.remove_vote_request(request.account.clone()).await;
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
    vote_requests: &Vec<SignedVoteRequest>
) -> Result<SignedGloveResult, MixingError> {
    let request = EnclaveRequest::MixVotes(vote_requests.clone());
    let response = context.enclave_handle.send_request(&request).await?;
    debug!("Mixing result from enclave: {:?}", response);
    match response {
        EnclaveResponse::GloveResult(signed_result) => {
            // Double-check things all line up before committing on-chain
            match GloveProof::verify_components(&signed_result, &context.attestation_bundle) {
                Ok(_) => debug!("Glove proof verified"),
                Err(InsecureMode) => warn!("Glove proof from insecure enclave"),
                Err(error) => return Err(error.into())
            }
            Ok(signed_result)
        }
        EnclaveResponse::Error(enclave_error) => Err(enclave_error.into()),
        _ => Err(MixingError::UnexpectedResponse(response)),
    }
}

async fn submit_glove_result_on_chain(
    context: &GloveContext,
    poll_index: u32,
    signed_requests: &Vec<SignedVoteRequest>,
    signed_glove_result: SignedGloveResult
) -> Result<(), ProxyError> {
    let ResultType::Standard(standard) = &signed_glove_result.result.result_type else {
        // TODO Vote abstain with a minimum balance.
        // TODO Should the enclave produce the extrinic calls structs? It would prove the enclave
        //  intiated the abstain votes. Otherwise, users are trusting the host service is correctly
        //  interpreting the enclave's None mixing output.
        panic!("Net zero mix votes");
    };

    let mut batched_calls = Vec::with_capacity(signed_requests.len() + 1);

    // Add a proxied vote call for each signed vote request
    for (signed_req, assigned_bal) in signed_requests.iter().zip(&standard.assigned_balances) {
        batched_calls.push(RuntimeCall::Proxy(ProxyCall::proxy {
            real: account_to_address(signed_req.request.account.clone()),
            force_proxy_type: None,
            call: Box::new(RuntimeCall::ConvictionVoting(ConvictionVotingCall::vote {
                poll_index,
                vote: AccountVote::Standard {
                    // TODO Deal with mixed_balance of zero
                    // TODO conviction multiplier
                    vote: Vote(if standard.aye { AYE } else { NAY }),
                    balance: assigned_bal.balance
                }
            })),
        }));
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
    confirm_proxy_executed(&context.network, &events)
}

async fn submit_attestation_bundle_location_on_chain(
    context: &GloveContext
) -> Result<AttestationBundleLocation, SubxtError> {
    let compressed = context.attestation_bundle.encode_envelope();
    let payload = client_interface::metadata::tx().system().remark(compressed);
    let result = context.network
        .call_extrinsic(&payload).await
        .map(|(block_hash, events)| {
            AttestationBundleLocation::SubstrateRemark(ExtrinsicLocation {
                block_hash,
                block_index: events.extrinsic_index(),
            })
        });
    info!("Attestation bundle location: {:?}", result);
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
            real: account_to_address(account),
            force_proxy_type: None,
            call: Box::new(RuntimeCall::ConvictionVoting(ConvictionVotingCall::remove_vote {
                class: None,
                index: poll_index
            })),
        }
    )]).await?;
    confirm_proxy_executed(network, &events)
}

fn confirm_proxy_executed(
    network: &SubstrateNetwork,
    events: &ExtrinsicEvents
) -> Result<(), ProxyError> {
    // Find the first proxy call which failed, if any
    for (batch_index, proxy_executed) in events.find::<ProxyExecuted>().enumerate() {
        match proxy_executed {
            Ok(ProxyExecuted { result: Ok(_) }) => continue,
            Ok(ProxyExecuted { result: Err(dispatch_error) }) => {
                return network
                    .extract_runtime_error(&dispatch_error)
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

#[derive(thiserror::Error, Debug)]
pub enum MixingError {
    #[error("IO error: {0}")]
    Io(#[from] IoError),
    #[error("Enclave error: {0}")]
    Enclave(#[from] enclave_interface::Error),
    #[error("Unexpected response from enclave: {0:?}")]
    UnexpectedResponse(EnclaveResponse),
    #[error("Enclave attestation error: {0}")]
    Attestation(#[from] attestation::Error)
}

#[derive(thiserror::Error, Debug)]
pub enum ProxyError {
    #[error("Module error from batch index {0}: {1:?}")]
    Module(usize, RuntimeError),
    #[error("Dispatch error from batch index {0}: {1:?}")]
    Dispatch(usize, MetadataDispatchError),
    #[error("Batch error: {0}")]
    Batch(#[from] BatchError),
    #[error("Internal Subxt error: {0}")]
    Subxt(#[from] SubxtError)
}

impl ProxyError {
    fn batch_index(&self) -> Option<usize> {
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

#[derive(thiserror::Error, Debug)]
enum ServiceError {
    #[error("Signature on signed vote request is invalid")]
    InvalidRequestSignature,
    #[error("Client is not a member of the Glove proxy")]
    NotMember,
    #[error("Poll is not ongoing or does not exist")]
    PollNotOngoing,
    #[error("Insufficient account balance for vote")]
    InsufficientBalance,
    #[error("Scale decoding error: {0}")]
    Scale(#[from] ScaleError),
    #[error("Proxy error: {0}")]
    Proxy(#[from] ProxyError),
    #[error("Internal Subxt error: {0}")]
    Subxt(#[from] SubxtError),
}

impl IntoResponse for ServiceError {
    fn into_response(self) -> Response {
        match self {
            NotMember => (StatusCode::BAD_REQUEST, self.to_string()),
            PollNotOngoing => (StatusCode::BAD_REQUEST, self.to_string()),
            InsufficientBalance => (StatusCode::BAD_REQUEST, self.to_string()),
            Scale(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            _ => {
                warn!("{:?}", self);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
            }
        }.into_response()
    }
}
