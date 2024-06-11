use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Json, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Router;
use axum::routing::{get, post};
use clap::Parser;
use itertools::Itertools;
use sp_runtime::AccountId32;
use subxt::Error as SubxtError;
use subxt_signer::sr25519::Keypair;
use tokio::net::TcpListener;
use tokio::spawn;
use tokio::sync::Mutex;
use tokio::time::sleep;
use tower_http::trace::TraceLayer;
use tracing::{debug, info};
use tracing::log::warn;
use tracing_subscriber::filter::{EnvFilter, LevelFilter};

use core::{is_glove_member, ServiceInfo, SubstrateNetwork, VoteRequest};
use core::account_to_address;
use core::BatchError;
use core::core_to_subxt;
use core::metadata::proxy::events::ProxyExecuted;
use core::metadata::runtime_types::pallet_conviction_voting::pallet::Call as ConvictionVotingCall;
use core::metadata::runtime_types::pallet_conviction_voting::pallet::Error::{InsufficientFunds, NotOngoing, NotVoter};
use core::metadata::runtime_types::pallet_conviction_voting::vote::AccountVote;
use core::metadata::runtime_types::pallet_conviction_voting::vote::Vote;
use core::metadata::runtime_types::pallet_proxy::pallet::Call as ProxyCall;
use core::metadata::runtime_types::pallet_proxy::pallet::Error::NotProxy;
use core::metadata::runtime_types::pallet_referenda::types::ReferendumInfo;
use core::metadata::runtime_types::polkadot_runtime::RuntimeCall;
use core::metadata::runtime_types::polkadot_runtime::RuntimeError;
use core::metadata::runtime_types::polkadot_runtime::RuntimeError::Proxy;
use core::metadata::runtime_types::sp_runtime::DispatchError as MetadataDispatchError;
use core::metadata::storage;
use core::RemoveVoteRequest;
use mixing::VoteMixRequest;
use RuntimeError::ConvictionVoting;
use ServiceError::{NotMember, PollNotOngoing};
use ServiceError::InsufficientBalance;

mod mixing;
mod core;

const AYE: u8 = 128;
const NAY: u8 = 0;

#[derive(Parser, Debug)]
#[command(version, about = "Glove proxy service")]
struct Args {
    /// Secret phrase for the Glove proxy account
    #[arg(long, value_parser = core::parse_secret_phrase)]
    proxy_secret_phrase: Keypair,

    /// URL for the network endpoint.
    ///
    /// See https://wiki.polkadot.network/docs/maintain-endpoints for more information.
    #[arg(long)]
    network_url: String
}

// TODO Listen, or poll, for any member who votes directly

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::try_new("subxt_core::events=info")?
        // Set the base level to debug
        .add_directive(LevelFilter::DEBUG.into());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();

    let args = Args::parse();

    let network = SubstrateNetwork::connect(args.network_url, args.proxy_secret_phrase).await?;
    info!("Connected to Substrate network: {}", network.url);

    let glove_context = Arc::new(GloveContext {
        network,
        state: GloveState::default()
    });

    let router = Router::new()
        .route("/info", get(info))
        .route("/vote", post(vote))
        .route("/remove-vote", post(remove_vote))
        .layer(TraceLayer::new_for_http())
        .with_state(glove_context);
    let listener = TcpListener::bind("localhost:8080").await?;
    axum::serve(listener, router).await?;

    Ok(())
}

struct GloveContext {
    network: SubstrateNetwork,
    state: GloveState
}

#[derive(Default)]
struct GloveState {
    polls: Mutex<HashMap<u32, Poll>>
}

impl GloveState {
    async fn get_poll(&self, poll_index: u32) -> Poll {
        let mut polls = self.polls.lock().await;
        polls
            .entry(poll_index)
            .or_insert_with(|| Poll {
                index: poll_index,
                inner: Arc::default()
            })
            .clone()
    }

    async fn get_optional_poll(&self, poll_index: u32) -> Option<Poll> {
        let polls = self.polls.lock().await;
        polls.get(&poll_index).map(Poll::clone)
    }

    async fn remove_poll(&self, poll_index: u32) {
        let mut polls = self.polls.lock().await;
        polls.remove(&poll_index);
    }
}

#[derive(Debug, Clone)]
struct Poll {
    index: u32,
    inner: Arc<Mutex<InnerPoll>>
}

impl Poll {
    /// Returns `true` if vote mixing should be initiated as a background task.
    async fn add_vote_request(&self, vote_request: VoteRequest) -> bool {
        if vote_request.poll_index != self.index {
            panic!("Request doesn't belong here: {} vs {:?}", self.index, vote_request);
        }
        let mut poll = self.inner.lock().await;
        poll.requests.insert(vote_request.account.clone(), vote_request);
        let initiate_mix = !poll.pending_mix;
        poll.pending_mix = true;
        initiate_mix
    }

    async fn remove_vote_request(&self, account: AccountId32) -> Option<bool> {
        let mut poll = self.inner.lock().await;
        let _ = poll.requests.remove(&account)?;
        let initiate_mix = !poll.pending_mix;
        poll.pending_mix = true;
        Some(initiate_mix)
    }

    async fn begin_mix(&self) -> Option<Vec<VoteRequest>> {
        let mut poll = self.inner.lock().await;
        if !poll.pending_mix {
            return None;
        }
        poll.pending_mix = false;
        Some(
            poll.requests
                .clone()
                .into_values()
                .sorted_by(|a, b| Ord::cmp(&a.account, &b.account))
                .collect()
        )
    }
}

#[derive(Debug, Default)]
struct InnerPoll {
    requests: HashMap<AccountId32, VoteRequest>,
    /// Initially `false`, this is `true` if a background task has been kicked off to mix the vote
    /// requests and submit the results on-chain. The task will set this back to `false` once it has
    /// started by calling [Poll::begin_mix].
    pending_mix: bool
}

async fn info(context: State<Arc<GloveContext>>) -> Json<ServiceInfo> {
    Json(ServiceInfo {
        proxy_account: (&context.network).account(),
        network_url: context.network.url.clone()
    })
}

// TODO Reject for zero balance
async fn vote(
    State(context): State<Arc<GloveContext>>,
    Json(payload): Json<VoteRequest>
) -> Result<(), ServiceError> {
    let poll_index = payload.poll_index;
    if !is_glove_member(&context.network, payload.account.clone(), context.network.account()).await? {
        return Err(NotMember);
    }
    if !is_poll_ongoing(&context.network, poll_index).await? {
        return Err(PollNotOngoing);
    }
    // In a normal poll with multiple votes on both sides, the on-chain vote balance can be
    // significantly less than the vote request balance. A malicious actor could use this to scew
    // the poll by passing a balance value much higher than they have, knowing there's a good chance
    // it won't be fully utilised.
    if account_balance(&context.network, payload.account.clone()).await? < payload.balance {
        return Err(InsufficientBalance);
    }
    let poll = context.state.get_poll(poll_index).await;
    let initiate_mix = poll.add_vote_request(payload).await;
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
        let Some(poll_requests) = poll.begin_mix().await else {
            // Another task has already started mixing the votes
            break;
        };
        if poll_requests.is_empty() {
            info!("No votes to mix for poll {}", poll.index);
            break;
        }
        let result = mix_votes_and_submit_on_chain(&context.network, poll.index, &poll_requests).await;
        if result.is_ok() {
            info!("Vote mixing for poll {} succeeded", poll.index);
            break;
        }
        match result.unwrap_err() {
            ProxyError::Module(_, ConvictionVoting(NotOngoing)) => {
                info!("Poll {} has been detected as no longer ongoing, and so removing it", poll.index);
                context.state.remove_poll(poll.index).await;
                break;
            }
            ProxyError::Module(batch_index, ConvictionVoting(InsufficientFunds)) => {
                warn!("Insufficient funds for {:?}. Removing it from poll and trying again",
                        poll_requests[batch_index]);
                // TODO On-chain vote needs to be removed as well
                poll.remove_vote_request(poll_requests[batch_index].account.clone()).await;
                continue;
            }
            ProxyError::Batch(BatchError::Module(batch_index, Proxy(NotProxy))) => {
                warn!("Account is no longer part of the proxy, removing it from poll and trying again: {:?}",
                        poll_requests[batch_index]);
                // TODO How to remove on-chain vote if the account is no longer part of the proxy?
                poll.remove_vote_request(poll_requests[batch_index].account.clone()).await;
                continue;
            }
            error => {
                if let Some(batch_index) = error.batch_index() {
                    warn!("Error mixing votes for {:?}: {:?}", poll_requests[batch_index], error)
                } else {
                    warn!("Error mixing votes: {:?}", error)
                }
                break;
            }
        }
    }
}

async fn mix_votes_and_submit_on_chain(
    network: &SubstrateNetwork,
    poll_index: u32,
    poll_requests: &Vec<VoteRequest>
) -> Result<(), ProxyError> {
    info!("Mixing votes for poll {}:", poll_index);
    // Convert to VoteMixRequests
    let mix_requests = poll_requests
        .iter()
        .map(|request| {
            debug!("{:?}", request);
            VoteMixRequest::new(request.aye, request.balance)
        })
        .collect::<Vec<_>>();
    let Some(mixing_result) = mixing::mix_votes(&mix_requests) else {
        // TODO Vote abstain with a minimum balance.
        // TODO Should the enclave produce the extrinic calls structs? It would prove the enclave
        //  intiated the abstain votes. Otherwise, users are trusting the host service is correctly
        //  interpreting the enclave's None mixing output.
        panic!("Net zero mix votes");
    };

    debug!("Mixing result: {:?}", mixing_result);

    let proxy_vote_calls = poll_requests
        .iter()
        .zip(mixing_result.balances)
        .map(|(request, mix_balance)| {
            ProxyCall::proxy {
                real: account_to_address(request.account.clone()),
                force_proxy_type: None,
                call: Box::new(RuntimeCall::ConvictionVoting(ConvictionVotingCall::vote {
                    poll_index,
                    vote: AccountVote::Standard {
                        // TODO Deal with mixed_balance of zero
                        // TODO conviction multiplier
                        vote: Vote(if mixing_result.aye { AYE } else { NAY }),
                        balance: mix_balance
                    }
                })),
            }
        })
        .collect::<Vec<_>>();

    Ok(batch_proxy_calls(network, proxy_vote_calls).await?)
}

async fn proxy_remove_vote(
    network: &SubstrateNetwork,
    account: AccountId32,
    poll_index: u32
) -> Result<(), ProxyError> {
    Ok(
        // This doesn't need to be a batch call, but using `batch_proxy_calls` lets us reuse the
        // error handling.
        batch_proxy_calls(
            network,
            vec![ProxyCall::proxy {
                real: account_to_address(account),
                force_proxy_type: None,
                call: Box::new(RuntimeCall::ConvictionVoting(ConvictionVotingCall::remove_vote {
                    class: None,
                    index: poll_index
                })),
            }]
        ).await?
    )
}

// We can't use `batchAll` to submit the votes atomically, because it doesn't work with the `proxy`
// extrinsic. `proxy` doesn't propagate any errors from the proxied call (it captures the error in a
// ProxyExecuted event), and so `batchAll` doesn't receive any errors to terminate the batch.
//
// Even if that did work, there is another issue with `batchAll` if there are multiple calls of the
// same extrinsic in the batch - there's no way of knowing which of them failed. The `ItemCompleted`
// events can't be issued, since they're rolled back in light of the error.
async fn batch_proxy_calls(network: &SubstrateNetwork, proxy_calls: Vec<ProxyCall>) -> Result<(), ProxyError> {
    let proxy_calls = proxy_calls.into_iter().map(RuntimeCall::Proxy).collect::<Vec<_>>();
    let events = network.batch(proxy_calls).await?;
    // Find the first proxy call which failed, if any
    for (batch_index, proxy_executed) in events.find::<ProxyExecuted>().enumerate() {
        match proxy_executed {
            Ok(ProxyExecuted { result: Err(dispatch_error) }) => {
                return network
                    .extract_runtime_error(&dispatch_error)
                    .map_or_else(
                        || Err(ProxyError::Dispatch(batch_index, dispatch_error)),
                        |runtime_error| Err(ProxyError::Module(batch_index, runtime_error))
                    );
            }
            Ok(ProxyExecuted { result: Ok(_) }) => continue,
            Err(error) => return Err(error.into())
        }
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn add_new_vote_and_then_remove() {
        let glove_state = GloveState::default();
        let account = AccountId32::from([1; 32]);
        let vote_request = VoteRequest::new(account.clone(), 1, true, 10);

        let poll = glove_state.get_poll(1).await;

        let pending_mix = poll.add_vote_request(vote_request.clone()).await;
        assert_eq!(pending_mix, true);
        let vote_requeats = poll.begin_mix().await;
        assert_eq!(vote_requeats, Some(vec![vote_request]));

        let pending_mix = poll.remove_vote_request(account).await;
        assert_eq!(pending_mix, Some(true));
        let vote_requeats = poll.begin_mix().await;
        assert_eq!(vote_requeats, Some(vec![]));
        assert_eq!(poll.begin_mix().await, None);
    }

    #[tokio::test]
    async fn remove_from_non_existent_poll() {
        let glove_state = GloveState::default();
        let account = AccountId32::from([1; 32]);
        let poll = glove_state.get_poll(1).await;
        let pending_mix = poll.remove_vote_request(account).await;
        assert_eq!(pending_mix, None);
    }

    #[tokio::test]
    async fn remove_non_existent_account_within_poll() {
        let glove_state = GloveState::default();
        let account_1 = AccountId32::from([1; 32]);
        let account_2 = AccountId32::from([2; 32]);
        let vote_request = VoteRequest::new(account_1.clone(), 1, true, 10);

        let poll = glove_state.get_poll(1).await;
        poll.add_vote_request(vote_request.clone()).await;

        let pending_mix = poll.remove_vote_request(account_2).await;
        assert_eq!(pending_mix, None);
    }

    #[tokio::test]
    async fn replace_vote_before_mixing() {
        let glove_state = GloveState::default();
        let account = AccountId32::from([1; 32]);
        let vote_request_1 = VoteRequest::new(account.clone(), 1, true, 10);
        let vote_request_2 = VoteRequest::new(account.clone(), 1, true, 20);

        let poll = glove_state.get_poll(1).await;

        let pending_mix = poll.add_vote_request(vote_request_1.clone()).await;
        assert_eq!(pending_mix, true);
        let pending_mix = poll.add_vote_request(vote_request_2.clone()).await;
        assert_eq!(pending_mix, false);

        let vote_requeats = poll.begin_mix().await;
        assert_eq!(vote_requeats, Some(vec![vote_request_2]));
    }

    #[tokio::test]
    async fn votes_from_two_accounts_in_between_mixing() {
        let glove_state = GloveState::default();
        let account_1 = AccountId32::from([1; 32]);
        let account_2 = AccountId32::from([2; 32]);
        let vote_request_1 = VoteRequest::new(account_1.clone(), 1, true, 10);
        let vote_request_2 = VoteRequest::new(account_2.clone(), 1, false, 20);

        let poll = glove_state.get_poll(1).await;

        let pending_mix = poll.add_vote_request(vote_request_2.clone()).await;
        assert_eq!(pending_mix, true);
        let vote_requeats = poll.begin_mix().await;
        assert_eq!(vote_requeats, Some(vec![vote_request_2.clone()]));

        let pending_mix = poll.add_vote_request(vote_request_1.clone()).await;
        assert_eq!(pending_mix, true);
        let vote_requeats = poll.begin_mix().await;
        assert_eq!(vote_requeats, Some(vec![vote_request_1, vote_request_2]));
    }
}
