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
use subxt::error::DispatchError as SubxtDispatchError;
use subxt::Error::Runtime;
use subxt_signer::sr25519::Keypair;
use SubxtDispatchError::Module;
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
use core::metadata::proxy::events::ProxyExecuted;
use core::metadata::runtime_types::pallet_conviction_voting::pallet::Call as ConvictionVotingCall;
use core::metadata::runtime_types::pallet_conviction_voting::vote::AccountVote;
use core::metadata::runtime_types::pallet_conviction_voting::vote::Vote;
use core::metadata::runtime_types::pallet_proxy::pallet::Error::NotProxy;
use core::metadata::runtime_types::polkadot_runtime::RuntimeCall;
use core::metadata::runtime_types::polkadot_runtime::RuntimeError;
use core::metadata::runtime_types::polkadot_runtime::RuntimeError::Proxy;
use core::metadata::runtime_types::sp_runtime::DispatchError as MetadataDispatchError;
use core::metadata::storage;
use core::RemoveVoteRequest;
use mixing::VoteMixRequest;
use ProxyCallError::NotProxyMember;
use ServiceError::{NotMember, UnknownPoll};

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
// TODO Reject for insufficient balance
async fn vote(
    State(context): State<Arc<GloveContext>>,
    Json(payload): Json<VoteRequest>
) -> Result<(), ServiceError> {
    let poll_index = payload.poll_index;
    if !is_glove_member(&context.network, payload.account.clone(), context.network.account()).await? {
        return Err(NotMember);
    }
    // TODO Change this to reject on poll not ongoing (which should cover non-existent poll)
    if poll_index >= poll_count(&context.network).await? {
        return Err(UnknownPoll);
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
        Err(ProxyRemoveVoteError::NotVoter) => return Ok(()),
        // Unlikely since we've just checked above, but just in case
        Err(ProxyRemoveVoteError::ProxyCall(NotProxyMember)) => return Err(NotMember),
        Err(ProxyRemoveVoteError::ProxyCall(error)) => return Err(error.into()),
        Ok(_) => {}
    }

    if initiate_mix {
        // TODO Only do the mixing if the votes were previously submitted on-chain
        schedule_vote_mixing(context, poll);
    }

    Ok(())
}

async fn poll_count(network: &SubstrateNetwork) -> Result<u32, SubxtError> {
    network.api
        .storage()
        .at_latest().await?
        .fetch(&storage().referenda().referendum_count()).await?
        .ok_or(SubxtError::Other("Unable to determine poll count".into()))
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
            return;
        };
        if poll_requests.is_empty() {
            info!("No votes to mix for poll {}", poll.index);
            return;
        }
        let result = mix_votes_and_submit_on_chain(&context.network, poll.index, &poll_requests).await;
        if let Err((request_index, error)) = result {
            match error {
                ProxyVoteError::NotOngoing => {
                    info!("Poll {} has been detected as no longer ongoing, and so removing it", poll.index);
                    context.state.remove_poll(poll.index).await;
                    return;
                }
                // For these errors, retry with the request removed
                // TODO On-chain vote needs to be removed as well
                ProxyVoteError::InsufficientFunds => {}
                ProxyVoteError::MaxVotesReached => {}
                // TODO How to remove on-chain vote if the account is no longer part of the proxy?
                ProxyVoteError::ProxyCall(NotProxyMember) => {}
                _ => {
                    warn!("Error mixing votes for {:?}: {:?}", poll_requests[request_index], error);
                    return;
                }
            }
            warn!(
                "{:?} failed with error {:?}. Removing it from poll and trying again",
                poll_requests[request_index], error
            );
            poll.remove_vote_request(poll_requests[request_index].account.clone()).await;
        } else {
            info!("Vote mixing for poll {} succeeded", poll.index);
            return;
        }
    }
}

async fn mix_votes_and_submit_on_chain(
    network: &SubstrateNetwork,
    poll_index: u32,
    poll_requests: &Vec<VoteRequest>
) -> Result<(), (usize, ProxyVoteError)> {
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
        panic!("Net zero mix votes");
    };

    debug!("Mixing result: {:?}", mixing_result);

    // We can't use `batchAll` to submit the votes atomically, because it doesn't work with the
    // `proxy` extrinsic. `proxy` doesn't propagate any errors from the proxied call (it captures
    // the error in a ProxyExecuted event), and so `batchAll` doesn't receive any errors to
    // terminate the batch.
    //
    // Even if that did work, there is another issue with `batchAll` if there are multiple calls of
    // the same extrinsic in the batch - there's no way of knowing which of them failed. The
    // `ItemCompleted` events can't be issued, since they're rolled back in light of the error.
    for (index, request) in poll_requests.into_iter().enumerate() {
        // TODO Deal with mixed_balance of zero
        // TODO conviction multiplier
        if let Err(error) = proxy_vote(
            network,
            request.account.clone(),
            poll_index,
            mixing_result.aye,
            mixing_result.balances[index]
        ).await {
            return Err((index, error));
        }
    }

    Ok(())
}

async fn proxy_vote(
    network: &SubstrateNetwork,
    account: AccountId32,
    poll_index: u32,
    aye: bool,
    balance: u128
) -> Result<(), ProxyVoteError> {
    let vote_call = ConvictionVotingCall::vote {
        poll_index,
        vote: AccountVote::Standard {
            vote: Vote(if aye { AYE } else { NAY }),
            balance
        }
    };
    let proxy_result = proxy_call(network, account, RuntimeCall::ConvictionVoting(vote_call)).await;
    if let Err(error) = proxy_result {
        if let ProxyCallError::ProxiedCall(voting_error) = &error {
            let voting_error = voting_error.as_str();
            if voting_error == "InsufficientFunds" {
                return Err(ProxyVoteError::InsufficientFunds);
            } else if voting_error == "NotOngoing" {
                return Err(ProxyVoteError::NotOngoing);
            } else if voting_error == "MaxVotesReached" {
                return Err(ProxyVoteError::MaxVotesReached);
            }
        }
        Err(ProxyVoteError::ProxyCall(error))
    } else {
        Ok(())
    }
}

#[derive(thiserror::Error, Debug)]
enum ProxyVoteError {
    #[error("Too high a balance was provided that the account cannot afford")]
    InsufficientFunds,
    #[error("Poll is not ongoing")]
    NotOngoing,
    #[error("Maximum number of votes for account reached")]
    MaxVotesReached,
    #[error("Proxy call error: {0}")]
    ProxyCall(#[from] ProxyCallError)
}

async fn proxy_remove_vote(
    network: &SubstrateNetwork,
    account: AccountId32,
    poll_index: u32
) -> Result<(), ProxyRemoveVoteError> {
    let call = ConvictionVotingCall::remove_vote { class: None, index: poll_index };
    let proxy_result = proxy_call(network, account, RuntimeCall::ConvictionVoting(call)).await;
    if let Err(error) = proxy_result {
        if let ProxyCallError::ProxiedCall(voting_error) = &error {
            let voting_error = voting_error.as_str();
            if voting_error == "NotVoter" {
                return Err(ProxyRemoveVoteError::NotVoter);
            }
        }
        Err(ProxyRemoveVoteError::ProxyCall(error))
    } else {
        Ok(())
    }
}

#[derive(thiserror::Error, Debug)]
enum ProxyRemoveVoteError {
    #[error("The given account did not vote on the poll")]
    NotVoter,
    #[error("Proxy call error: {0}")]
    ProxyCall(#[from] ProxyCallError)
}

async fn proxy_call(
    network: &SubstrateNetwork,
    real_account: AccountId32,
    call: RuntimeCall
) -> Result<(), ProxyCallError> {
    debug!("Proxy call {:?} on behalf of {}", call, real_account);

    // Extract the pallet name from the call variant. This is to be used later if there is an error
    // from the pallet.
    let pallet_name = format!("{:?}", call).split('(').next().map(|s| s.to_string());

    let proxy_payload = core::metadata::tx()
        .proxy()
        .proxy(account_to_address(real_account), None, call)
        .unvalidated();  // For some reason the hash of the proxy call doesn't match

    let proxy_executed = match network.call_extrinsic(&proxy_payload).await {
        Ok(events) => events.find_first::<ProxyExecuted>()?,
        Err(subxt_error) => {
            if let Runtime(Module(module_error)) = &subxt_error {
                if let Ok(Proxy(NotProxy)) = module_error.as_root_error::<RuntimeError>() {
                    return Err(NotProxyMember);
                }
            };
            return Err(subxt_error.into())
        }
    };

    // The proxy extrinsic is a success even if the proxied call itself fails. This error is 
    // captured in the ProxyExecuted event.
    let Some(ProxyExecuted { result: Err(dispatch_error) }) = proxy_executed else {
        // This also treats the absence of the ProxyExecuted event as a success, which is similar
        // to what TxInBlock::wait_for_success does
        return Ok(());
    };

    let MetadataDispatchError::Module(module_error) = &dispatch_error else {
        return Err(ProxyCallError::Dispatch(dispatch_error));
    };

    // Check if the module error is coming from the proxied pallet and return the error variant name
    pallet_name
        .and_then(|pallet_name| {
            network.api
                .metadata()
                .pallet_by_name(pallet_name.as_str())
                .filter(|p| p.index() == module_error.index)
                .and_then(|p| p.error_variant_by_index(module_error.error[0]))
                .map(|error_variant| error_variant.name.clone())
        })
        .map_or_else(
            || Err(ProxyCallError::Dispatch(dispatch_error)),
            |error_variant| Err(ProxyCallError::ProxiedCall(error_variant))
        )
}

#[derive(thiserror::Error, Debug)]
enum ProxyCallError {
    #[error("Account is not a member of the proxy")]
    NotProxyMember,
    #[error("Error variant from proxied call: {0}")]
    ProxiedCall(String),
    #[error("Problem with proxy call dispatch: {0:?}")]
    Dispatch(MetadataDispatchError),
    #[error("Internal Subxt error: {0}")]
    Subxt(#[from] SubxtError),
}

#[derive(thiserror::Error, Debug)]
enum ServiceError {
    #[error("Client is not a member of the Glove proxy")]
    NotMember,
    #[error("Poll does not exist")]
    UnknownPoll,
    #[error("Proxy call error: {0:?}")]
    Call(#[from] ProxyCallError),
    #[error("Internal Subxt error: {0}")]
    Subxt(#[from] SubxtError),
}

impl IntoResponse for ServiceError {
    fn into_response(self) -> Response {
        match self {
            NotMember => (StatusCode::BAD_REQUEST, self.to_string()),
            UnknownPoll => (StatusCode::BAD_REQUEST, self.to_string()),
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
