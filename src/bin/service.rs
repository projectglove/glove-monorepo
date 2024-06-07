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
use subxt_signer::sr25519::Keypair;
use tokio::net::TcpListener;
use tokio::spawn;
use tokio::sync::Mutex;
use tokio::time::sleep;
use tower_http::trace::TraceLayer;
use tracing::{debug, info};
use tracing_subscriber::filter::{EnvFilter, LevelFilter};

use core::{is_glove_member, ServiceInfo, SubstrateNetwork, VoteRequest};
use core::account_to_address;
use core::metadata::proxy::events::ProxyExecuted;
use core::metadata::runtime_types::pallet_conviction_voting::pallet::Call as ConvictionVotingCall;
use core::metadata::runtime_types::pallet_conviction_voting::pallet::Error as ConvictionVotingError;
use core::metadata::runtime_types::pallet_conviction_voting::vote::AccountVote;
use core::metadata::runtime_types::pallet_conviction_voting::vote::Vote;
use core::metadata::runtime_types::polkadot_runtime::RuntimeCall;
use core::metadata::runtime_types::sp_runtime::DispatchError;
use core::metadata::runtime_types::sp_runtime::ModuleError;
use core::metadata::storage;
use core::RemoveVoteRequest;
use DispatchError::Module;
use mixing::VoteMixRequest;

mod mixing;
mod core;

const AYE: u8 = 128;
const NAY: u8 = 0;

type GloveResult = Result<(), GloveError>;

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

    async fn begin_mix(&self) -> Vec<VoteRequest> {
        let mut poll = self.inner.lock().await;
        if !poll.pending_mix {
            panic!("Mixing is not needed for poll {}", self.index);
        }
        poll.pending_mix = false;
        poll.requests
            .clone()
            .into_values()
            .sorted_by(|a, b| Ord::cmp(&a.account, &b.account))
            .collect()
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
async fn vote(context: State<Arc<GloveContext>>, Json(payload): Json<VoteRequest>) -> GloveResult {
    let poll_index = payload.poll_index;
    if !is_glove_member(&context.network, payload.account.clone(), context.network.account()).await? {
        return Err(GloveError::NotMember);
    }
    if poll_index >= poll_count(&context.network).await? {
        return Err(GloveError::UnknownPoll);
    }
    let poll = context.state.get_poll(poll_index).await;
    let initiate_mix = poll.add_vote_request(payload).await;
    if initiate_mix {
        schedule_vote_mixing(context.network.clone(), poll);
    }
    Ok(())
}

async fn remove_vote(context: State<Arc<GloveContext>>, Json(payload): Json<RemoveVoteRequest>) -> GloveResult {
    let network = &context.network;
    if !is_glove_member(network, payload.account.clone(), network.account()).await? {
        return Err(GloveError::NotMember);
    }
    let Some(poll) = context.state.get_optional_poll(payload.poll_index).await else {
        return Err(GloveError::PollNotVotedFor);
    };
    let Some(initiate_mix) = poll.remove_vote_request(payload.account.clone()).await else {
        return Err(GloveError::PollNotVotedFor);
    };

    proxy_remove_vote(network, payload.account, payload.poll_index).await?;
    if initiate_mix {
        // TODO Only do the mixing if the votes were previously submitted on-chain
        schedule_vote_mixing(context.network.clone(), poll);
    }
    Ok(())
}

async fn poll_count(network: &SubstrateNetwork) -> Result<u32, GloveError> {
    network.api
        .storage()
        .at_latest().await?
        .fetch(&storage().referenda().referendum_count()).await?
        .ok_or(subxt::Error::Other("Unable to determine poll count".to_string()).into())
}

/// Schedule a background task to mix the votes and submit them on-chain after a delay. Any voting
//  requests which are received in the interim will be included in the mix.
fn schedule_vote_mixing(network: SubstrateNetwork, poll: Poll) {
    debug!("Scheduling vote mixing for poll {}", poll.index);
    spawn(async move {
        // TODO Figure out the policy for submitting on-chain
        sleep(Duration::from_secs(10)).await;
        let poll_requests = poll.begin_mix().await;
        info!("Mixing votes for poll {}:", poll.index);
        poll_requests.iter().for_each(|r| debug!("{:?}", r));
        let result = mix_votes_and_submit_on_chain(&network, poll.index, poll_requests).await;
        debug!("Vote mixing for poll {} completed with {:?}", poll.index, result);
    });
}

async fn mix_votes_and_submit_on_chain(
    network: &SubstrateNetwork,
    poll_index: u32,
    poll_requests: Vec<VoteRequest>
) -> GloveResult {
    // Convert to VoteMixRequests
    let mix_requests = poll_requests
        .iter()
        .map(|r| VoteMixRequest::new(r.aye, r.balance))
        .collect::<Vec<_>>();
    let Some(mixing_result) = mixing::mix_votes(&mix_requests) else {
        // TODO Vote abstain with a minimum balance.
        return Err(GloveError::NetZeroMixVotes)
    };

    debug!("Mixing result: {:?}", mixing_result);

    // We can't use batchAll to submit the votes atomically, because it doesn't work with the proxy
    // extrinic. proxy doesn't propagate any errors from the proxied call (it captures it in a
    // ProxyExecuted event), and so batchAll doesn't receive any errors to terminate the batch.
    for (request, mixed_balance) in poll_requests.into_iter().zip(mixing_result.balances) {
        // TODO Deal with mixed_balance of zero
        // TODO conviction multiplier
        let vote = if mixing_result.aye { AYE } else { NAY };
        // TODO Errors which cause the request to be removed, and mixing done again: NotProxy,
        //  InsufficientBalance,
        // TODO Add another endpoint which a client can query with their nonce to see the status of
        //  of their on-chain vote.
        // TODO If it's a success then it could include the extrinsic coordinates.
        proxy_vote(network, request.account, poll_index, vote, mixed_balance).await?;
    }

    Ok(())
}

async fn proxy_vote(
    network: &SubstrateNetwork,
    account: AccountId32,
    poll_index: u32,
    vote: u8,
    balance: u128
) -> GloveResult {
    let vote_call = ConvictionVotingCall::vote {
        poll_index,
        vote: AccountVote::Standard {
            vote: Vote(vote),
            balance,
        }
    };
    Ok(proxy_conviction_voting_call(network, account, vote_call).await?)
}

async fn proxy_remove_vote(
    network: &SubstrateNetwork,
    account: AccountId32,
    poll_index: u32
) -> GloveResult {
    let remove_vote_call = ConvictionVotingCall::remove_vote { class: None, index: poll_index };
    Ok(proxy_conviction_voting_call(network, account, remove_vote_call).await?)
}

async fn proxy_conviction_voting_call(
    network: &SubstrateNetwork,
    account: AccountId32,
    call: ConvictionVotingCall
) -> GloveResult {
    let proxy_result = proxy_call(network, account, RuntimeCall::ConvictionVoting(call)).await;

    let module_error = match proxy_result {
        Err(GloveError::ModuleCall(module_error)) => module_error,
        Err(error) => return Err(error),
        Ok(_) => return Ok(())
    };

    // Annoyingly, this ModuleError is from the metadata runtime, and not the
    // `subxt::error::dispatch_error` version which has the `as_root_error` function for nicely
    // converting to the pallet-specfic error. Instead, we're forced to do this manual conversion.
    let error = network.api
        .metadata()
        .pallet_by_name("ConvictionVoting")
        .filter(|p| p.index() == module_error.index)
        .and_then(|p| p.error_variant_by_index(module_error.error[0]))
        .and_then(|v| {
            match v.name.as_str() {
                "NotOngoing"        => Some(ConvictionVotingError::NotOngoing),
                "NotVoter"          => Some(ConvictionVotingError::NotVoter),
                "NoPermission"      => Some(ConvictionVotingError::NoPermission),
                "NoPermissionYet"   => Some(ConvictionVotingError::NoPermissionYet),
                "AlreadyDelegating" => Some(ConvictionVotingError::AlreadyDelegating),
                "AlreadyVoting"     => Some(ConvictionVotingError::AlreadyVoting),
                "InsufficientFunds" => Some(ConvictionVotingError::InsufficientFunds),
                "NotDelegating"     => Some(ConvictionVotingError::NotDelegating),
                "Nonsense"          => Some(ConvictionVotingError::Nonsense),
                "MaxVotesReached"   => Some(ConvictionVotingError::MaxVotesReached),
                "ClassNeeded"       => Some(ConvictionVotingError::ClassNeeded),
                "BadClass"          => Some(ConvictionVotingError::BadClass),
                _ => None
            }.map(GloveError::VoteCall)
        })
        .unwrap_or_else(|| GloveError::ModuleCall(module_error));
    Err(error)
}

async fn proxy_call(
    network: &SubstrateNetwork,
    real_account: AccountId32,
    call: RuntimeCall
) -> GloveResult {
    debug!("Proxy call {:?} on behalf of {}", call, real_account);

    let proxy_payload = core::metadata::tx()
        .proxy()
        .proxy(account_to_address(real_account), None, call)
        .unvalidated();  // For some reason the hash of the proxy call doesn't match

    let proxy_executed = network.call_extrinsic(&proxy_payload).await?.find_first::<ProxyExecuted>()?;

    let Some(ProxyExecuted { result: Err(dispatch_error) }) = proxy_executed else {
        // This also treats the absence of the ProxyExecuted event as a success, which is similar
        // to what TxInBlock::wait_for_success does
        return Ok(());
    };

    match dispatch_error {
        Module(module_error) => Err(GloveError::ModuleCall(module_error)),
        _ => Err(GloveError::ProxyCall(dispatch_error))
    }
}

#[derive(thiserror::Error, Debug)]
enum GloveError {
    #[error("Internal Subxt error: {0}")]
    Subxt(#[from] subxt::Error),
    #[error("Problem with proxy call: {0:?}")]
    ProxyCall(DispatchError),
    #[error("Problem with module call: {0:?}")]
    ModuleCall(ModuleError),
    #[error("Problem with vote call: {0:?}")]
    VoteCall(ConvictionVotingError),
    #[error("Client is not a member of the Glove proxy")]
    NotMember,
    #[error("Requested votes netted to zero. This is a temporary issue, which will be implemented as obstain votes")]
    NetZeroMixVotes,
    #[error("Account has not voted for this poll")]
    PollNotVotedFor,
    #[error("Poll does not exist")]
    UnknownPoll
    // #[error("Internal server error")]
    // InternalServerError,
}

impl IntoResponse for GloveError {
    fn into_response(self) -> Response {
        let status_code = match self {
            GloveError::VoteCall(_) => StatusCode::BAD_REQUEST,
            GloveError::NotMember => StatusCode::BAD_REQUEST,
            GloveError::PollNotVotedFor => StatusCode::BAD_REQUEST,
            GloveError::UnknownPoll => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR
        };
        (status_code, self.to_string()).into_response()
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
        assert_eq!(vote_requeats, vec![vote_request]);

        let pending_mix = poll.remove_vote_request(account).await;
        assert_eq!(pending_mix, Some(true));
        let vote_requeats = poll.begin_mix().await;
        assert_eq!(vote_requeats, vec![]);
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
        assert_eq!(vote_requeats, vec![vote_request_2]);
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
        assert_eq!(vote_requeats, vec![vote_request_2.clone()]);

        let pending_mix = poll.add_vote_request(vote_request_1.clone()).await;
        assert_eq!(pending_mix, true);
        let vote_requeats = poll.begin_mix().await;
        assert_eq!(vote_requeats, vec![vote_request_1, vote_request_2]);
    }
}
