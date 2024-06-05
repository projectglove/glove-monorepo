use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Json, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Router;
use axum::routing::post;
use clap::Parser;
use itertools::Itertools;
use sp_runtime::AccountId32;
use subxt_signer::sr25519::Keypair;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use core::{SubstrateNetwork, VoteRequest};
use core::account_to_address;
use core::metadata::proxy::events::ProxyExecuted;
use core::metadata::runtime_types::pallet_conviction_voting::pallet::Call as ConvictionVotingCall;
use core::metadata::runtime_types::pallet_conviction_voting::pallet::Error as ConvictionVotingError;
use core::metadata::runtime_types::pallet_conviction_voting::vote::AccountVote;
use core::metadata::runtime_types::pallet_conviction_voting::vote::Vote;
use core::metadata::runtime_types::polkadot_runtime::RuntimeCall;
use core::metadata::runtime_types::sp_runtime::DispatchError;
use core::metadata::runtime_types::sp_runtime::ModuleError;
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
    let args = Args::parse();

    let network = SubstrateNetwork::connect(&args.network_url, args.proxy_secret_phrase).await?;

    let glove_context = Arc::new(GloveContext {
        network,
        state: GloveState::default()
    });

    let router = Router::new()
        .route("/vote", post(vote))
        .route("/remove-vote", post(remove_vote))
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
    polls: Mutex<HashMap<u32, HashMap<AccountId32, VoteRequest>>>
}

impl GloveState {
    async fn add_vote_request(&self, vote_request: VoteRequest) -> Vec<VoteRequest> {
        let mut polls = self.polls.lock().await;
        let poll_index = vote_request.poll_index;
        let poll_requests = polls.entry(poll_index).or_default();
        poll_requests.insert(vote_request.account.clone(), vote_request);
        Self::map_to_vec(poll_index, poll_requests)
    }

    async fn remove_vote_request(&self, poll_index: u32, account: AccountId32) -> Option<Vec<VoteRequest>> {
        let mut polls = self.polls.lock().await;
        let poll_requests = polls.get_mut(&poll_index)?;
        poll_requests.remove(&account)?;
        // TODO Fix "cannot borrow `polls` as mutable more than once at a time"
        // if poll_requests.is_empty() {
        //     polls.remove(&poll_index);
        // }
        Some(Self::map_to_vec(poll_index, poll_requests))
    }

    fn map_to_vec(poll_index: u32, poll_requests: &HashMap<AccountId32, VoteRequest>) -> Vec<VoteRequest> {
        println!("Requests for poll {}", poll_index);
        poll_requests.values().for_each(|r| println!("{:?}", r));
        println!();
        poll_requests.clone().into_values().sorted_by(|a, b| Ord::cmp(&a.account, &b.account)).collect()
    }
}

// TODO Reject for polls which are known to have closed
// TODO Reject for accounts which are not proxied to the GloveProxy
// TODO Reject for zero balance
async fn vote(context: State<Arc<GloveContext>>, Json(payload): Json<VoteRequest>) -> GloveResult {
    let poll_index = payload.poll_index;
    let poll_requests = context.state.add_vote_request(payload).await;
    // TODO Do mixing and submitting on-chain at correct time(s), rather than each time a request is
    //  submitted
    mix_votes_and_submit_on_chain(&context.network, poll_index, poll_requests).await?;
    Ok(())
}

async fn remove_vote(context: State<Arc<GloveContext>>, Json(payload): Json<RemoveVoteRequest>) -> GloveResult {
    let poll_requests = context.state
        .remove_vote_request(payload.poll_index, payload.account.clone()).await
        .ok_or(GloveError::PollNotVotedFor)?;
    // TODO Only do the mixing if the votes were previously submitted on-chain
    proxy_remove_vote(&context.network, payload.account, payload.poll_index).await?;
    if !poll_requests.is_empty() {
        // TODO Do this in the background; there's no need to block the client as they're no longer
        //  part of the mixing
        mix_votes_and_submit_on_chain(&context.network, payload.poll_index, poll_requests).await?;
    }
    Ok(())
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

    // We can't use batchAll to submit the votes atomically, because it doesn't work with the proxy
    // extrinic. proxy doesn't propagate any errors from the proxied call (it captures it in a
    // ProxyExecuted event), and so batchAll doesn't receive any errors to terminate the batch.
    for (request, mixed_balance) in poll_requests.into_iter().zip(mixing_result.balances) {
        // TODO Deal with mixed_balance of zero
        // TODO conviction multiplier
        let vote = if mixing_result.aye { AYE } else { NAY };
        // TODO Errors which cause the request to be removed, and mixing done again: NotProxy,
        //  InsufficientBalance,
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

    // Extract the underlying ConvictionVoting error
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
    #[error("Requested votes netted to zero. This is a temporary issue, which will be implemented as obstain votes")]
    NetZeroMixVotes,
    #[error("Account has not voted for this poll")]
    PollNotVotedFor
    // #[error("Internal server error")]
    // InternalServerError,
}

impl IntoResponse for GloveError {
    fn into_response(self) -> Response {
        let status_code = match self {
            GloveError::VoteCall(_) => StatusCode::BAD_REQUEST,
            GloveError::PollNotVotedFor => StatusCode::BAD_REQUEST,
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

        let poll_requests = glove_state.add_vote_request(vote_request.clone()).await;
        assert_eq!(poll_requests, vec![vote_request]);

        let poll_requests = glove_state.remove_vote_request(1, account).await;
        assert_eq!(poll_requests, Some(vec![]));
    }

    #[tokio::test]
    async fn remove_from_non_existent_poll() {
        let glove_state = GloveState::default();
        let account = AccountId32::from([1; 32]);

        let poll_requests = glove_state.remove_vote_request(1, account).await;
        assert_eq!(poll_requests, None);
    }

    #[tokio::test]
    async fn remove_non_existent_account_within_poll() {
        let glove_state = GloveState::default();
        let account_1 = AccountId32::from([1; 32]);
        let account_2 = AccountId32::from([2; 32]);
        let vote_request = VoteRequest::new(account_1.clone(), 1, true, 10);

        glove_state.add_vote_request(vote_request.clone()).await;

        let poll_requests = glove_state.remove_vote_request(1, account_2).await;
        assert_eq!(poll_requests, None);
    }

    #[tokio::test]
    async fn replace_vote() {
        let glove_state = GloveState::default();
        let account = AccountId32::from([1; 32]);
        let vote_request_1 = VoteRequest::new(account.clone(), 1, true, 10);
        let vote_request_2 = VoteRequest::new(account.clone(), 1, true, 20);

        glove_state.add_vote_request(vote_request_1.clone()).await;
        let poll_requests = glove_state.add_vote_request(vote_request_2.clone()).await;
        assert_eq!(poll_requests, vec![vote_request_2]);
    }

    #[tokio::test]
    async fn two_votes_in_poll_returned_in_order() {
        let glove_state = GloveState::default();
        let account_1 = AccountId32::from([1; 32]);
        let account_2 = AccountId32::from([2; 32]);
        let vote_request_1 = VoteRequest::new(account_1.clone(), 1, true, 10);
        let vote_request_2 = VoteRequest::new(account_2.clone(), 1, false, 20);

        glove_state.add_vote_request(vote_request_2.clone()).await;
        let poll_requests = glove_state.add_vote_request(vote_request_1.clone()).await;
        assert_eq!(poll_requests, vec![vote_request_1, vote_request_2]);
    }

    #[tokio::test]
    async fn two_polls_voted_for_by_same_account() {
        let glove_state = GloveState::default();
        let account = AccountId32::from([1; 32]);
        let vote_request_1 = VoteRequest::new(account.clone(), 1, true, 10);
        let vote_request_2 = VoteRequest::new(account.clone(), 2, false, 20);

        let poll_requests = glove_state.add_vote_request(vote_request_1.clone()).await;
        assert_eq!(poll_requests, vec![vote_request_1]);

        let poll_requests = glove_state.add_vote_request(vote_request_2.clone()).await;
        assert_eq!(poll_requests, vec![vote_request_2]);
    }
}
