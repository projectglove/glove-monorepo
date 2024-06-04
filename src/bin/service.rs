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
use core::metadata::proxy::events::ProxyExecuted;
use core::metadata::runtime_types::pallet_conviction_voting::pallet::Call::vote as vote_call;
use core::metadata::runtime_types::pallet_conviction_voting::pallet::Error as ConvictionVotingError;
use core::metadata::runtime_types::pallet_conviction_voting::vote::AccountVote::Standard;
use core::metadata::runtime_types::pallet_conviction_voting::vote::Vote;
use core::metadata::runtime_types::polkadot_runtime::RuntimeCall::ConvictionVoting;
use core::metadata::runtime_types::sp_runtime::DispatchError;
use DispatchError::Module;
use GloveError::{ModuleCall, VoteCall};
use mixing::VoteMixRequest;

use crate::core::metadata::runtime_types::polkadot_runtime::RuntimeCall;
use crate::core::metadata::runtime_types::sp_runtime::ModuleError;

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

    let glove_state = Arc::new(GloveState {
        network,
        polls: Mutex::new(HashMap::new())
    });

    let router = Router::new()
        .route("/vote", post(vote))
        .with_state(glove_state);
    let listener = TcpListener::bind("localhost:8080").await?;
    axum::serve(listener, router).await?;

    Ok(())
}

struct GloveState {
    network: SubstrateNetwork,
    polls: Mutex<HashMap<u32, HashMap<AccountId32, VoteRequest>>>
}

impl GloveState {
    async fn add_vote_request(&self, vote_request: VoteRequest) -> Vec<VoteRequest> {
        let mut polls = self.polls.lock().await;
        let poll_index = vote_request.poll_index;
        let poll_requests = polls.entry(poll_index).or_default();
        poll_requests.insert(vote_request.account.clone(), vote_request);
        println!("Requests for poll {}", poll_index);
        poll_requests.values().for_each(|r| println!("{:?}", r));
        println!();
        poll_requests.clone().into_values().sorted_by(|a, b| Ord::cmp(&a.account, &b.account)).collect()
    }

    async fn remove_vote_request(&self, poll_index: u32, account: AccountId32) -> Option<VoteRequest> {
        let mut polls = self.polls.lock().await;
        let poll_requests = polls.get_mut(&poll_index)?;
        let removed = poll_requests.remove(&account);
        if poll_requests.is_empty() {
            polls.remove(&poll_index);
        }
        removed
    }
}

// TODO Reject for polls which are known to have closed
// TODO Reject for accounts which are not proxied to the GloveProxy
// TODO Reject for zero balance
// #[debug_handler]
async fn vote(state: State<Arc<GloveState>>, Json(payload): Json<VoteRequest>) -> GloveResult {
    let poll_index = payload.poll_index;
    let poll_requests = state.add_vote_request(payload).await;
    // TODO Do mixing and submitting on-chain at correct time(s), rather than each time a request is
    //  submitted
    mix_votes_and_submit_on_chain(&state.network, poll_index, poll_requests).await?;
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

    for (request, mixed_balance) in poll_requests.into_iter().zip(mixing_result.balances) {
        // TODO Deal with mixed_balance of zero
        // TODO conviction multiplier
        let vote = if mixing_result.aye { AYE } else { NAY };
        // TODO Use batchAll to ensure the votes are committed together atomically
        // TODO Retry on NotProxy error with the offending request removed.
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
    let voting_call = ConvictionVoting(vote_call {
        poll_index,
        vote: Standard {
            vote: Vote(vote),
            balance,
        }
    });

    let module_error = match proxy_call(network, account, voting_call).await {
        Err(ModuleCall(module_error)) => module_error,
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
                "NotOngoing"        => Some(VoteCall(ConvictionVotingError::NotOngoing)),
                "NotVoter"          => Some(VoteCall(ConvictionVotingError::NotVoter)),
                "NoPermission"      => Some(VoteCall(ConvictionVotingError::NoPermission)),
                "NoPermissionYet"   => Some(VoteCall(ConvictionVotingError::NoPermissionYet)),
                "AlreadyDelegating" => Some(VoteCall(ConvictionVotingError::AlreadyDelegating)),
                "AlreadyVoting"     => Some(VoteCall(ConvictionVotingError::AlreadyVoting)),
                "InsufficientFunds" => Some(VoteCall(ConvictionVotingError::InsufficientFunds)),
                "NotDelegating"     => Some(VoteCall(ConvictionVotingError::NotDelegating)),
                "Nonsense"          => Some(VoteCall(ConvictionVotingError::Nonsense)),
                "MaxVotesReached"   => Some(VoteCall(ConvictionVotingError::MaxVotesReached)),
                "ClassNeeded"       => Some(VoteCall(ConvictionVotingError::ClassNeeded)),
                "BadClass"          => Some(VoteCall(ConvictionVotingError::BadClass)),
                _ => None
            }
        })
        .unwrap_or_else(|| ModuleCall(module_error));
        Err(error)
}

async fn proxy_call(
    network: &SubstrateNetwork,
    account: AccountId32,
    call: RuntimeCall
) -> GloveResult {
    // Annoyingly, subxt uses a different AccountId32 to sp-core.
    let account = subxt_core::utils::AccountId32::from(Into::<[u8; 32]>::into(account));

    let proxy_payload = core::metadata::tx()
        .proxy()
        .proxy(subxt_core::utils::MultiAddress::Id(account), None, call)
        .unvalidated();  // For some reason the hash of the proxy call doesn't match

    let proxy_executed = network.call_extrinsic(&proxy_payload).await?.find_first::<ProxyExecuted>()?;

    let Some(ProxyExecuted { result: Err(dispatch_error) }) = proxy_executed else {
        // This also treats the absence of the ProxyExecuted event as a success, which is similar
        // to what TxInBlock::wait_for_success does
        return Ok(());
    };

    match dispatch_error {
        Module(module_error) => Err(ModuleCall(module_error)),
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
    // #[error("Internal server error")]
    // InternalServerError,
}

impl IntoResponse for GloveError {
    fn into_response(self) -> Response {
        let status_code = match self {
            VoteCall(_) => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR
        };
        (status_code, self.to_string()).into_response()
    }
}
