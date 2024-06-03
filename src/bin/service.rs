use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use axum::extract::{Json, State};
use axum::http::StatusCode;
use axum::Router;
use axum::routing::post;
use clap::Parser;
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
use mixing::VoteMixRequest;

use crate::core::metadata::runtime_types::polkadot_runtime::RuntimeCall;
use crate::core::metadata::runtime_types::sp_runtime::ModuleError;

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

#[tokio::main]
async fn main() -> Result<()> {
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
    polls: Mutex<HashMap<u32, Vec<VoteRequest>>>
}

impl GloveState {
    async fn add_vote_request(&self, vote_request: VoteRequest) -> Vec<VoteRequest> {
        let mut polls = self.polls.lock().await;
        let poll_index = vote_request.poll_index;
        let requests = polls.entry(poll_index).or_default();
        let existing_index = requests.iter()
            .enumerate()
            .find_map(|(index, r)| (r.account == vote_request.account).then_some(index));
        match existing_index {
            Some(index) => requests[index] = vote_request,
            None => requests.push(vote_request),
        }
        println!("Requests for poll {}", poll_index);
        requests.iter().for_each(|r| println!("{:?}", r));
        println!();
        requests.clone()
    }
}

// TODO Reject for polls which are known to have closed
// TODO Reject for accounts which are not proxied to the GloveProxy
// TODO Reject for zero balance
// #[debug_handler]
async fn vote(state: State<Arc<GloveState>>, Json(payload): Json<VoteRequest>) -> Result<(), StatusCode> {
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
) -> Result<(), StatusCode> {
    // Convert to VoteMixRequests
    let mix_requests = poll_requests
        .iter()
        .map(|r| VoteMixRequest::new(r.aye, r.balance))
        .collect::<Vec<_>>();
    let Some(mixing_result) = mixing::mix_votes(&mix_requests) else {
        // TODO Vote abstain with a minimum balance.
        return Err(StatusCode::INTERNAL_SERVER_ERROR)
    };

    // TODO Use batchAll to ensure the votes are committed together atomically
    for (request, mixed_balance) in poll_requests.into_iter().zip(mixing_result.balances) {
        // TODO Deal with mixed_balance of zero
        // TODO conviction multiplier
        let vote = if mixing_result.aye { AYE } else { NAY };
        let result = proxy_vote(network, request.account, poll_index, vote, mixed_balance).await;
        // TODO Retry on NotProxy error with the offending request removed.
        if let Err(e) = result {
            return Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }

    Ok(())
}

async fn proxy_vote(
    network: &SubstrateNetwork,
    account: AccountId32,
    poll_index: u32,
    vote: u8,
    balance: u128
) -> Result<()> {
    let voting_call = ConvictionVoting(vote_call {
        poll_index,
        vote: Standard {
            vote: Vote(vote),
            balance,
        }
    });

    let Err(anyhow) = proxy_call(network, account, voting_call).await else {
        return Ok(());
    };

    let Some(GloveError::ModuleCall(module_error)) = anyhow.downcast_ref::<GloveError>() else {
        return Err(anyhow);
    };

    // Extract the underlying ConvictionVoting error
    network.api
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
            }
        })
        .map_or_else(|| Err(anyhow), |e| Err(GloveError::VoteCall(e).into()))
}

async fn proxy_call(
    network: &SubstrateNetwork,
    account: AccountId32,
    call: RuntimeCall
) -> Result<()> {
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
        Module(module_error) => Err(GloveError::ModuleCall(module_error).into()),
        _ => Err(GloveError::ProxyCall(dispatch_error).into())
    }
}

#[derive(thiserror::Error, Debug)]
enum GloveError {
    #[error("Problem with proxy call: {0:?}")]
    ProxyCall(DispatchError),
    #[error("Problem with module call: {0:?}")]
    ModuleCall(ModuleError),
    #[error("Problem with vote call: {0:?}")]
    VoteCall(ConvictionVotingError),
    // #[error("Problem with mixing votes")]
    // MixingVotes,
    // #[error("Internal server error")]
    // InternalServerError,
}
