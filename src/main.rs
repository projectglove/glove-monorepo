use std::io;
use std::io::{BufRead, Write};
use std::str::FromStr;

use anyhow::{anyhow, bail, Result};
use bigdecimal::num_traits::Pow;
use clap::Parser;
use futures::future::join_all;
use sp_runtime::AccountId32;
use strum::EnumString;
use subxt_signer::sr25519::Keypair;

use DispatchError::Module;
use glove::metadata::proxy::events::ProxyExecuted;
use glove::metadata::runtime_types::pallet_conviction_voting::pallet::Call::vote;
use glove::metadata::runtime_types::pallet_conviction_voting::vote::AccountVote::Standard;
use glove::metadata::runtime_types::pallet_conviction_voting::vote::Vote;
use glove::metadata::runtime_types::polkadot_runtime::RuntimeCall::ConvictionVoting;
use glove::metadata::runtime_types::sp_runtime::DispatchError;
use glove::SubstrateNetwork;
use mixing::VoteMixRequest;

mod mixing;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let network = SubstrateNetwork::connect(&args.network_url, args.proxy_secret_phrase).await?;

    println!("Proxy address: {}", network.account_string(&network.keypair.public_key().0.into()));

    let mut stdin_lines = io::stdin().lock().lines();

    print!("Poll index: ");
    io::stdout().flush().unwrap();
    let poll_index = stdin_lines.next().unwrap().unwrap().parse::<u32>().unwrap();

    let mut requests = Vec::new();
    loop {
        print!("|<real account> <aye|nay> <balance>|mix: ");
        io::stdout().flush().unwrap();
        let line = stdin_lines.next().unwrap().unwrap();
        if line == "mix" {
            break;
        } else {
            let Some(request) = parse_vote_request(line.as_str(), network.token_decimals) else {
                println!("Invalid, try again");
                continue;
            };
            requests.push(request);
        }
    }

    let Some(mixing_result) = mixing::mix_votes(&requests.iter().map(|r| r.1).collect()) else {
        // TODO Vote abstain with a minimum balance.
        bail!("Voting requests cancel each other out");
    };

    println!("Net mixing result: {:?}", mixing_result);

    let proxy_vote_futures = requests
        .into_iter()
        .enumerate()
        .filter_map(|(index, (real_account, _))| {
            let mixed_balance = mixing_result.balances[index];
            if mixed_balance == 0 {
                None
            } else {
                let vote = if mixing_result.aye { AYE } else { NAY };
                Some(proxy_vote(&network, real_account, poll_index, vote, mixed_balance))
            }
        })
        .collect::<Vec<_>>();

    // TODO Use batchAll to ensure the votes are committed together atomically
    // TODO Retry on NotProxy error with the offending request removed.
    join_all(proxy_vote_futures).await
        .into_iter()
        .collect::<Result<_, _>>()?;

    Ok(())
}

const AYE: u8 = 128;
const NAY: u8 = 0;

fn parse_vote_request(str: &str, decimals: u8) -> Option<(AccountId32, VoteMixRequest)> {
    let parts = str.split(' ').collect::<Vec<_>>();
    if parts.len() != 3 {
        return None;
    }
    let Ok(real_account) = AccountId32::from_str(parts[0]) else {
        return None;
    };
    let aye = match parts[1] {
        "aye" => true,
        "a" => true,
        "nay" => false,
        "n" => false,
        _ => return None
    };
    let Ok(balance) = parts[2].parse::<f64>().map(|b| (b * 10f64.pow(decimals)) as u128) else {
        return None;
    };
    Some((real_account, VoteMixRequest::new(aye, balance)))
}


#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Secret phrase for the Glove proxy account
    #[arg(long, value_parser = glove::parse_secret_phrase)]
    proxy_secret_phrase: Keypair,

    /// URL for the network endpoint.
    ///
    /// See https://wiki.polkadot.network/docs/maintain-endpoints for more information.
    #[arg(long)]
    network_url: String
}

/// See https://docs.rs/pallet-conviction-voting/latest/pallet_conviction_voting/pallet/enum.Error.html
#[derive(thiserror::Error, strum::Display, EnumString, Debug)]
enum ConvictionVotingError {
    NotOngoing,
    NotVoter,
    NoPermission,
    NoPermissionYet,
    AlreadyDelegating,
    AlreadyVoting,
    InsufficientFunds,
    NotDelegating,
    Nonsense,
    MaxVotesReached,
    ClassNeeded,
    BadClass,
}

async fn proxy_vote(
    network: &SubstrateNetwork,
    real_account: AccountId32,
    poll_index: u32,
    vote: u8,
    balance: u128
) -> Result<()> {
    let voting_call = ConvictionVoting(vote {
        poll_index,
        vote: Standard {
            vote: Vote(vote),
            balance,
        }
    });

    // Annoyingly, subxt uses a different AccountId32 to sp-core.
    let real_account = subxt_core::utils::AccountId32::from(Into::<[u8; 32]>::into(real_account));
    let proxy_payload = glove::metadata::tx()
        .proxy()
        .proxy(subxt_core::utils::MultiAddress::Id(real_account), None, voting_call)
        .unvalidated();  // For some reason the hash of the proxy call doesn't match

    let proxy_executed = network.call_extrinsic(&proxy_payload).await?
        .find_first::<ProxyExecuted>()?;

    let Some(ProxyExecuted { result: Err(dispatch_error) }) = proxy_executed else {
        // This also treats the absence of the ProxyExecuted event as a success, which is similar
        // to what TxInBlock::wait_for_success does
        return Ok(());
    };

    // Extract the underlying ConvictionVoting error

    let Module(module_error) = dispatch_error else {
        bail!("Problem with proxy vote: {:?}", dispatch_error);
    };

    network.api
        .metadata()
        .pallet_by_name("ConvictionVoting")
        .filter(|p| p.index() == module_error.index)
        .and_then(|p| p.error_variant_by_index(module_error.error[0]))
        .and_then(|v| ConvictionVotingError::try_from(v.name.as_str()).ok())
        .map_or_else(
            || Err(anyhow!("Problem with proxy vote: {:?}", module_error)),
            |e| Err(e.into())
        )
}
