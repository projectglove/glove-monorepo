use std::io;
use std::io::{BufRead, Write};
use std::str::FromStr;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use futures::future::join_all;
use sp_core::crypto::{Ss58AddressFormat, Ss58Codec};
use sp_runtime::AccountId32;
use strum::EnumString;
use subxt::{OnlineClient, PolkadotConfig};
use subxt_signer::SecretUri;
use subxt_signer::sr25519::Keypair;

use DispatchError::Module;
use metadata::proxy::events::ProxyExecuted;
use metadata::runtime_types::pallet_conviction_voting::pallet::Call::vote;
use metadata::runtime_types::pallet_conviction_voting::vote::AccountVote::Standard;
use metadata::runtime_types::pallet_conviction_voting::vote::Vote;
use metadata::runtime_types::polkadot_runtime::RuntimeCall::ConvictionVoting;
use metadata::runtime_types::sp_runtime::DispatchError;
use mixing::VoteMixRequest;

mod mixing;

#[subxt::subxt(runtime_metadata_path = "assets/polkadot-metadata.scale")]
mod metadata {}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let glove_proxy = GloveProxy::connect(&args.network_url, args.proxy_secret_phrase).await?;

    println!("Proxy address: {}", glove_proxy.account_string(&glove_proxy.keypair.public_key().0.into()));

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
            let Some(request) = parse_vote_request(line.as_str()) else {
                println!("Invalid, try again");
                continue;
            };
            requests.push(request);
        }
    }

    let Some(mixing_result) = mixing::mix_votes(&requests.iter().map(|r| r.1).collect()) else {
        bail!("Net vote result is cancelled out");
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
                Some(glove_proxy.proxy_vote(real_account, poll_index, vote, mixed_balance))
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

fn parse_vote_request(string: &str) -> Option<(AccountId32, VoteMixRequest)> {
    let parts: Vec<&str> = string.split(' ').collect();
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
    let Ok(balance) = parts[2].parse::<f64>().map(|b| (b * 1e12) as u128) else {
        return None;
    };
    Some((real_account, VoteMixRequest::new(aye, balance)))
}


#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Secret phrase for the Glove proxy account
    #[arg(long, value_parser = Args::parse_secret_phrase)]
    proxy_secret_phrase: Keypair,

    /// URL for the network endpoint.
    ///
    /// See https://wiki.polkadot.network/docs/maintain-endpoints for more information.
    #[arg(long)]
    network_url: String
}

impl Args {
    fn parse_secret_phrase(str: &str) -> Result<Keypair> {
        Ok(Keypair::from_uri(&SecretUri::from_str(str)?)?)
    }
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

struct GloveProxy {
    api: OnlineClient<PolkadotConfig>,
    ss58_format: Ss58AddressFormat,
    keypair: Keypair,
}

impl GloveProxy {
    async fn connect(url: &String, keypair: Keypair) -> Result<Self> {
        let api = OnlineClient::<PolkadotConfig>::from_url(url).await
            .with_context(|| "Unable to connect to network endpoint:")?;
        let ss58_format = api.metadata()
            .pallet_by_name("System")
            .and_then(|pallet| pallet.constant_by_name("SS58Prefix"))
            .map(|constant| Ss58AddressFormat::custom(constant.value()[0] as u16))
            .ok_or(anyhow!("Unable to determine network SS58 format"))?;
        Ok(Self { api, ss58_format, keypair })
    }

    async fn proxy_vote(&self, real_account: AccountId32, poll_index: u32, vote: u8, balance: u128) -> Result<()> {
        let voting_call = ConvictionVoting(vote {
            poll_index,
            vote: Standard {
                vote: Vote(vote),
                balance,
            }
        });

        let real_account = subxt_core::utils::AccountId32::from(Into::<[u8; 32]>::into(real_account));
        let proxy_payload = metadata::tx()
            .proxy()
            .proxy(subxt_core::utils::MultiAddress::Id(real_account), None, voting_call)
            .unvalidated();  // Necessary

        let proxy_executed = self.api.tx()
            .sign_and_submit_then_watch_default(&proxy_payload, &self.keypair).await?
            .wait_for_finalized_success().await?
            .find_first::<ProxyExecuted>()?;

        let Some(ProxyExecuted { result: Err(dispatch_error) }) = proxy_executed else {
            // This also treats the absence of the ProxyExecuted event as a success, which is similar
            // to what TxInBlock::wait_for_success does
            return Ok(());
        };

        let Module(module_error) = dispatch_error else {
            bail!("Problem with proxy vote: {:?}", dispatch_error);
        };

        // Extract the underlying ConvictionVoting error
        self.api
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

    fn account_string(&self, account: &AccountId32) -> String {
        account.to_ss58check_with_version(self.ss58_format)
    }
}
