use std::{env, io};
use std::io::{BufRead, Write};
use std::str::FromStr;

use base58::ToBase58;
use clap::Parser;
use parity_scale_codec::Decode;
use subxt::{OnlineClient, PolkadotConfig};
use subxt::utils::{AccountId32, MultiAddress};
use subxt_signer::SecretUri;
use subxt_signer::sr25519::Keypair;

use polkadot::conviction_voting::calls::types::Vote;
use polkadot::proxy::calls::types::Proxy;
use polkadot::proxy::events::{ProxyAdded, ProxyExecuted};
use polkadot::runtime_types::pallet_conviction_voting::pallet::Call::vote;
use polkadot::runtime_types::polkadot_runtime::RuntimeCall::ConvictionVoting;

use crate::polkadot::runtime_types::pallet_conviction_voting::vote::AccountVote::Standard;

#[subxt::subxt(runtime_metadata_path = "assets/polkadot-metadata.scale")]
pub mod polkadot {}

const SUBSTRATE_SS58_PREFIX: u8 = 42;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Secret phrase for the Glove proxy account
    #[arg(long)]
    proxy_secret_phrase: String,

    /// URL for the network endpoint.
    ///
    /// See https://wiki.polkadot.network/docs/maintain-endpoints for more information.
    #[arg(long)]
    network_url: String
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let proxy_keypair = Keypair::from_uri(&SecretUri::from_str(&args.proxy_secret_phrase)?)?;
    println!("Proxy address: {}", display_address(&proxy_keypair.public_key().to_address::<()>()));

    let stdin = io::stdin();
    let mut iterator = stdin.lock().lines();
    print!("Enter real account: ");
    io::stdout().flush().unwrap();
    let real_account = iterator.next().unwrap().unwrap();
    print!("Enter poll index: ");
    io::stdout().flush().unwrap();
    let poll_index = iterator.next().unwrap().unwrap().parse::<u32>().unwrap();
    print!("Enter vote: ");
    io::stdout().flush().unwrap();
    let vote = iterator.next().unwrap().unwrap().parse::<u8>().unwrap();
    print!("Enter balance: ");
    io::stdout().flush().unwrap();
    let balance = (iterator.next().unwrap().unwrap().parse::<f64>().unwrap() * 1e12) as u128;

    let api = OnlineClient::<PolkadotConfig>::from_url(args.network_url).await?;

    let real = MultiAddress::<AccountId32, ()>::Id(AccountId32::from_str(&real_account)?);

    let voting_call = ConvictionVoting(vote {
        poll_index,
        vote: Standard {
            vote: polkadot::runtime_types::pallet_conviction_voting::vote::Vote(vote),
            balance,
        }
    });

    let proxy_payload = polkadot::tx().proxy().proxy(real, None, voting_call);
    let proxy_payload = proxy_payload.unvalidated();

    println!("Proxied voting request: {:?}", proxy_payload.call_data());

    let tx_progress = api
        .tx()
        .sign_and_submit_then_watch_default(&proxy_payload, &proxy_keypair)
        .await?;

    println!("Tx submitted, waiting for finalised success...");

    tx_progress
        .wait_for_finalized_success()
        .await?
        .find_first::<ProxyExecuted>()?
        .unwrap()
        .result
        .map_err(|e| {
            // if let DispatchError::Module(module_error) = e {
            //     // TODO Figure out the underlying convition_voting error
            //     format!("{:?}", e)
            // } else {
            //     format!("{:?}", e)
            // }
            format!("{:?}", e)
        })?;

    println!("Voting successful");

    let mut blocks_sub = api.blocks().subscribe_finalized().await?;

    while let Some(block) = blocks_sub.next().await {
        let block = block?;
        let block_number = block.header().number;
        let extrinsics = block.extrinsics().await?;

        println!("New block #{block_number} created! ✨");

        for extrinsic in extrinsics.iter() {
            let extrinsic = extrinsic?;

            let index = extrinsic.index();
            let pallet_name = extrinsic.pallet_name()?;
            let variant_name = extrinsic.variant_name()?;
            let sender = extrinsic
                .address_bytes()
                .and_then(|b| MultiAddress::<AccountId32, ()>::decode(&mut &b[..]).ok())
                .map_or("---".into(), |a| display_address(&a));

            println!("  Extrinsic: #{index} {pallet_name} {variant_name} by {:?}", sender);

            if pallet_name == "ConvictionVoting" && variant_name == "vote" {
                let vote_call = extrinsic.as_extrinsic::<Vote>()?.unwrap();
                println!("    vote on #{} {:?}", vote_call.poll_index, vote_call.vote)
            }

            let events = extrinsic.events().await?;

            if pallet_name == "Proxy" && variant_name == "proxy" {
                let proxied_call = extrinsic.as_extrinsic::<Proxy>()?.unwrap();
                if let ConvictionVoting(vote { poll_index, vote }) = *proxied_call.call {
                    // First check the proxied call was successful
                    if let Ok(Some(ProxyExecuted { result: Ok(_) })) = events.find_first::<ProxyExecuted>() {
                        println!("    proxy vote on behalf of {}: #{:} {:?}", display_address(&proxied_call.real), poll_index, vote)
                    }

                    // match a {
                    //     polkadot::runtime_types::pallet_conviction_voting::pallet::Call::vote => {
                    //     }
                    //     _ => {
                    //
                    //     }
                    // }
                }
            }

            for event in events.iter() {
                let event = event?;
                match (event.pallet_name(), event.variant_name()) {
                    ("Proxy", "ProxyAdded") => {
                        let proxy_added = event.as_event::<ProxyAdded>()?.unwrap();
                        println!("    {:?} assigned {:?} as a {:?} proxy", display_account(&proxy_added.delegator), display_account(&proxy_added.delegatee), proxy_added.proxy_type);
                    }
                    ("Balances", "Transfer") => {
                        let transfer = event.as_event::<polkadot::balances::events::Transfer>()?.unwrap();
                        println!("    {:?} transferred {:?} to {:?}", display_account(&transfer.from), transfer.amount, display_account(&transfer.to));
                    }
                    ("Balances", "Deposit") => {
                        let deposit = event.as_event::<polkadot::balances::events::Deposit>()?.unwrap();
                        println!("    {:?} deposited {:?}", display_account(&deposit.who), deposit.amount);
                    }
                    ("Balances", "Withdraw") => {
                        let deposit = event.as_event::<polkadot::balances::events::Withdraw>()?.unwrap();
                        println!("    {:?} withdrew {:?}", display_account(&deposit.who), deposit.amount);
                    }
                    ("TransactionPayment", "TransactionFeePaid") => {
                        let fee_paid = event.as_event::<polkadot::transaction_payment::events::TransactionFeePaid>()?.unwrap();
                        println!("    {:?} paid {:?} in fees with {:?} tip", display_account(&fee_paid.who), fee_paid.actual_fee, fee_paid.tip);
                    }
                    ("Treasury", "Deposit") => {
                        let deposit = event.as_event::<polkadot::treasury::events::Deposit>()?.unwrap();
                        println!("    {:?} deposited into Treasury", deposit.value);
                    }
                    // ("ConvictionVoting", "Delegated") => {
                    //     let delegated = event.as_event::<polkadot::conviction_voting::events::Delegated>()?.unwrap();
                    //     println!("    {:?} deposited into Treasury", delegated.);
                    // }
                    ("System", "ExtrinsicSuccess") => {
                        let es = event.as_event::<polkadot::system::events::ExtrinsicSuccess>()?.unwrap();
                        println!("    ExtrinsicSuccess {:?}", es.dispatch_info);
                    }
                    ("System", "ExtrinsicFailed") => {
                        let ef = event.as_event::<polkadot::system::events::ExtrinsicFailed>()?.unwrap();
                        println!("    ExtrinsicFailed {:?} {:?}", ef.dispatch_info, ef.dispatch_error);
                    }
                    // ("ParaInclusion", _) => {}
                    _ => {
                        // println!("    {} {}", event.pallet_name(), event.variant_name())
                    }
                }
            }
        }

        println!()
    }

    Ok(())
}

fn display_address(address: &MultiAddress<AccountId32, ()>) -> String {
    match address {
        MultiAddress::Id(id32) => display_account(id32),
        _ => format!("{:?}", address)
    }
}

fn display_account(account: &AccountId32) -> String {
    let mut v = vec![SUBSTRATE_SS58_PREFIX];
    // then push the account ID bytes.
    v.extend(account.0);
    let r = ss58hash(&v);
    v.extend(&r[0..2]);
    v.to_base58()
}

fn ss58hash(data: &[u8]) -> Vec<u8> {
    use blake2::{Blake2b512, Digest};
    const PREFIX: &[u8] = b"SS58PRE";
    let mut ctx = Blake2b512::new();
    ctx.update(PREFIX);
    ctx.update(data);
    ctx.finalize().to_vec()
}