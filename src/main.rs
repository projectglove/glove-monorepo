use std::io;
use std::io::{BufRead, Write};
use std::str::FromStr;

use clap::Parser;
use parity_scale_codec::Decode;
use sp_core::crypto::{Ss58AddressFormat, Ss58Codec};
use sp_core::crypto::AccountId32 as SpAccountId32;
use subxt::{OnlineClient, PolkadotConfig};
use subxt::utils::AccountId32 as SubxtAccountId32;
use subxt::utils::MultiAddress;
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

    let proxy_keypair = SecretUri::from_str(&args.proxy_secret_phrase)
        .map_err(|e| format!("Invalid proxy secret phrase: {:?}", e))
        .and_then(|uri| Keypair::from_uri(&uri).map_err(|e| format!("Invalid proxy secret phrase: {:?}", e)))?;

    let network = NetworkContext::connect(&args.network_url).await?;

    println!("Proxy address: {}", network.address_string(&proxy_keypair.public_key().to_address::<()>()));

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


    let real = MultiAddressId32::Id(SubxtAccountId32::from_str(&real_account)?);

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

    let tx_progress = network.api
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

    let mut blocks_sub = network.api.blocks().subscribe_finalized().await?;

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
                .and_then(|b| MultiAddress::<SubxtAccountId32, ()>::decode(&mut &b[..]).ok())
                .map_or("---".into(), |a| network.address_string(&a));

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
                        println!("    proxy vote on behalf of {}: #{:} {:?}", network.address_string(&proxied_call.real), poll_index, vote)
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
                        println!("    {:?} assigned {:?} as a {:?} proxy", network.subxt_account_string(&proxy_added.delegator), network.subxt_account_string(&proxy_added.delegatee), proxy_added.proxy_type);
                    }
                    ("Balances", "Transfer") => {
                        let transfer = event.as_event::<polkadot::balances::events::Transfer>()?.unwrap();
                        println!("    {:?} transferred {:?} to {:?}", network.subxt_account_string(&transfer.from), transfer.amount, network.subxt_account_string(&transfer.to));
                    }
                    ("Balances", "Deposit") => {
                        let deposit = event.as_event::<polkadot::balances::events::Deposit>()?.unwrap();
                        println!("    {:?} deposited {:?}", network.subxt_account_string(&deposit.who), deposit.amount);
                    }
                    ("Balances", "Withdraw") => {
                        let deposit = event.as_event::<polkadot::balances::events::Withdraw>()?.unwrap();
                        println!("    {:?} withdrew {:?}", network.subxt_account_string(&deposit.who), deposit.amount);
                    }
                    ("TransactionPayment", "TransactionFeePaid") => {
                        let fee_paid = event.as_event::<polkadot::transaction_payment::events::TransactionFeePaid>()?.unwrap();
                        println!("    {:?} paid {:?} in fees with {:?} tip", network.subxt_account_string(&fee_paid.who), fee_paid.actual_fee, fee_paid.tip);
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

struct NetworkContext {
    api: OnlineClient<PolkadotConfig>,
    ss58_format: Ss58AddressFormat
}

impl NetworkContext {
    async fn connect(url: &String) -> Result<Self, String> {
        let api = OnlineClient::<PolkadotConfig>::from_url(url)
            .await
            .map_err(|e| format!("Unable to connect to network endpoint: {:?}", e))?;
        let ss58_format = api.metadata()
            .pallet_by_name("System")
            .and_then(|p| p.constant_by_name("SS58Prefix"))
            .map(|c| Ss58AddressFormat::custom(c.value()[0] as u16))
            .ok_or("Unable to determine network SS58 format")?;
        Ok(Self { api, ss58_format })
    }

    fn subxt_account_string(&self, account: &SubxtAccountId32) -> String {
        self.account_string(&SpAccountId32::new(account.0))
    }

    fn account_string(&self, account: &SpAccountId32) -> String {
        account.to_ss58check_with_version(self.ss58_format)
    }
    
    fn address_string(&self, address: &MultiAddressId32) -> String {
        match address {
            MultiAddress::Id(id32) => self.subxt_account_string(id32),
            _ => format!("{:?}", address)
        }
    }
}

type MultiAddressId32 = MultiAddress<SubxtAccountId32, ()>;
