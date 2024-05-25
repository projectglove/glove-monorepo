use std::io;
use std::io::{BufRead, Write};
use std::str::FromStr;

use clap::Parser;
use parity_scale_codec::{Decode, Encode};
use sp_core::crypto::{Ss58AddressFormat, Ss58Codec};
use sp_runtime::AccountId32;
use sp_runtime::MultiAddress;
use subxt::{Error, OnlineClient, PolkadotConfig};
use subxt_core::tx::signer::Signer;
use subxt_signer::SecretUri;
use subxt_signer::sr25519::Keypair;

use DispatchError::Module;
use metadata::proxy::events::ProxyExecuted;
use metadata::runtime_types::pallet_conviction_voting::pallet::Call::vote;
use metadata::runtime_types::pallet_conviction_voting::vote::AccountVote::Standard;
use metadata::runtime_types::pallet_conviction_voting::vote::Vote;
use metadata::runtime_types::polkadot_runtime::RuntimeCall::ConvictionVoting;
use metadata::runtime_types::sp_runtime::DispatchError;

#[subxt::subxt(runtime_metadata_path = "assets/polkadot-metadata.scale")]
pub mod metadata {}

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

    let network = NetworkContext::connect(&args.network_url, proxy_keypair).await?;

    println!("Proxy address: {}", network.account_string(&network.proxy_keypair.public_key().0.into()));

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

    let real_account = AccountId32::from_str(&real_account)?;
    network.proxy_vote(real_account, poll_index, vote, balance).await?;

    //
    // metadata::runtime_types::pallet_conviction_voting::pallet::Error::AlreadyDelegating;
    //
    // metadata::runtime_types::pallet_conviction_voting::pallet::Error::

    // pallet_conviction_voting::pallet::Error::de

    Ok(())
}

struct NetworkContext {
    api: OnlineClient<PolkadotConfig>,
    ss58_format: Ss58AddressFormat,
    proxy_keypair: Keypair,
}

impl NetworkContext {
    async fn connect(url: &String, proxy_keypair: Keypair) -> Result<Self, String> {
        let api = OnlineClient::<PolkadotConfig>::from_url(url)
            .await
            .map_err(|e| format!("Unable to connect to network endpoint: {:?}", e))?;
        let ss58_format = api.metadata()
            .pallet_by_name("System")
            .and_then(|p| p.constant_by_name("SS58Prefix"))
            .map(|c| Ss58AddressFormat::custom(c.value()[0] as u16))
            .ok_or("Unable to determine network SS58 format")?;
        Ok(Self { api, ss58_format, proxy_keypair })
    }

    async fn proxy_vote(&self, real_account: AccountId32, poll_index: u32, vote: u8, balance: u128) -> Result<(), Error> {
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
            .sign_and_submit_then_watch_default(&proxy_payload, &self.proxy_keypair).await?
            .wait_for_finalized_success().await?
            .find_first::<ProxyExecuted>()?;

        let Some(ProxyExecuted { result: Err(dispatch_error) }) = proxy_executed else {
            // This also treats the absence of the ProxyExecuted event as a success, which is similar
            // to what TxInBlock::wait_for_success does
            return Ok(());
        };

        match dispatch_error {
            Module(module_error) => {
                let metadata1 = self.api.metadata();
                let conviction_voting_pallet = metadata1.pallet_by_name("ConvictionVoting");
                if conviction_voting_pallet.map_or(false, |p| module_error.index == p.index()) {
                    let error_variant = conviction_voting_pallet.unwrap().error_variant_by_index(module_error.error[0]);
                    if let Some(error_variant) = error_variant {
                        Err(Error::Other(format!("Problem with proxy vote call: {:?}", error_variant)))
                    } else {
                        Err(Error::Other(format!("Problem with proxy vote call: {:?}", module_error)))
                    }
                } else {
                    Err(Error::Other(format!("Problem with proxy vote call: {:?}", module_error)))
                }
            },
            _ => Err(Error::Other(format!("Problem with proxy vote call: {:?}", dispatch_error))),
        }
    }

    fn account_string(&self, account: &AccountId32) -> String {
        account.to_ss58check_with_version(self.ss58_format)
    }
    
    fn address_string(&self, address: &MultiAddressId32) -> String {
        match address {
            MultiAddress::Id(id32) => self.account_string(id32),
            _ => format!("{:?}", address)
        }
    }
}

type MultiAddressId32 = MultiAddress<AccountId32, ()>;
