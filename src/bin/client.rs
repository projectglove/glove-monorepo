use anyhow::Result;
use clap::{Parser, Subcommand};
use DispatchError::Module;
use sp_core::crypto::AccountId32;
use subxt::error::DispatchError;
use subxt::Error::Runtime;
use subxt_signer::sr25519::Keypair;

use core::account_to_address;
use core::metadata::runtime_types::pallet_proxy::pallet::Error::Duplicate;
use core::metadata::runtime_types::polkadot_runtime::{ProxyType, RuntimeError};
use core::SubstrateNetwork;
use RuntimeError::Proxy;

mod core;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let network = SubstrateNetwork::connect(&args.network_url, args.secret_phrase).await?;

    match args.command {
        Command::AddProxy { proxy_account } => {
            let add_proxy_call = core::metadata::tx()
                .proxy()
                .add_proxy(account_to_address(proxy_account), ProxyType::Governance, 0)
                .unvalidated();
            match network.call_extrinsic(&add_proxy_call).await {
                Ok(_) => println!("Account added to Glove proxy"),
                Err(Runtime(Module(module_error))) => {
                    match module_error.as_root_error::<RuntimeError>() {
                        Ok(Proxy(Duplicate)) => println!("Account already part of Glove proxy"),
                        _ => return Err(Runtime(Module(module_error)))?
                    }
                },
                Err(e) => return Err(e)?
            };
        }
    }

    Ok(())
}

#[derive(Debug, Parser)]
#[command(version, about = "Glove CLI client")]
struct Args {
    /// Secret phrase for the Glove client account
    #[arg(long, value_parser = core::parse_secret_phrase)]
    secret_phrase: Keypair,

    /// URL for the network endpoint.
    ///
    /// See https://wiki.polkadot.network/docs/maintain-endpoints for more information.
    #[arg(long)]
    network_url: String,

    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    AddProxy {
        // TODO This shouldn't really be needed. The network_url arg should be glove_service_url
        //  and that should have a metatdata end-point which returns the Glove proxy account and the
        //  network URL the service is using.
        /// The Glove proxy account to be added to
        proxy_account: AccountId32
    }
}
