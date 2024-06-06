use anyhow::Result;
use clap::{Parser, Subcommand};
use DispatchError::Module;
use subxt::error::DispatchError;
use subxt::Error::Runtime;
use subxt_signer::sr25519::Keypair;

use core::{account_to_address, is_glove_member};
use core::metadata::runtime_types::pallet_proxy::pallet::Error::Duplicate;
use core::metadata::runtime_types::polkadot_runtime::{ProxyType, RuntimeError};
use core::ServiceInfo;
use core::SubstrateNetwork;
use RuntimeError::Proxy;

mod core;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let service_info = reqwest::get(format!("{}/info", &args.glove_url)).await?.
        json::<ServiceInfo>().await?;

    let network = SubstrateNetwork::connect(service_info.network_url.clone(), args.secret_phrase).await?;

    match args.command {
        Command::JoinGlove => {
            let message = join_glove(&service_info, &network).await?;
            println!("{}", message);
        }
    }

    Ok(())
}

async fn join_glove(service_info: &ServiceInfo, network: &SubstrateNetwork) -> Result<String, subxt::Error> {
    if is_glove_member(network, network.account(), service_info.proxy_account.clone()).await? {
        return Ok("Account already part of Glove proxy".to_string());
    }
    let add_proxy_call = core::metadata::tx()
        .proxy()
        .add_proxy(account_to_address(service_info.proxy_account.clone()), ProxyType::Governance, 0)
        .unvalidated();
    match network.call_extrinsic(&add_proxy_call).await {
        Ok(_) => Ok("Account added to Glove proxy".to_string()),
        Err(Runtime(Module(module_error))) => {
            match module_error.as_root_error::<RuntimeError>() {
                // Unlikely, but just in case
                Ok(Proxy(Duplicate)) => Ok("Account already part of Glove proxy".to_string()),
                _ => Err(Runtime(Module(module_error)))
            }
        },
        Err(e) => Err(e)
    }
}

#[derive(Debug, Parser)]
#[command(version, about = "Glove CLI client")]
struct Args {
    /// Secret phrase for the Glove client account
    #[arg(long, value_parser = core::parse_secret_phrase)]
    secret_phrase: Keypair,

    /// The URL of the Glove service
    #[arg(long)]
    glove_url: String,

    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    JoinGlove
    // TODO LeaveGlove, which removes the account from the proxy and also remotes any active votes
}
