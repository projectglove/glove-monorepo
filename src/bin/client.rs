use anyhow::Result;
use clap::Parser;
use subxt_signer::sr25519::Keypair;

use core::SubstrateNetwork;

mod core;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let network = SubstrateNetwork::connect(&args.network_url, args.secret_phrase).await?;

    Ok(())
}

#[derive(Parser, Debug)]
#[command(version, about = "Glove CLI client")]
struct Args {
    /// Secret phrase for the Glove client account
    #[arg(long, value_parser = glove::parse_secret_phrase)]
    secret_phrase: Keypair,

    /// URL for the network endpoint.
    ///
    /// See https://wiki.polkadot.network/docs/maintain-endpoints for more information.
    #[arg(long)]
    network_url: String
}
