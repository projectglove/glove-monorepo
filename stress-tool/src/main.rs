use std::io;
use std::io::Write;
use std::sync::{Arc, mpsc, Mutex};
use std::thread::available_parallelism;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use rand::{Rng, thread_rng};
use reqwest::{Client, Url};
use sp_runtime::AccountId32;
use tokio::spawn;

use client::{node_endpoint, url_with_path};
use client_interface::{parse_secret_phrase, ServiceInfo, SubstrateNetwork};
use client_interface::metadata::referenda::storage::types::referendum_info_for::ReferendumInfoFor;
use client_interface::subscan::Subscan;
use common::ExtrinsicLocation;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    println!("THIS IS A GLOVE STRESS TESTING TOOL AND IS ONLY INTENDED FOR TEST NETWORKS");
    match args.command {
        Command::JoinGlove(cmd) => join_glove(args.glove_url, cmd).await?,
        Command::Vote(cmd) => vote(args.glove_url, cmd).await?,
        Command::Extrinsic(ref cmd) => extrinsic(cmd.id, args).await?
    }
    Ok(())
}

async fn join_glove(glove_url: Url, cmd: JoinGloveCmd) -> Result<()> {
    let (sender, receiver) = mpsc::channel();
    let shared_derived_accounts = Arc::new(Mutex::new(cmd.accounts_args.derived_accounts()?));
    let parallelism = cmd.accounts_args.parallelism()?;

    for _ in 0..parallelism {
        let shared_derived_accounts = shared_derived_accounts.clone();
        let sender = sender.clone();
        let glove_url = glove_url.clone();
        spawn(async move {
            loop {
                let derived_account = {
                    let mut shared_derived_accounts = shared_derived_accounts.lock().unwrap();
                    shared_derived_accounts.pop()
                };
                let Some((account_index, secret_phrase, account)) = derived_account else {
                    // Signal the thread is done
                    sender.send(()).unwrap();
                    break;
                };
                let output = client::run(vec![
                    "client",
                    &format!("-g={}", glove_url),
                    "join-glove",
                    &format!("--secret-phrase={}", secret_phrase),
                ]).await.unwrap();
                println!("{}. {}: {}", account_index, account, output);
            }
        });
    }

    // Wait for all the threads to finish
    for _ in 0..parallelism {
        receiver.recv()?;
    }

    Ok(())
}

async fn vote(glove_url: Url, cmd: VoteCmd) -> Result<()>{
    let poll_indices = if cmd.poll_index.is_empty() {
        let service_info = Client::new()
            .get(url_with_path(&glove_url, "info"))
            .send().await?
            .error_for_status()?
            .json::<ServiceInfo>().await?;
        let network = SubstrateNetwork::connect(node_endpoint(&service_info.network_name)).await?;
        print!("Fetching active polls... ");
        io::stdout().flush()?;
        let ongoing_poll_indices = get_ongoing_poll_indices(&network).await?;
        println!("{:?}", ongoing_poll_indices);
        ongoing_poll_indices
    } else {
        cmd.poll_index
    };

    let derived_accounts = cmd.accounts_args.derived_accounts()?;

    struct VoteArg {
        poll_index: u32,
        aye_probability: f64,
        account_index: u8,
        secret_phrase: String,
        account: AccountId32
    }

    let mut vote_args = Vec::new();

    for poll_index in poll_indices {
        let aye_probability = thread_rng().gen_range(0.0..1.0);
        for (account_index, secret_phrase, account) in derived_accounts.clone() {
            vote_args.push(VoteArg {
                poll_index,
                aye_probability,
                account_index,
                secret_phrase,
                account
            });
        }
    }

    let shared_vote_args = Arc::new(Mutex::new(vote_args));

    let (sender, receiver) = mpsc::channel();

    let parallelism = cmd.accounts_args.parallelism()?;

    for _ in 0..parallelism {
        let shared_vote_args = shared_vote_args.clone();
        let sender = sender.clone();
        let glove_url = glove_url.clone();
        spawn(async move {
            loop {
                let vote_arg = {
                    let mut shared_vote_args = shared_vote_args.lock().unwrap();
                    shared_vote_args.pop()
                };
                let Some(vote_arg) = vote_arg else {
                    // Signal the thread is done
                    sender.send(()).unwrap();
                    break;
                };
                let balance = thread_rng().gen_range(0.5..5.0);
                let conviction = thread_rng().gen_range(0..6);
                let aye = thread_rng().gen_bool(vote_arg.aye_probability);
                let mut args = vec![
                    "client".to_string(),
                    format!("-g={}", glove_url),
                    "vote".to_string(),
                    format!("--secret-phrase={}", vote_arg.secret_phrase),
                    format!("-p={}", vote_arg.poll_index),
                    format!("-b={}", balance),
                    format!("-c={}", conviction),
                ];
                if aye {
                    args.push("--aye".to_string());
                }
                let output = client::run(args).await.unwrap();
                println!("{}. {} poll={} balance={} conviction={} aye={}: {}",
                       vote_arg.account_index, vote_arg.account, vote_arg.poll_index, balance,
                       conviction, aye, output);
            }
        });
    }

    // Wait for all the threads to finish
    for _ in 0..parallelism {
        receiver.recv()?;
    }

    Ok(())
}

async fn extrinsic(extrinsic_location: ExtrinsicLocation, args: Args) -> Result<()> {
    let service_info = Client::new()
        .get(url_with_path(&args.glove_url, "info"))
        .send().await?
        .error_for_status()?
        .json::<ServiceInfo>().await?;
    let subscan = Subscan::new(service_info.network_name, None);
    match subscan.get_extrinsic(extrinsic_location).await? {
        Some(extrinsic) => println!("{:#?}", extrinsic),
        None => bail!("Extrinsic not found")
    }
    Ok(())
}

async fn get_ongoing_poll_indices(network: &SubstrateNetwork) -> Result<Vec<u32>> {
    // TODO Use Subscan
    let mut poll_indices = Vec::new();
    let mut poll_index = 0;
    loop {
        match network.get_poll(poll_index).await? {
            Some(ReferendumInfoFor::Ongoing(_)) => poll_indices.push(poll_index),
            Some(_) => {},
            None => break,
        }
        poll_index += 1;
    }
    Ok(poll_indices)
}

#[derive(Debug, Parser)]
#[command(version, about = "Glove service stress testing tool")]
struct Args {
    #[arg(long, short, verbatim_doc_comment)]
    glove_url: Url,

    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    JoinGlove(JoinGloveCmd),
    Vote(VoteCmd),
    Extrinsic(ExtrinsicCmd),
}

#[derive(Debug, Parser)]
struct JoinGloveCmd {
    #[command(flatten)]
    accounts_args: AccountsArgs
}

#[derive(Debug, Parser)]
struct VoteCmd {
    #[command(flatten)]
    accounts_args: AccountsArgs,
    #[arg(long, short, verbatim_doc_comment)]
    poll_index: Vec<u32>,
}

#[derive(Debug, Parser)]
struct ExtrinsicCmd {
    #[arg(long, short, verbatim_doc_comment)]
    id: ExtrinsicLocation,
}

#[derive(Debug, Clone, clap::Args)]
struct AccountsArgs {
    #[arg(long, verbatim_doc_comment)]
    secret_phrase: String,

    #[arg(long, short, verbatim_doc_comment, default_value_t = 0)]
    start_derivation: u8,

    #[arg(long, short, verbatim_doc_comment)]
    end_derivation: u8,

    #[arg(long, short, verbatim_doc_comment, default_value_t = 0)]
    parallelism: u8
}

impl AccountsArgs {
    fn derived_accounts(&self) -> Result<Vec<(u8, String, AccountId32)>> {
        let mut keys = Vec::new();
        for i in self.start_derivation..=self.end_derivation {
            let derived_phrase = format!("{}//{}", self.secret_phrase.clone(), i);
            let keypair = parse_secret_phrase(&derived_phrase)?;
            let account: AccountId32 = keypair.public_key().0.into();
            keys.push((i, derived_phrase, account));
        }
        Ok(keys)
    }

    fn parallelism(&self) -> io::Result<u8> {
        if self.parallelism == 0 {
            available_parallelism().map(|p| {
                println!("Parallelism: {}", p);
                p.get() as u8
            })
        } else {
            Ok(self.parallelism)
        }
    }
}
