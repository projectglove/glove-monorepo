use std::env;

use anyhow::Result;

use client::{run, SuccessOutput};

#[tokio::main]
async fn main() -> Result<SuccessOutput> {
    run(env::args_os()).await
}
