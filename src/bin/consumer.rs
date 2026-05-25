use std::{path::PathBuf, process::ExitCode};

use anyhow::{Context, Result, bail};
use clap::Parser;
use ndn_app::Consumer;
use ndn_helloworld_rs::{
    DEFAULT_CERTIFICATE_CHAIN_DIR, DEFAULT_TRUST_ANCHOR_DIR, default_data_name, load_validator,
    socket_path, validate_data,
};
use ndn_packet::Name;

#[derive(Debug, Parser)]
struct Args {
    #[arg(long)]
    name: Option<Name>,
    #[arg(long)]
    expect_reject: bool,
    #[arg(long)]
    socket: Option<PathBuf>,
    #[arg(long, env = "NDN_APP_TRUST_ANCHOR_DIR", default_value = DEFAULT_TRUST_ANCHOR_DIR)]
    trust_anchor_dir: PathBuf,
    #[arg(
        long,
        env = "NDN_APP_CERTIFICATE_CHAIN_DIR",
        default_value = DEFAULT_CERTIFICATE_CHAIN_DIR
    )]
    certificate_chain_dir: PathBuf,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let args = Args::parse();
    println!("STARTING consumer v{}", env!("CARGO_PKG_VERSION"));
    let name = match args.name {
        Some(name) => name,
        None => default_data_name()?,
    };
    let socket = socket_path(args.socket)?;
    let validator = load_validator(&args.trust_anchor_dir, &args.certificate_chain_dir)?;
    let mut consumer = Consumer::connect(&socket)
        .await
        .with_context(|| format!("failed to connect through `{}`", socket.display()))?;
    let data = consumer
        .fetch(name.clone())
        .await
        .with_context(|| format!("failed to fetch `{name}`"))?;

    match validate_data(&validator, &data).await {
        Ok(content) if args.expect_reject => {
            bail!(
                "expected Data `{name}` to be rejected, but it validated with content `{}`",
                String::from_utf8_lossy(&content)
            );
        }
        Ok(content) => {
            println!(
                "VERIFIED data {name}: {}",
                String::from_utf8_lossy(&content)
            );
        }
        Err(error) if args.expect_reject => {
            println!("REJECTED data {name}: {error}");
        }
        Err(error) => return Err(error).context(format!("validation rejected `{name}`")),
    }
    Ok(())
}
