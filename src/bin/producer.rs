use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use clap::Parser;
use ndn_app::Producer;
use ndn_helloworld_rs::{
    DEFAULT_SIGNING_CERT_FILE, DEFAULT_SIGNING_KEY_FILE, default_data_name, load_signing_identity,
    socket_path,
};
use ndn_packet::{Name, encode::DataBuilder};
use ndn_security::{SignWith, Signer};

#[derive(Debug, Parser)]
struct Args {
    #[arg(long)]
    name: Option<Name>,
    #[arg(long, default_value = "Hello, world!")]
    content: String,
    #[arg(long)]
    socket: Option<PathBuf>,
    #[arg(long, env = "NDN_APP_SIGNING_KEY_FILE", default_value = DEFAULT_SIGNING_KEY_FILE)]
    signing_key: PathBuf,
    #[arg(long, env = "NDN_APP_SIGNING_CERT_FILE", default_value = DEFAULT_SIGNING_CERT_FILE)]
    signing_cert: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    println!("STARTING producer v{}", env!("CARGO_PKG_VERSION"));
    let name = match args.name {
        Some(name) => name,
        None => default_data_name()?,
    };
    let socket = socket_path(args.socket)?;
    let (signer, _) = load_signing_identity(&args.signing_key, &args.signing_cert)?;
    let signer: Arc<dyn Signer> = Arc::new(signer);
    let content = Arc::new(args.content.into_bytes());

    let producer = Producer::connect(&socket, name.clone())
        .await
        .with_context(|| format!("failed to register `{name}` through `{}`", socket.display()))?;
    println!("SERVING signed data {name}");

    producer
        .serve(move |interest, responder| {
            let signer = Arc::clone(&signer);
            let content = Arc::clone(&content);
            async move {
                let wire = DataBuilder::new(interest.name.as_ref().clone(), content.as_ref())
                    .freshness(Duration::from_secs(1))
                    .sign_with_sync(signer.as_ref())
                    .expect("mounted signing credential must remain usable");
                if let Err(error) = responder.respond_bytes(wire).await {
                    eprintln!("failed to respond: {error}");
                }
            }
        })
        .await
        .context("producer connection closed")
}
