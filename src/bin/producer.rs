use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use clap::Parser;
use ndn_config::{
    ControlParameters, ControlResponse,
    control_parameters::{origin, route_flags},
    nfd_command::{command_name, module, verb},
};
use ndn_faces::local::{IpcFace, ipc_face_connect};
use ndn_helloworld_rs::{
    DEFAULT_SIGNING_CERT_FILE, DEFAULT_SIGNING_KEY_FILE, default_data_name, load_signing_identity,
    socket_path,
};
use ndn_packet::{
    Data, Interest, Name,
    encode::{DataBuilder, InterestBuilder},
    lp::{LpPacket, encode_lp_packet, is_lp_packet},
};
use ndn_security::{SignWith, Signer};
use ndn_transport::{Face, FaceId};

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
    let socket_str = socket
        .to_str()
        .ok_or_else(|| anyhow!("socket path `{}` is not valid UTF-8", socket.display()))?;

    let face = connect_and_advertise(socket_str, &name)
        .await
        .with_context(|| {
            format!(
                "failed to advertise `{name}` through `{}`",
                socket.display()
            )
        })?;
    println!("SERVING signed data {name}");

    loop {
        let raw = face.recv().await.context("producer connection closed")?;
        let raw = strip_lp(raw);
        let interest = match Interest::decode(raw) {
            Ok(interest) => interest,
            Err(_) => continue,
        };

        let wire = DataBuilder::new(interest.name.as_ref().clone(), content.as_ref())
            .freshness(Duration::from_secs(1))
            .sign_with_sync(signer.as_ref())
            .expect("mounted signing credential must remain usable");
        if let Err(error) = face.send(encode_lp_packet(&wire)).await {
            eprintln!("failed to respond: {error}");
        }
    }
}

async fn connect_and_advertise(socket: &str, name: &Name) -> Result<IpcFace> {
    let face = ipc_face_connect(FaceId(0), socket)
        .await
        .with_context(|| format!("failed to connect to `{socket}`"))?;
    register_client_route(&face, name).await?;
    println!("ADVERTISED route {name}");
    Ok(face)
}

async fn register_client_route(face: &IpcFace, name: &Name) -> Result<()> {
    let params = client_route_parameters(name);
    let response = send_command(face, module::RIB, verb::REGISTER, &params).await?;
    if !response.is_ok() {
        bail!(
            "rib/register rejected `{name}`: {} {}",
            response.status_code,
            response.status_text
        );
    }
    Ok(())
}

fn client_route_parameters(name: &Name) -> ControlParameters {
    ControlParameters {
        name: Some(name.clone()),
        origin: Some(origin::CLIENT),
        cost: Some(0),
        flags: Some(route_flags::CHILD_INHERIT),
        ..Default::default()
    }
}

async fn send_command(
    face: &IpcFace,
    module_name: &[u8],
    verb_name: &[u8],
    params: &ControlParameters,
) -> Result<ControlResponse> {
    let command = command_name(module_name, verb_name, params);
    let interest = InterestBuilder::new(command).sign_digest_sha256();
    face.send(encode_lp_packet(&interest))
        .await
        .context("failed to send management command")?;

    let response = face
        .recv()
        .await
        .context("failed to receive management response")?;
    let response = strip_lp(response);
    let data = Data::decode(response).map_err(|_| anyhow!("management response was not Data"))?;
    let content = data
        .content()
        .ok_or_else(|| anyhow!("management response Data had no content"))?;
    ControlResponse::decode(Bytes::copy_from_slice(content))
        .map_err(|_| anyhow!("management response content was not a ControlResponse"))
}

fn strip_lp(raw: Bytes) -> Bytes {
    if is_lp_packet(&raw)
        && let Ok(lp) = LpPacket::decode(raw.clone())
    {
        if lp.nack.is_none()
            && let Some(fragment) = lp.fragment
        {
            return fragment;
        }
    }
    raw
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_route_parameters_trigger_ndnd_readvertise() {
        let name: Name = "/root-network/subnetwork1/helloworld/valid"
            .parse()
            .unwrap();
        let params = client_route_parameters(&name);

        assert_eq!(params.name, Some(name));
        assert_eq!(params.origin, Some(origin::CLIENT));
        assert_eq!(params.cost, Some(0));
        assert_eq!(params.flags, Some(route_flags::CHILD_INHERIT));
    }
}
