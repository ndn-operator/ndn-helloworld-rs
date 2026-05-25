use std::{
    env, fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use ndn_packet::{Data, Name};
use ndn_security::{Certificate, EcdsaP256Signer, TrustSchema, ValidationResult, Validator};

pub const DEFAULT_SIGNING_KEY_FILE: &str = "/etc/ndn/app/signing/ndn.key";
pub const DEFAULT_SIGNING_CERT_FILE: &str = "/etc/ndn/app/signing/ndn.cert";
pub const DEFAULT_TRUST_ANCHOR_DIR: &str = "/etc/ndn/app/trust-anchors";
pub const DEFAULT_CERTIFICATE_CHAIN_DIR: &str = "/etc/ndn/app/certificate-chain";
pub const DEFAULT_SOCKET_PATH: &str = "/run/ndnd.sock";
pub const HELLOWORLD_SCHEMA: &[u8] = include_bytes!("../schema/helloworld.tlv");

#[derive(Clone, Debug)]
pub struct LoadedCertificate {
    pub full_name: Name,
    pub key_name: Name,
    pub certificate: Certificate,
}

pub fn socket_path(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path);
    }
    match env::var("NDN_CLIENT_TRANSPORT") {
        Ok(uri) => uri
            .strip_prefix("unix://")
            .map(PathBuf::from)
            .ok_or_else(|| anyhow!("NDN_CLIENT_TRANSPORT must use a unix:// URI")),
        Err(_) => Ok(PathBuf::from(DEFAULT_SOCKET_PATH)),
    }
}

pub fn default_data_name() -> Result<Name> {
    let prefix = env::var("NDN_PREFIX").unwrap_or_else(|_| "/root-network/subnetwork1".into());
    format!("{prefix}/helloworld/valid")
        .parse()
        .map_err(|_| anyhow!("invalid NDN_PREFIX `{prefix}`"))
}

pub fn load_signing_identity(
    key_path: impl AsRef<Path>,
    cert_path: impl AsRef<Path>,
) -> Result<(EcdsaP256Signer, LoadedCertificate)> {
    let key_data = decode_pem_data(key_path.as_ref(), "NDN KEY")?;
    let cert = load_certificate(cert_path)?;
    let key_name = key_data.name.as_ref().clone();
    if key_name != cert.key_name {
        bail!(
            "mounted key `{key_name}` does not match mounted certificate subject `{}`",
            cert.key_name
        );
    }
    let secret = key_data
        .content()
        .ok_or_else(|| anyhow!("NDN KEY packet has no private-key content"))?;
    let secret_key = p256::SecretKey::from_sec1_der(secret)
        .map_err(|_| anyhow!("NDN KEY content is not a valid SEC1 P-256 private key"))?;
    let signing_key = p256::ecdsa::SigningKey::from(secret_key);
    let signer = EcdsaP256Signer::new(signing_key, key_name, Some(cert.full_name.clone()));
    Ok((signer, cert))
}

pub fn load_certificate(path: impl AsRef<Path>) -> Result<LoadedCertificate> {
    let data = decode_pem_data(path.as_ref(), "NDN CERT")?;
    let full_name = data.name.as_ref().clone();
    let key_name = subject_key_name(&full_name)?;
    let mut certificate = Certificate::decode(&data)
        .with_context(|| format!("failed to decode certificate `{}`", path.as_ref().display()))?;

    // ndnd signs Data with the subject key name as its KeyLocator. ndn-rs
    // indexes certificates by Certificate::name, so index the mounted public
    // key under that KeyLocator while retaining the full Data name for policy.
    certificate.name = Arc::new(key_name.clone());
    Ok(LoadedCertificate {
        full_name,
        key_name,
        certificate,
    })
}

pub fn load_validator(
    trust_anchor_dir: impl AsRef<Path>,
    certificate_chain_dir: impl AsRef<Path>,
) -> Result<Validator> {
    let schema = TrustSchema::from_lvs_binary(HELLOWORLD_SCHEMA)
        .context("failed to load embedded helloworld LVS policy")?;
    let validator = Validator::new(schema.clone());
    let anchors = load_directory_certificates(trust_anchor_dir.as_ref())?;
    if anchors.is_empty() {
        bail!("no trust-anchor certificates were mounted");
    }
    for anchor in anchors {
        validator.add_trust_anchor(anchor.certificate);
    }

    for certificate in load_directory_certificates(certificate_chain_dir.as_ref())? {
        let issuer = certificate.certificate.issuer.as_deref().ok_or_else(|| {
            anyhow!(
                "certificate `{}` has no issuer KeyLocator",
                certificate.full_name
            )
        })?;
        if !schema.allows(&certificate.key_name, issuer) {
            bail!(
                "LVS rejected mounted certificate delegation `{}` signed by `{issuer}`",
                certificate.key_name
            );
        }
        validator.cert_cache().insert(certificate.certificate);
    }
    Ok(validator)
}

pub async fn validate_data(validator: &Validator, data: &Data) -> Result<Bytes> {
    match validator.validate_chain(data).await {
        ValidationResult::Valid(_) => data
            .content()
            .cloned()
            .ok_or_else(|| anyhow!("validated Data contains no content")),
        ValidationResult::Invalid(error) => Err(anyhow!(error)),
        ValidationResult::Pending => bail!("certificate chain is incomplete"),
    }
}

fn load_directory_certificates(directory: &Path) -> Result<Vec<LoadedCertificate>> {
    let mut entries = fs::read_dir(directory)
        .with_context(|| {
            format!(
                "failed to read certificate directory `{}`",
                directory.display()
            )
        })?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.retain(|path| path.extension().and_then(|value| value.to_str()) == Some("cert"));
    entries.sort();
    entries
        .into_iter()
        .map(load_certificate)
        .collect::<Result<Vec<_>>>()
}

fn decode_pem_data(path: &Path, expected_tag: &str) -> Result<Data> {
    let input = fs::read(path).with_context(|| format!("failed to read `{}`", path.display()))?;
    let block =
        pem::parse(input).with_context(|| format!("failed to parse PEM `{}`", path.display()))?;
    if block.tag() != expected_tag {
        bail!(
            "expected `{expected_tag}` PEM in `{}`, got `{}`",
            path.display(),
            block.tag()
        );
    }
    Data::decode(Bytes::copy_from_slice(block.contents()))
        .with_context(|| format!("failed to decode NDN Data in `{}`", path.display()))
}

fn subject_key_name(certificate_name: &Name) -> Result<Name> {
    let components = certificate_name.components();
    if components.len() < 4 || components[components.len() - 4].value.as_ref() != b"KEY" {
        bail!("certificate name `{certificate_name}` does not contain a KEY certificate suffix");
    }
    Ok(Name::from_components(
        components[..components.len() - 2].iter().cloned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_binds_data_to_its_subnetwork_signer() {
        let schema = TrustSchema::from_lvs_binary(HELLOWORLD_SCHEMA).expect("schema");
        let data: Name = "/root-network/subnetwork1/helloworld/valid"
            .parse()
            .unwrap();
        let good: Name = "/root-network/subnetwork1/helloworld/KEY/leaf"
            .parse()
            .unwrap();
        let forged: Name = "/root-network/subnetwork2/helloworld/KEY/leaf"
            .parse()
            .unwrap();
        assert!(schema.allows(&data, &good));
        assert!(!schema.allows(&data, &forged));
    }

    #[test]
    fn schema_enforces_delegated_ca_relationships() {
        let schema = TrustSchema::from_lvs_binary(HELLOWORLD_SCHEMA).expect("schema");
        let leaf: Name = "/root-network/subnetwork1/helloworld/KEY/leaf"
            .parse()
            .unwrap();
        let own_ca: Name = "/root-network/subnetwork1/KEY/ca".parse().unwrap();
        let sibling_ca: Name = "/root-network/subnetwork2/KEY/ca".parse().unwrap();
        assert!(schema.allows(&leaf, &own_ca));
        assert!(!schema.allows(&leaf, &sibling_ca));
    }
}
