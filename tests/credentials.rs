use std::fs;

use ndn_helloworld_rs::{load_signing_identity, load_validator};
use ndn_packet::{Data, encode::DataBuilder};
use ndn_security::{SignWith, Signer, TrustSchema, ValidationResult, Validator};

const KEY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/mynetwork.key");
const CERT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/mynetwork.cert");

#[test]
fn decodes_operator_style_ndnd_pem_identity() {
    let (signer, cert) = load_signing_identity(KEY, CERT).expect("mounted identity");
    assert_eq!(signer.key_name().to_string(), cert.key_name.to_string());
    assert!(cert.full_name.to_string().contains("/KEY/"));
}

#[tokio::test]
async fn ndnd_key_signs_data_verifiable_by_its_certificate() {
    let (signer, cert) = load_signing_identity(KEY, CERT).expect("mounted identity");
    let wire = DataBuilder::new("/mynetwork/helloworld/valid", b"Hello, world!")
        .sign_with_sync(&signer)
        .expect("sign");
    let data = Data::decode(wire).expect("decode signed Data");
    let validator = Validator::new(TrustSchema::accept_all());
    validator.cert_cache().insert(cert.certificate);

    assert!(matches!(
        validator.validate(&data).await,
        ValidationResult::Valid(_)
    ));
}

#[test]
fn untrusted_chain_files_are_not_promoted_to_anchors() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let anchors = directory.path().join("anchors");
    let chain = directory.path().join("chain");
    fs::create_dir(&anchors).expect("anchor directory");
    fs::create_dir(&chain).expect("chain directory");
    fs::copy(CERT, chain.join("leaf.cert")).expect("chain certificate");

    let error = match load_validator(&anchors, &chain) {
        Ok(_) => panic!("chain-only setup must fail"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("no trust-anchor"));

    fs::copy(CERT, anchors.join("root.cert")).expect("anchor certificate");
    fs::remove_file(chain.join("leaf.cert")).expect("clear chain");
    load_validator(&anchors, &chain).expect("explicit anchor is accepted");
}
