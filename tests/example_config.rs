//! The shipped example config must actually parse and validate. An example
//! that does not is worse than none: an operator copies it and debugs a typo
//! at 3am on a validator that will not boot.

#[test]
fn example_config_parses_and_validates() {
    let raw = include_str!("../integration/kms-config.example.json");
    let cfg: midnight_kms::KmsConfig =
        serde_json::from_str(raw).expect("example config must deserialize");
    cfg.validate().expect("example config must pass validation");
    assert_eq!(cfg.keys.len(), 3);
    // Defaults must apply for fields the example omits.
    assert!(cfg.attest.allow_token_file_fallback);
    assert_eq!(
        cfg.attest.socket_path.to_str().unwrap(),
        "/run/container_launcher/teeserver.sock"
    );
}
