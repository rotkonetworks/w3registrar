use w3registrar::adapter::pgp::PGPHelper;
use w3registrar::config::{Adapter, Config, EmailConfig, GithubConfig, HTTPConfig, MatrixConfig, PGPConfig, PostgresConfig, RedisConfig, RegistrarConfig, RegistrarConfigs, WebsocketConfig, GLOBAL_CONFIG};
use std::collections::HashMap;

fn setup_test_config() {
    let config = Config {
        websocket: WebsocketConfig::default(),
        registrar: RegistrarConfigs {
            networks: HashMap::new(),
        },
        redis: RedisConfig::default(),
        http: HTTPConfig::default(),
        adapter: Adapter {
            matrix: MatrixConfig {
                homeserver: "https://matrix.org".to_string(),
                username: "test".to_string(),
                password: "test".to_string(),
                security_key: "test".to_string(),
                admins: vec![],
                state_dir: "/tmp/test".to_string(),
            },
            email: EmailConfig {
                username: "test".to_string(),
                password: "test".to_string(),
                name: "test".to_string(),
                port: 143,
                email: "test@test.com".to_string(),
                mailbox: "INBOX".to_string(),
                server: "localhost".to_string(),
                checking_frequency: None,
            },
            github: GithubConfig::default(),
            pgp: PGPConfig {
                keyserver_url: "https://keyserver.ubuntu.com".to_string(),
            },
        },
        postgres: PostgresConfig::default(),
    };

    let _ = GLOBAL_CONFIG.set(config);
}

#[tokio::test]
async fn test_fetch_key_from_keyserver_valid_fingerprint() {
    setup_test_config();

    // Using Linus Torvalds' PGP key fingerprint as a known valid test case
    // ABAF11C65A2970B130ABE3C479BE3E4300411886
    let fingerprint: [u8; 20] = [
        0xAB, 0xAF, 0x11, 0xC6, 0x5A, 0x29, 0x70, 0xB1,
        0x30, 0xAB, 0xE3, 0xC4, 0x79, 0xBE, 0x3E, 0x43,
        0x00, 0x41, 0x18, 0x86,
    ];

    let result = PGPHelper::fetch_key_from_keyserver(&fingerprint).await;

    assert!(result.is_ok(), "Should successfully fetch a valid PGP key");

    let cert = result.unwrap();
    assert_eq!(
        cert.fingerprint().as_bytes(),
        &fingerprint,
        "Fetched certificate fingerprint should match requested fingerprint"
    );
}

#[tokio::test]
async fn test_fetch_key_from_keyserver_invalid_fingerprint() {
    setup_test_config();

    // Using a non-existent fingerprint
    let fingerprint: [u8; 20] = [0x00; 20];

    let result = PGPHelper::fetch_key_from_keyserver(&fingerprint).await;

    assert!(result.is_err(), "Should fail to fetch non-existent PGP key");

    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("No PGP key found"),
        "Error message should indicate key not found"
    );
}

#[tokio::test]
async fn test_keyserver_url_configuration() {
    let custom_keyserver = "https://keys.openpgp.org";

    let config = Config {
        websocket: WebsocketConfig::default(),
        registrar: RegistrarConfigs {
            networks: HashMap::new(),
        },
        redis: RedisConfig::default(),
        http: HTTPConfig::default(),
        adapter: Adapter {
            matrix: MatrixConfig {
                homeserver: "https://matrix.org".to_string(),
                username: "test".to_string(),
                password: "test".to_string(),
                security_key: "test".to_string(),
                admins: vec![],
                state_dir: "/tmp/test".to_string(),
            },
            email: EmailConfig {
                username: "test".to_string(),
                password: "test".to_string(),
                name: "test".to_string(),
                port: 143,
                email: "test@test.com".to_string(),
                mailbox: "INBOX".to_string(),
                server: "localhost".to_string(),
                checking_frequency: None,
            },
            github: GithubConfig::default(),
            pgp: PGPConfig {
                keyserver_url: custom_keyserver.to_string(),
            },
        },
        postgres: PostgresConfig::default(),
    };

    assert_eq!(
        config.adapter.pgp.keyserver_url,
        custom_keyserver,
        "Custom keyserver URL should be configurable"
    );
}

#[test]
fn test_pgp_config_default() {
    let config = PGPConfig::default();

    assert_eq!(
        config.keyserver_url,
        "https://keyserver.ubuntu.com",
        "Default keyserver should be Ubuntu keyserver"
    );
}
