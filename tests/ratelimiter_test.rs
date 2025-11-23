use std::net::IpAddr;
use std::str::FromStr;
use w3registrar::api::Network;
use w3registrar::config::{
    Adapter, Config, EmailConfig, GithubConfig, HTTPConfig, ImageConfig, MatrixConfig, PGPConfig,
    PostgresConfig, Ratelimit, RedisConfig, RegistrarConfigs, WebsocketConfig,
};
use std::collections::HashMap;
use subxt::utils::AccountId32;

#[allow(dead_code)]
fn setup_test_config_with_limits(_wallet_limit: u64, _ip_limit: u64) {
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
            pgp: PGPConfig::default(),
            image: ImageConfig::default(),
        },
        postgres: PostgresConfig::default(),
        ratelimit: Ratelimit::default(),
    };

    let _ = Config::load_cell().set(config);
}

#[test]
fn test_ratelimit_default_values() {
    let ratelimit = Ratelimit::default();

    assert_eq!(
        ratelimit.wallet_requests_per_second, 5,
        "default wallet limit should be 5 per second"
    );
    assert_eq!(
        ratelimit.ip_requests_per_second, 5,
        "default ip limit should be 5 per second"
    );
}

#[test]
fn test_ratelimit_exception_ip() {
    // test that localhost variants are properly handled
    let localhost_v4 = IpAddr::from_str("127.0.0.1").unwrap();
    let localhost_v6 = IpAddr::from_str("::1").unwrap();
    let external_ip = IpAddr::from_str("8.8.8.8").unwrap();

    // with default config, only specific ips are exceptions
    let ratelimit = Ratelimit::default();

    // default has no exceptions
    assert!(!ratelimit.is_exception_ip(&localhost_v4), "should not be exception without config");
    assert!(!ratelimit.is_exception_ip(&localhost_v6), "should not be exception without config");
    assert!(!ratelimit.is_exception_ip(&external_ip), "external ip should not be exception");
}

#[test]
fn test_ratelimit_limits_are_reasonable() {
    let ratelimit = Ratelimit::default();

    // limits should be reasonable for normal usage
    assert!(
        ratelimit.wallet_requests_per_second >= 1,
        "wallet limit too low for normal usage"
    );
    assert!(
        ratelimit.ip_requests_per_second >= 1,
        "ip limit too low for normal usage"
    );

    // sanity check - not unlimited
    assert!(
        ratelimit.wallet_requests_per_second <= 100,
        "wallet limit seems too high"
    );
    assert!(
        ratelimit.ip_requests_per_second <= 100,
        "ip limit seems too high"
    );
}

#[test]
fn test_network_enum_for_ratelimit() {
    // ensure network enum works with ratelimit
    let paseo = Network::Paseo;
    let polkadot = Network::Polkadot;
    let kusama = Network::Kusama;

    // just verify they can be used (no panic)
    assert_ne!(format!("{}", paseo), "");
    assert_ne!(format!("{}", polkadot), "");
    assert_ne!(format!("{}", kusama), "");
}

// integration tests would require a running postgres instance
// for full ratelimiter testing, run with:
// cargo test --features integration -- --test-threads=1

#[cfg(feature = "integration")]
mod integration {
    use super::*;
    use w3registrar::postgres::PostgresConnection;

    #[tokio::test]
    async fn test_ip_ratelimiter_allows_under_limit() {
        setup_test_config_with_limits(60, 120);

        let pg_conn = PostgresConnection::default().await.expect("need postgres");
        let test_ip = IpAddr::from_str("192.168.1.100").unwrap();

        // first request should be allowed
        let allowed = pg_conn.is_allowed_ip(&test_ip).await.expect("query failed");
        assert!(allowed, "first request should be allowed");
    }

    #[tokio::test]
    async fn test_wallet_ratelimiter_allows_under_limit() {
        setup_test_config_with_limits(60, 120);

        let pg_conn = PostgresConnection::default().await.expect("need postgres");
        let test_account = AccountId32::from([1u8; 32]);
        let network = Network::Paseo;

        // first request should be allowed
        let allowed = pg_conn
            .is_allowed(&test_account, &network)
            .await
            .expect("query failed");
        assert!(allowed, "first request should be allowed");
    }
}
