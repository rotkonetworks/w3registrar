use super::types::*;
use crate::adapter::github::{Github, GithubRedirectStepTwoParams};
use crate::adapter::Adapter;
use crate::config::Config;
use crate::indexer::Indexer;
use crate::postgres::PostgresConnection;
use crate::redis::RedisConnection;

use anyhow::anyhow;
use axum::{extract::Query, routing::get, Router};
use std::str::FromStr;
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info, instrument};

fn log_error_and_return(log: String) -> String {
    error!(log);
    log
}

async fn github_oauth_callback(Query(params): Query<GithubRedirectStepTwoParams>) -> String {
    info!(params=?params, "PARAMS");

    let gh = match Github::new(&params).await {
        Ok(gh) => gh,
        Err(e) => return log_error_and_return(format!("Error: {e}")),
    };
    info!(credentials = ?gh, "Github Credentials");

    let gh_username = match gh.request_username().await {
        Ok(username) => username,
        Err(e) => return log_error_and_return(format!("Error: {e}")),
    };
    info!(username = ?gh_username, "Github Username");

    let mut redis_connection = match RedisConnection::get_connection().await {
        Ok(conn) => conn,
        Err(e) => {
            return log_error_and_return(format!("Error: {e}"));
        }
    };

    let search_query = format!("github|{gh_username}|*");
    let accounts = match redis_connection.search(&search_query).await {
        Ok(res) => res,
        Err(e) => return log_error_and_return(format!("Error: {e}")),
    };

    let reconstructed_url = match Github::reconstruct_request_url(&params.state) {
        Ok(url) => url,
        Err(e) => return log_error_and_return(format!("Error: {e}")),
    };

    for acc_str in accounts {
        info!("Account: {}", acc_str);
        let parts: Vec<&str> = acc_str.splitn(4, '|').collect();
        if parts.len() != 4 {
            continue;
        }
        info!("Parts: {:#?}", parts);
        let account = match Account::from_str(&format!("{}|{}", parts[0], parts[1])) {
            Ok(account) => account,
            Err(e) => return log_error_and_return(format!("Error: {e}")),
        };

        let network = match Network::from_str(parts[2]) {
            Ok(network) => network,
            Err(e) => return log_error_and_return(format!("Error: {e}")),
        };

        if let Ok(account_id) = subxt::utils::AccountId32::from_str(parts[3]) {
            match <Github as Adapter>::handle_content(
                reconstructed_url.as_str(),
                &mut redis_connection,
                &network,
                &account_id,
                &account,
            )
            .await
            {
                Ok(_) => return String::from("OK"),
                Err(e) => return log_error_and_return(format!("Error: {e}")),
            }
        }
    }

    log_error_and_return("Error: Github account not found in the registration queue".to_string())
}

async fn pong() -> &'static str {
    "PONG"
}

async fn get_events(
    axum::extract::Path((network, wallet)): axum::extract::Path<(String, String)>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    let network = match Network::from_str(&network) {
        Ok(n) => n,
        Err(_) => return (axum::http::StatusCode::BAD_REQUEST, "invalid network").into_response(),
    };

    let limit = params.get("limit").and_then(|l| l.parse().ok()).unwrap_or(100i64);

    let pg_conn = match PostgresConnection::default().await {
        Ok(c) => c,
        Err(e) => return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    match pg_conn.get_identity_events(&wallet, Some(&network), Some(limit)).await {
        Ok(events) => axum::Json(events).into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn trigger_backfill(
    axum::extract::Path(network): axum::extract::Path<String>,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    let network = match Network::from_str(&network) {
        Ok(n) => n,
        Err(_) => return (axum::http::StatusCode::BAD_REQUEST, "invalid network").into_response(),
    };

    let network_name = format!("{}", network);
    let network_for_spawn = network;

    tokio::spawn(async move {
        let indexer = match Indexer::new().await {
            Ok(i) => i,
            Err(e) => {
                error!(error=?e, "failed to create indexer for backfill");
                return;
            }
        };

        if let Err(e) = indexer.backfill_full_history(&network_for_spawn).await {
            error!(network=?network_for_spawn, error=?e, "full history backfill failed");
        }
    });

    (axum::http::StatusCode::ACCEPTED, format!("backfill started for {}", network_name)).into_response()
}

pub async fn spawn_http_serv() -> anyhow::Result<()> {
    let cfg = Config::load_static();
    let gh_config = cfg.adapter.github.clone();
    let http_config = cfg.http.clone();
    let redirect_url = gh_config
        .redirect_url
        .ok_or_else(|| anyhow!("GitHub redirect_url not configured"))?;

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route(redirect_url.path(), get(github_oauth_callback))
        .route("/ping", get(pong))
        .route("/events/{network}/{wallet}", get(get_events))
        .route("/admin/backfill/{network}", axum::routing::post(trigger_backfill))
        .layer(cors);
    let listener = tokio::net::TcpListener::bind(&(http_config.host, http_config.port)).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[instrument(name = "identity_indexer")]
pub async fn spawn_identity_indexer() -> anyhow::Result<()> {
    Indexer::new().await?.index().await
}
