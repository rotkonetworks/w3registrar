//! Server components: WebSocket listener, Node listener, Redis subscriber, HTTP server
//!
//! This module contains the main server infrastructure for the W3Registrar.

#![allow(dead_code)]

use super::messages::*;
use super::types::*;
use crate::config::{Config, RedisConfig, RegistrarConfig, GLOBAL_CONFIG};
use crate::indexer::Indexer;
use crate::node::{
    self, filter_accounts,
    substrate::runtime_types::{
        pallet_identity::types::{Judgement, Registration},
        people_paseo_runtime::people::IdentityInfo,
    },
    Client as NodeClient,
};
use crate::postgres::{PostgresConnection, RegistrationRecord};
use crate::redis::RedisConnection;
use crate::adapter::{
    email::jmap::send_email_challenge,
    github::{Github, GithubRedirectStepTwoParams},
    matrix::{send_challenge as send_matrix_challenge, send_dm as send_matrix_dm},
    pgp::PGPHelper,
    Adapter,
};

use anyhow::anyhow;
use anyhow::Result;
use axum::{extract::Query, routing::get, Router};
use futures::channel::mpsc::{self, Sender};
use futures::stream::{SplitSink, SplitStream};
use futures::StreamExt;
use futures_util::SinkExt;
use once_cell::sync::OnceCell;
use redis::{self, Client as RedisClient, Msg};
use serde_json::json;
use sp_core::blake2_256;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use subxt::utils::AccountId32;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, error, info, info_span, instrument, Span};
use tungstenite::Error;

static REDIS_CLIENT: OnceCell<Arc<RedisClient>> = OnceCell::new();

#[derive(Debug, Clone)]
pub struct SocketListener {
    redis_cfg: RedisConfig,
    span: Span,
    socket_addr: SocketAddr,
}

impl SocketListener {
    pub async fn new() -> anyhow::Result<Self> {
        let cfg = Config::load_static();
        let span = info_span!("socket_listener");
        let socket_addr = cfg
            .websocket
            .socket_addrs()
            .ok_or_else(|| anyhow!("Failed to resolve websocket address"))?;
        Ok(Self {
            span,
            redis_cfg: cfg.redis.clone(),
            socket_addr,
        })
    }

    #[instrument(skip_all, parent = &self.span, name = "subscription_request")]
    pub async fn handle_subscription_request(
        &mut self,
        request: IncomingSubscribeRequest,
        subscriber: &mut Option<AccountId32>,
    ) -> anyhow::Result<serde_json::Value> {
        let pg_conn = PostgresConnection::default().await?;

        if !pg_conn
            .is_allowed(&request.account, &request.network)
            .await?
        {
            return Err(anyhow!("rate limit exceeded, try again later"));
        } else {
            pg_conn
                .register_requester(&request.account, &request.network)
                .await?;
        }

        let cfg = Config::load_static();

        if !cfg.registrar.is_network_supported(&request.network) {
            return Ok(serde_json::json!({
                "type": "error",
                "message": format!("Network {} not supported", request.network)
            }));
        }

        let network_cfg = cfg.registrar.require_network(&request.network)?;

        *subscriber = Some(request.account.clone());
        let client = NodeClient::from_url(&network_cfg.endpoint).await?;
        let registration = node::get_registration(&client, &request.account).await?;

        let mut conn = RedisConnection::get_connection().await?;

        let existing_verification = conn
            .get_verification_state(&request.network, &request.account)
            .await?;

        let mut verification = existing_verification
            .unwrap_or_else(|| AccountVerification::new(request.network.to_string()));

        let accounts_from_chain = Account::into_accounts(&registration.info);
        let accounts = if accounts_from_chain.is_empty() {
            info!("No on-chain identity found, generating codes for all verifiable fields");
            let verifiable_fields = vec![
                Account::Email(String::new()),
                Account::Twitter(String::new()),
                Account::Github(String::new()),
                Account::Matrix(String::new()),
                Account::Discord(String::new()),
                Account::Web(String::new()),
            ];
            Account::into_hashmap(verifiable_fields, false)
        } else {
            filter_accounts(
                &registration.info,
                &request.account,
                network_cfg.registrar_index,
                &request.network,
            )
            .await?
        };

        for (account, is_done) in &accounts {
            let (name, acc_type) = (account.inner(), account.account_type());

            if !verification.challenges.contains_key(&acc_type) {
                let token = account.generate_token(*is_done).await;
                verification.add_challenge(&acc_type, name.clone(), token);
            }
        }

        conn.init_verification_state(&request.network, &request.account, &verification, &accounts)
            .await?;

        let cfg = GLOBAL_CONFIG.get().expect("GLOBAL_CONFIG is not initialized");
        if matches!(cfg.adapter.email.protocol, crate::config::EmailProtocol::Jmap)
            && matches!(cfg.adapter.email.mode, crate::config::EmailMode::Send | crate::config::EmailMode::Bidirectional)
        {
            for (account, is_done) in &accounts {
                if let Account::Email(email_address) = account {
                    if !is_done {
                        if let Some(challenge) = verification.challenges.get(&AccountType::Email) {
                            if let Some(token) = &challenge.token {
                                info!(
                                    "Sending email challenge to {} for {}/{}",
                                    email_address, request.network, request.account
                                );
                                if let Err(e) = send_email_challenge(
                                    email_address,
                                    token,
                                    &request.network,
                                    &request.account,
                                )
                                .await
                                {
                                    error!("Failed to send email challenge to {}: {}", email_address, e);
                                }
                            }
                        }
                    }
                }
            }
        }

        let hash = self.hash_identity_info(&registration.info);

        conn.build_account_state_message(&request.network, &request.account, Some(hash))
            .await
    }

    fn hash_identity_info(&self, info: &IdentityInfo) -> String {
        let info_bytes = format!("{:?}", info).into_bytes();
        let hash = blake2_256(&info_bytes);
        format!("0x{}", hex::encode(hash))
    }

    #[instrument(skip_all, parent = &self.span)]
    async fn process_v1_1(
        &mut self,
        message: VersionedMessage,
        subscriber: &mut Option<AccountId32>,
    ) -> anyhow::Result<serde_json::Value> {
        match message.payload {
            WebSocketMessage::SubscribeAccountState(incoming) => {
                self.handle_subscription_request(incoming, subscriber).await
            }
            WebSocketMessage::VerifyPGPKey(incoming) => {
                self.handle_pgp_verification_request(incoming, subscriber)
                    .await
            }
            WebSocketMessage::VerifyPGPKeyAutomated(incoming) => {
                self.handle_pgp_automated_verification_request(incoming, subscriber)
                    .await
            }
            WebSocketMessage::UploadPGPKey(incoming) => {
                self.handle_upload_pgp_key_request(incoming).await
            }
            WebSocketMessage::FetchPGPKey(incoming) => {
                self.handle_fetch_pgp_key_request(incoming).await
            }
            WebSocketMessage::UpdateRemailerSettings(incoming) => {
                self.handle_update_remailer_settings_request(incoming).await
            }
            WebSocketMessage::SearchRegistration(incoming) => {
                self.handle_search_request(incoming).await
            }
            WebSocketMessage::GetAccountHistory(incoming) => {
                self.handle_account_history_request(incoming).await
            }
            WebSocketMessage::AdminApprove(incoming) => {
                self.handle_admin_approve_request(incoming).await
            }
            WebSocketMessage::AdminReject(incoming) => {
                self.handle_admin_reject_request(incoming).await
            }
            WebSocketMessage::AdminProvideJudgement(incoming) => {
                self.handle_admin_provide_judgement_request(incoming).await
            }
            WebSocketMessage::RemailerBlock(incoming) => {
                self.handle_remailer_block_request(incoming).await
            }
            WebSocketMessage::RemailerUnblock(incoming) => {
                self.handle_remailer_unblock_request(incoming).await
            }
            WebSocketMessage::RemailerGetBlocked(incoming) => {
                self.handle_remailer_get_blocked_request(incoming).await
            }
            WebSocketMessage::RemailerSendMessage(incoming) => {
                self.handle_remailer_send_message_request(incoming).await
            }
            WebSocketMessage::InitiateChallenge(incoming) => {
                self.handle_initiate_challenge_request(incoming).await
            }
        }
    }

    #[instrument(skip_all, parent = &self.span)]
    pub async fn _handle_incoming(
        &mut self,
        message: Message,
        subscriber: &mut Option<AccountId32>,
        sender_addr: IpAddr,
    ) -> Result<serde_json::Value> {
        let pg_conn = PostgresConnection::default().await?;
        if !pg_conn.is_allowed_ip(&sender_addr).await? {
            return Ok(json!({
                "type": "error",
                "message": "rate limit exceeded, try again later"
            }));
        } else {
            pg_conn.register_requester_ip(&sender_addr).await?;
        }

        let text = match message {
            Message::Text(t) => t,
            _ => {
                return Ok(json!({
                    "type": "error",
                    "message": "Unsupported message format"
                }))
            }
        };

        let versioned_msg: VersionedMessage = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => {
                return Ok(json!({
                    "type": "error",
                    "message": format!("Failed to parse message: {}", e)
                }))
            }
        };

        info!(
            message_version = %versioned_msg.version,
            message_type = %versioned_msg.message_type_str(),
            "Received WebSocket message"
        );

        match versioned_msg.version.as_str() {
            "1.0" | "1.1" => match self.process_v1_1(versioned_msg, subscriber).await {
                Ok(response) => Ok(response),
                Err(e) => Ok(json!({
                    "type": "error",
                    "message": e.to_string()
                })),
            },
            _ => Ok(json!({
                "type": "error",
                "message": format!("Unsupported version: {}", versioned_msg.version),
            })),
        }
    }

    pub async fn check_node(
        id: AccountId32,
        accounts: Vec<Account>,
        network: &Network,
    ) -> anyhow::Result<()> {
        let cfg = Config::load_static();
        let network_cfg = cfg.registrar.require_network(network)?;

        let client = NodeClient::from_url(&network_cfg.endpoint).await?;
        let registration = node::get_registration(&client, &id).await?;

        info!(registration = %format!("{:?}", registration));

        Self::is_complete(&registration, &accounts)?;
        Self::has_paid_fee(registration.judgements.0)?;
        Self::validate_account_types(&accounts, network_cfg)?;

        Ok(())
    }

    fn validate_account_types(
        accounts: &[Account],
        network_cfg: &RegistrarConfig,
    ) -> anyhow::Result<()> {
        for account in accounts {
            let acc_type = account.account_type();
            let supported = network_cfg.fields.iter().any(|field| {
                AccountType::from_str(field)
                    .map(|f| f == acc_type)
                    .unwrap_or(false)
            });

            if !supported {
                return Err(anyhow!(
                    "Account type {} is not supported on this network",
                    acc_type,
                ));
            }
        }
        Ok(())
    }

    fn has_paid_fee(judgements: Vec<(u32, Judgement<u128>)>) -> anyhow::Result<(), anyhow::Error> {
        if judgements
            .iter()
            .any(|(_, j)| matches!(j, Judgement::FeePaid(_)))
        {
            Ok(())
        } else {
            Err(anyhow!("fee is not paid!"))
        }
    }

    pub fn is_complete(
        registration: &Registration<u128, IdentityInfo>,
        expected: &[Account],
    ) -> anyhow::Result<(), anyhow::Error> {
        for acc in expected {
            let (stored_acc, expected_acc) = match acc {
                Account::Email(email_acc) => {
                    (identity_data_tostring(&registration.info.email), email_acc)
                }
                Account::Discord(discord_acc) => (
                    identity_data_tostring(&registration.info.discord),
                    discord_acc,
                ),
                Account::Display(display_name) => (
                    identity_data_tostring(&registration.info.display),
                    display_name,
                ),
                Account::Matrix(matrix_acc) => (
                    identity_data_tostring(&registration.info.matrix),
                    matrix_acc,
                ),
                Account::Twitter(twit_acc) => {
                    (identity_data_tostring(&registration.info.twitter), twit_acc)
                }
                Account::Web(web_acc) => (identity_data_tostring(&registration.info.web), web_acc),
                Account::Github(github_acc) => (
                    identity_data_tostring(&registration.info.github),
                    github_acc,
                ),
                Account::Legal(_) => todo!(),
                Account::Image(image) => (identity_data_tostring(&registration.info.image), image),
                Account::PGPFingerprint(fingerprint) => (
                    Some(hex::encode(
                        registration
                            .info
                            .pgp_fingerprint
                            .ok_or_else(|| anyhow!("Internal error"))?,
                    )),
                    &hex::encode(fingerprint),
                ),
            };

            let stored_acc = stored_acc.ok_or_else(|| {
                anyhow!(
                    "{} acc {} not in identity obj",
                    acc.account_type(),
                    expected_acc
                )
            })?;

            if !expected_acc.eq(&stored_acc) {
                return Err(anyhow!("got {}, expected {}", expected_acc, stored_acc));
            }
        }
        Ok(())
    }

    async fn send_message(
        write: &Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>,
        msg: String,
    ) -> Result<(), anyhow::Error> {
        debug!("Attempting to send message: {}", msg);
        let mut guard = write.lock().await;
        let result = guard.send(Message::Text(msg.into())).await;
        debug!("Message send result: {:?}", result);
        result.map_err(|e| e.into())
    }

    #[instrument(skip_all)]
    async fn close_ws_connection() {
        info!("Received close frame, closing...");
    }

    #[instrument(skip_all)]
    async fn handle_non_text_message() -> bool {
        info!("Recived non text message");
        true
    }

    #[instrument(skip_all)]
    async fn handle_connection_errors(error: Error) -> bool {
        error!(error = %error, "WebSocket error");
        false
    }

    #[instrument(skip_all, parent = &self.span)]
    async fn process_websocket(
        &mut self,
        ws_write: Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>,
        mut ws_read: SplitStream<WebSocketStream<TcpStream>>,
        sender_addr: IpAddr,
    ) {
        let mut subscriber: Option<AccountId32> = None;
        let (sender, mut receiver) = mpsc::channel::<serde_json::Value>(100);

        loop {
            tokio::select! {
                Some(msg) = receiver.next() => {
                    if !self.handle_channel_message(&ws_write, msg).await {
                        break;
                    }
                }

                Some(msg_result) = ws_read.next() => {
                    match msg_result {
                        Ok(Message::Close(_)) => {
                            Self::close_ws_connection().await;
                            break;
                        }
                        _ => {
                            if !self.handle_ws_message(&ws_write, msg_result, &mut subscriber, sender.clone(), sender_addr).await {
                                Self::close_ws_connection().await;
                                break;
                            }
                        }
                    }
                }

                else => {
                    info!("WebSocket or channel stream ended");
                    break;
                }
            }
        }

        if let Some(id) = subscriber {
            info!(subscriber_id = %id, "Cleaning up subscriber");
        }
        info!("WebSocket connection closed");
    }

    #[instrument(skip_all, parent = &self.span)]
    async fn handle_channel_message(
        &self,
        write: &Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>,
        msg: serde_json::Value,
    ) -> bool {
        let resp_type = msg
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        match serde_json::to_string(&msg) {
            Ok(serialized) => {
                info!(response_type = %resp_type, "Sending response");
                match Self::send_message(write, serialized).await {
                    Ok(_) => true,
                    Err(e) => {
                        error!(error = %e, "Failed to send message");
                        false
                    }
                }
            }
            Err(e) => {
                error!(error = %e, "Failed to serialize response");
                true
            }
        }
    }

    #[instrument(skip_all, parent = &self.span)]
    async fn handle_ws_message(
        &mut self,
        write: &Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>,
        msg_result: Result<Message, tokio_tungstenite::tungstenite::Error>,
        subscriber: &mut Option<AccountId32>,
        sender: Sender<serde_json::Value>,
        sender_addr: IpAddr,
    ) -> bool {
        match msg_result {
            Ok(Message::Text(bytes)) => {
                let text = bytes.to_string();
                self.handle_text_message(write, text, subscriber, sender, sender_addr)
                    .await
            }
            Ok(Message::Close(_)) => false,
            Ok(_) => Self::handle_non_text_message().await,
            Err(e) => Self::handle_connection_errors(e).await,
        }
    }

    #[instrument(skip_all, parent = &self.span)]
    async fn handle_text_message(
        &mut self,
        write: &Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>,
        text: String,
        subscriber: &mut Option<AccountId32>,
        sender: Sender<serde_json::Value>,
        sender_addr: IpAddr,
    ) -> bool {
        match self
            ._handle_incoming(Message::Text(text.into()), subscriber, sender_addr)
            .await
        {
            Ok(response) => {
                let serialized = match serde_json::to_string(&response) {
                    Ok(s) => s,
                    Err(e) => {
                        error!(error = %e, "Failed to serialize response");
                        return true;
                    }
                };

                if let Err(e) = Self::send_message(write, serialized).await {
                    error!(error = %e, "Failed to send response");
                    return false;
                }

                if let Some(id) = subscriber.take() {
                    info!(subscriber_id = %id, "New subscriber registered");
                    let mut cloned_self = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = cloned_self.spawn_redis_listener(sender, id, response).await
                        {
                            error!(error = %e, "Redis listener error");
                        }
                    });
                }
                true
            }
            Err(e) => self.handle_error_response(write, e).await,
        }
    }

    #[instrument(skip_all)]
    async fn handle_error_response(
        &self,
        write: &Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>,
        error: anyhow::Error,
    ) -> bool {
        error!(error = %error, "Error handling message");

        let error_response = serde_json::json!({
            "version": "1.0",
            "error": error.to_string()
        });

        match serde_json::to_string(&error_response) {
            Ok(serialized) => match Self::send_message(write, serialized).await {
                Ok(_) => true,
                Err(e) => {
                    error!(error = %e, "Failed to send error response");
                    false
                }
            },
            Err(e) => {
                error!(error = %e, "Failed to serialize error response");
                true
            }
        }
    }

    #[instrument(skip_all, parent = &self.span)]
    pub async fn handle_connection(&mut self, stream: std::net::TcpStream) {
        let ip_addr = match stream.peer_addr() {
            Ok(addr) => addr.ip(),
            Err(e) => {
                error!(error = %e, "Failed to get peer address");
                return;
            }
        };

        let peer_addr = stream
            .peer_addr()
            .map_or("unknown".to_string(), |addr| addr.to_string());

        info!({ peer_addr = peer_addr }, "New WebSocket connection attempt");

        let tokio_stream = match tokio::net::TcpStream::from_std(stream) {
            Ok(stream) => {
                debug!({ peer_addr = peer_addr }, "Successfully converted to tokio TcpStream");
                stream
            }
            Err(e) => {
                error!(error = %e, "Failed to convert to tokio TcpStream");
                return;
            }
        };

        let ws_stream = match tokio_tungstenite::accept_async(tokio_stream).await {
            Ok(stream) => {
                info!("WebSocket handshake successful");
                stream
            }
            Err(e) => {
                error!(error = %e, "WebSocket handshake failed");
                return;
            }
        };

        let (write, read) = ws_stream.split();
        let write = Arc::new(Mutex::new(write));

        info!("Starting WebSocket message processing");
        self.process_websocket(write, read, ip_addr).await;
    }

    #[instrument(skip_all, fields(peer_addr), parent = &self.span)]
    pub async fn listen(&mut self) -> anyhow::Result<()> {
        let listener = match tokio::net::TcpListener::bind(self.socket_addr).await {
            Ok(l) => l,
            Err(e) => {
                error!(address=?self.socket_addr, "Failed to bind to address: {}", e);
                std::process::exit(1);
            }
        };
        info!("WebSocket server listening on {}", self.socket_addr);

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    info!(peer_addr = %addr, "Incoming websocket connection");
                    let mut clone = self.clone();
                    tokio::spawn(async move {
                        match stream.into_std() {
                            Ok(std_stream) => clone.handle_connection(std_stream).await,
                            Err(e) => error!(error = %e, "Failed to convert stream to std"),
                        }
                    });
                    info!("Connection handler spawned");
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
    }

    #[instrument(skip_all, parent = &self.span)]
    async fn spawn_redis_listener(
        &mut self,
        mut sender: Sender<serde_json::Value>,
        account: AccountId32,
        response: serde_json::Value,
    ) -> anyhow::Result<()> {
        use tokio_stream::StreamExt;

        let redis_cfg = Config::load_static().redis.clone();
        info!(account_id = %account.to_string(), "Starting Redis listener task!");

        tokio::spawn(async move {
            let mut pubsub = match RedisConnection::new_pubsub().await {
                Ok(ps) => ps,
                Err(e) => {
                    error!("Failed to create Redis PubSub: {}", e);
                    return;
                }
            };

            let network = &response["payload"]["message"]["AccountState"]["network"];
            let channel = format!(
                "__keyspace@0__:{}|{}",
                account,
                network.as_str().unwrap_or_default(),
            );

            if let Err(e) = pubsub.subscribe(&channel).await {
                error!("Unable to subscribe to {} because {:?}", channel, e);
                return;
            };

            debug!("Starting message processing loop");
            let mut stream = pubsub
                .on_message()
                .timeout_repeating(tokio::time::interval(Duration::from_secs(
                    redis_cfg.listener_timeout,
                )));

            while let Some(Ok(msg)) = tokio_stream::StreamExt::next(&mut stream).await {
                debug!("Redis event received: {:?}", msg);

                let result = match RedisConnection::process_state_change(&msg).await {
                    Ok(result) => result,
                    Err(e) => {
                        error!(error = %e, "Failed to process Redis message {:?}", msg);
                        break;
                    }
                };

                let (_, obj) = match result {
                    Some(data) => data,
                    None => continue,
                };

                if (sender.send(obj).await).is_err() {
                    info!("WebSocket channel closed, stopping Redis listener");
                    break;
                }
            }
            debug!("Redis listener loop ended");
        });

        debug!("Redis listener task spawned");
        Ok(())
    }

    async fn handle_pgp_verification_request(
        &self,
        request: IncomingVerifyPGPRequest,
        subscriber: &mut Option<AccountId32>,
    ) -> anyhow::Result<serde_json::Value> {
        let cfg = Config::load_static();

        if !cfg.registrar.is_network_supported(&request.network) {
            return Err(anyhow!("Network {} not supported", request.network));
        }

        let network_cfg = cfg.registrar.require_network(&request.network)?;

        *subscriber = Some(request.account.clone());

        let mut conn = RedisConnection::get_connection().await?;
        let mut fingerprint_bytes: Option<[u8; 20]> = None;

        if let Some(verification_state) = conn
            .get_verification_state(&request.network, &request.account)
            .await?
        {
            if let Some(challenge_info) = verification_state.challenges.get(&AccountType::PGPFingerprint)
            {
                if let Ok(bytes) = hex::decode(&challenge_info.account_name) {
                    if bytes.len() == 20 {
                        let mut fp = [0u8; 20];
                        fp.copy_from_slice(&bytes);
                        fingerprint_bytes = Some(fp);
                        info!("Using fingerprint from draft: {}", challenge_info.account_name);
                    }
                }
            }
        }

        if fingerprint_bytes.is_none() {
            let client = NodeClient::from_url(&network_cfg.endpoint).await?;
            let registration = node::get_registration(&client, &request.account).await?;

            if let Some(onchain_fingerprint) = registration.info.pgp_fingerprint {
                fingerprint_bytes = Some(onchain_fingerprint);
                info!(
                    "Using fingerprint from on-chain registration: {}",
                    hex::encode(onchain_fingerprint)
                );
            }
        }

        let registred_fingerprint = fingerprint_bytes.ok_or_else(|| {
            anyhow!(
                "No fingerprint found (neither in draft nor on-chain) for {:?}",
                request.account
            )
        })?;

        let account_id = request.account;

        PGPHelper::verify(
            request.signed_challenge.as_bytes(),
            registred_fingerprint,
            &request.network,
            account_id,
        )
        .await
    }

    async fn handle_pgp_automated_verification_request(
        &self,
        request: IncomingVerifyPGPAutomatedRequest,
        subscriber: &mut Option<AccountId32>,
    ) -> anyhow::Result<serde_json::Value> {
        let cfg = Config::load_static();

        if !cfg.registrar.is_network_supported(&request.network) {
            return Err(anyhow!("Network {} not supported", request.network));
        }

        let network_cfg = cfg.registrar.require_network(&request.network)?;

        *subscriber = Some(request.account.clone());

        let mut conn = RedisConnection::get_connection().await?;
        let mut fingerprint_bytes: Option<[u8; 20]> = None;

        if let Some(verification_state) = conn
            .get_verification_state(&request.network, &request.account)
            .await?
        {
            if let Some(challenge_info) = verification_state.challenges.get(&AccountType::PGPFingerprint)
            {
                if let Ok(bytes) = hex::decode(&challenge_info.account_name) {
                    if bytes.len() == 20 {
                        let mut fp = [0u8; 20];
                        fp.copy_from_slice(&bytes);
                        fingerprint_bytes = Some(fp);
                        info!("Using fingerprint from draft: {}", challenge_info.account_name);
                    }
                }
            }
        }

        if fingerprint_bytes.is_none() {
            let client = NodeClient::from_url(&network_cfg.endpoint).await?;
            let registration = node::get_registration(&client, &request.account).await?;

            if let Some(onchain_fingerprint) = registration.info.pgp_fingerprint {
                fingerprint_bytes = Some(onchain_fingerprint);
                info!(
                    "Using fingerprint from on-chain registration: {}",
                    hex::encode(onchain_fingerprint)
                );
            }
        }

        let fingerprint = fingerprint_bytes.ok_or_else(|| {
            anyhow!(
                "No fingerprint found (neither in draft nor on-chain) for {:?}",
                request.account
            )
        })?;

        let account_id = request.account;

        PGPHelper::verify_automated(fingerprint, &request.network, account_id).await
    }

    async fn handle_upload_pgp_key_request(
        &self,
        request: IncomingUploadPGPKeyRequest,
    ) -> anyhow::Result<serde_json::Value> {
        use sequoia_openpgp::{parse::Parse, Cert};

        let pg_conn = PostgresConnection::default().await?;

        if !pg_conn
            .is_allowed(&request.account, &request.network)
            .await?
        {
            return Err(anyhow!("rate limit exceeded, try again later"));
        } else {
            info!("Requester is allowed");
            pg_conn
                .register_requester(&request.account, &request.network)
                .await?;
        }

        let cfg = Config::load_static();

        if !cfg.registrar.is_network_supported(&request.network) {
            return Err(anyhow!("Network {} not supported", request.network));
        }

        let cert = Cert::from_bytes(request.armored_key.as_bytes())
            .map_err(|e| anyhow!("Invalid PGP key format: {}", e))?;

        let cert_fingerprint = hex::encode(cert.fingerprint().as_bytes());

        if cert_fingerprint.to_lowercase() != request.fingerprint.to_lowercase() {
            return Err(anyhow!(
                "Fingerprint mismatch: provided {} but key has {}",
                request.fingerprint,
                cert_fingerprint
            ));
        }

        let network_cfg = cfg.registrar.require_network(&request.network)?;

        let mut conn = RedisConnection::get_connection().await?;
        let mut expected_fingerprint: Option<String> = None;

        if let Some(verification_state) = conn
            .get_verification_state(&request.network, &request.account)
            .await?
        {
            if let Some(challenge_info) = verification_state.challenges.get(&AccountType::PGPFingerprint)
            {
                expected_fingerprint = Some(challenge_info.account_name.clone());
                info!("Using fingerprint from draft: {}", challenge_info.account_name);
            }
        }

        if expected_fingerprint.is_none() {
            let client = NodeClient::from_url(&network_cfg.endpoint).await?;
            let registration = node::get_registration(&client, &request.account).await?;

            if let Some(onchain_fingerprint) = registration.info.pgp_fingerprint {
                let fp = hex::encode(onchain_fingerprint);
                info!("Using fingerprint from on-chain registration: {}", fp);
                expected_fingerprint = Some(fp);
            }
        }

        let expected_fingerprint_hex = expected_fingerprint.ok_or_else(|| {
            anyhow!(
                "No fingerprint found (neither in draft nor on-chain) for account {:?}",
                request.account
            )
        })?;

        if cert_fingerprint.to_lowercase() != expected_fingerprint_hex.to_lowercase() {
            return Err(anyhow!(
                "Uploaded key fingerprint {} does not match expected fingerprint {}",
                cert_fingerprint,
                expected_fingerprint_hex
            ));
        }

        let pg_conn = PostgresConnection::default().await?;
        pg_conn
            .store_pgp_key(
                &cert_fingerprint,
                &request.account,
                &request.network,
                &request.armored_key,
            )
            .await?;

        Ok(serde_json::json!({
            "type": "JsonResult",
            "payload": {
                "type": "ok",
                "message": "PGP key uploaded successfully",
                "fingerprint": cert_fingerprint
            }
        }))
    }

    async fn handle_update_remailer_settings_request(
        &self,
        request: IncomingUpdateRemailerSettingsRequest,
    ) -> anyhow::Result<serde_json::Value> {
        let cfg = Config::load_static();

        if !cfg.registrar.is_network_supported(&request.network) {
            return Err(anyhow!("Network {} not supported", request.network));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let age_ms = now.saturating_sub(request.timestamp);
        const MAX_AGE_MS: u64 = 5 * 60 * 1000;

        if age_ms > MAX_AGE_MS {
            return Err(anyhow!(
                "Signature timestamp too old: {} ms (max {} ms)",
                age_ms,
                MAX_AGE_MS
            ));
        }

        let message = format!(
            "Update remailer settings\nAccount: {}\nNetwork: {}\nEnabled: {}\nRegistered only: {}\nVerified PGP only: {}\nTimestamp: {}",
            request.account,
            request.network,
            request.remailer_enabled,
            request.remailer_registered_only,
            request.require_verified_pgp,
            request.timestamp
        );

        verify_signature(&request.account, message.as_bytes(), &request.signature)?;

        let network_cfg = cfg.registrar.require_network(&request.network)?;

        let pg_conn = PostgresConnection::default().await?;
        let db_key = pg_conn
            .get_pgp_key_by_address(&request.account, &request.network)
            .await?;

        let Some((db_fingerprint, _)) = db_key else {
            return Err(anyhow!(
                "No PGP key found in database for account {:?}. Upload a key first.",
                request.account
            ));
        };

        let client = NodeClient::from_url(&network_cfg.endpoint).await?;
        let registration = node::get_registration(&client, &request.account).await?;

        let Some(onchain_fingerprint) = registration.info.pgp_fingerprint else {
            return Err(anyhow!(
                "No fingerprint registered on chain for account {:?}",
                request.account
            ));
        };

        let onchain_fingerprint_hex = hex::encode(onchain_fingerprint);

        if db_fingerprint.to_lowercase() != onchain_fingerprint_hex.to_lowercase() {
            return Err(anyhow!(
                "Database fingerprint does not match on-chain fingerprint."
            ));
        }

        pg_conn
            .update_remailer_settings(
                &request.account,
                &request.network,
                request.remailer_enabled,
                request.remailer_registered_only,
                request.require_verified_pgp,
            )
            .await?;

        Ok(serde_json::json!({
            "type": "JsonResult",
            "payload": {
                "type": "ok",
                "message": "Remailer settings updated successfully"
            }
        }))
    }

    async fn handle_fetch_pgp_key_request(
        &self,
        request: IncomingFetchPGPKeyRequest,
    ) -> anyhow::Result<serde_json::Value> {
        let pg_conn = PostgresConnection::default().await?;

        match pg_conn
            .get_pgp_key_by_fingerprint(&request.fingerprint)
            .await?
        {
            Some(armored_key) => Ok(serde_json::json!({
                "type": "JsonResult",
                "payload": {
                    "type": "ok",
                    "armored_key": armored_key,
                    "fingerprint": request.fingerprint
                }
            })),
            None => Ok(serde_json::json!({
                "type": "error",
                "message": format!("No PGP key found for fingerprint: {}", request.fingerprint)
            })),
        }
    }

    async fn handle_search_request(
        &self,
        request: IncomingSearchRequest,
    ) -> anyhow::Result<serde_json::Value> {
        let query: Vec<RegistrationRecord> = request.search().await?;
        Ok(serde_json::to_value(query)?)
    }

    async fn handle_account_history_request(
        &self,
        request: IncomingAccountHistoryRequest,
    ) -> anyhow::Result<serde_json::Value> {
        let pg_conn = PostgresConnection::default().await?;
        let events = pg_conn
            .get_identity_events(&request.account, request.network.as_ref(), request.limit)
            .await?;
        Ok(serde_json::to_value(events)?)
    }

    fn verify_admin_auth(
        &self,
        admin_account: &AccountId32,
        message: &str,
        signature: &str,
        timestamp: u64,
    ) -> anyhow::Result<()> {
        let cfg = Config::load_static();

        let admin_str = admin_account.to_string();
        if !cfg.admin.allowed_accounts.contains(&admin_str) {
            return Err(anyhow!("Account {} is not an authorized admin", admin_str));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| anyhow!("System time error"))?
            .as_millis() as u64;

        let age_ms = now.saturating_sub(timestamp);
        const MAX_AGE_MS: u64 = 5 * 60 * 1000;

        if age_ms > MAX_AGE_MS {
            return Err(anyhow!(
                "Admin signature timestamp too old: {} ms (max {} ms)",
                age_ms,
                MAX_AGE_MS
            ));
        }

        verify_signature(admin_account, message.as_bytes(), signature)?;

        Ok(())
    }

    async fn handle_admin_approve_request(
        &self,
        request: AdminApproveRequest,
    ) -> anyhow::Result<serde_json::Value> {
        let message = format!(
            "approve:{}:{}:{}:{}",
            request.network, request.account, request.account_type, request.timestamp
        );

        self.verify_admin_auth(
            &request.admin_account,
            &message,
            &request.signature,
            request.timestamp,
        )?;

        info!(
            admin = %request.admin_account,
            account = %request.account,
            account_type = %request.account_type,
            network = %request.network,
            "Admin approved verification"
        );

        let mut redis_conn = RedisConnection::get_connection().await?;
        redis_conn
            .update_challenge_status(&request.network, &request.account, &request.account_type)
            .await?;

        let pg_conn = PostgresConnection::default().await?;
        pg_conn
            .update_timeline(
                crate::postgres::TimelineEvent::AdminApproved,
                &request.account,
                &request.network,
            )
            .await?;

        Ok(json!({
            "type": "AdminApproveResponse",
            "success": true,
            "message": format!("Verification for {} approved by admin", request.account_type)
        }))
    }

    async fn handle_admin_reject_request(
        &self,
        request: AdminRejectRequest,
    ) -> anyhow::Result<serde_json::Value> {
        let message = format!(
            "reject:{}:{}:{}",
            request.network, request.account, request.timestamp
        );

        self.verify_admin_auth(
            &request.admin_account,
            &message,
            &request.signature,
            request.timestamp,
        )?;

        info!(
            admin = %request.admin_account,
            account = %request.account,
            network = %request.network,
            reason = ?request.reason,
            "Admin rejected verification"
        );

        let mut redis_conn = RedisConnection::get_connection().await?;
        redis_conn
            .clear_verification_state(&request.network, &request.account)
            .await?;

        let pg_conn = PostgresConnection::default().await?;
        pg_conn
            .update_timeline(
                crate::postgres::TimelineEvent::AdminRejected,
                &request.account,
                &request.network,
            )
            .await?;

        Ok(json!({
            "type": "AdminRejectResponse",
            "success": true,
            "message": "Verification rejected by admin"
        }))
    }

    async fn handle_admin_provide_judgement_request(
        &self,
        request: AdminProvideJudgementRequest,
    ) -> anyhow::Result<serde_json::Value> {
        let message = format!(
            "judge:{}:{}:{}",
            request.network, request.account, request.timestamp
        );

        self.verify_admin_auth(
            &request.admin_account,
            &message,
            &request.signature,
            request.timestamp,
        )?;

        info!(
            admin = %request.admin_account,
            account = %request.account,
            network = %request.network,
            "Admin forcing judgement provision"
        );

        node::provide_judgement(
            &request.account,
            node::substrate::runtime_types::pallet_identity::types::Judgement::Reasonable,
            &request.network,
        )
        .await?;

        let pg_conn = PostgresConnection::default().await?;
        pg_conn
            .update_timeline(
                crate::postgres::TimelineEvent::AdminJudgementProvided,
                &request.account,
                &request.network,
            )
            .await?;

        Ok(json!({
            "type": "AdminProvideJudgementResponse",
            "success": true,
            "message": format!("Judgement provided for {} by admin", request.account)
        }))
    }

    async fn handle_remailer_block_request(
        &self,
        request: RemailerBlockRequest,
    ) -> anyhow::Result<serde_json::Value> {
        let cfg = Config::load_static();

        if !cfg.registrar.is_network_supported(&request.network) {
            return Err(anyhow!("Network {} not supported", request.network));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let age_ms = now.saturating_sub(request.timestamp);
        const MAX_AGE_MS: u64 = 5 * 60 * 1000;

        if age_ms > MAX_AGE_MS {
            return Err(anyhow!(
                "Signature timestamp too old: {} ms (max {} ms)",
                age_ms,
                MAX_AGE_MS
            ));
        }

        let message = format!(
            "Block sender\nAccount: {}\nNetwork: {}\nBlocked: {}\nTimestamp: {}",
            request.account, request.network, request.blocked_address, request.timestamp
        );

        verify_signature(&request.account, message.as_bytes(), &request.signature)?;

        let pg_conn = PostgresConnection::default().await?;
        pg_conn
            .remailer_block_sender(
                &request.account,
                &request.network,
                &request.blocked_address,
                request.reason.as_deref(),
            )
            .await?;

        info!(
            account = %request.account,
            network = %request.network,
            blocked = %request.blocked_address,
            "Blocked sender via remailer"
        );

        Ok(json!({
            "type": "JsonResult",
            "payload": {
                "type": "ok",
                "message": format!("Blocked {} from contacting you", request.blocked_address)
            }
        }))
    }

    async fn handle_remailer_unblock_request(
        &self,
        request: RemailerUnblockRequest,
    ) -> anyhow::Result<serde_json::Value> {
        let cfg = Config::load_static();

        if !cfg.registrar.is_network_supported(&request.network) {
            return Err(anyhow!("Network {} not supported", request.network));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let age_ms = now.saturating_sub(request.timestamp);
        const MAX_AGE_MS: u64 = 5 * 60 * 1000;

        if age_ms > MAX_AGE_MS {
            return Err(anyhow!(
                "Signature timestamp too old: {} ms (max {} ms)",
                age_ms,
                MAX_AGE_MS
            ));
        }

        let message = format!(
            "Unblock sender\nAccount: {}\nNetwork: {}\nUnblocked: {}\nTimestamp: {}",
            request.account, request.network, request.blocked_address, request.timestamp
        );

        verify_signature(&request.account, message.as_bytes(), &request.signature)?;

        let pg_conn = PostgresConnection::default().await?;
        pg_conn
            .remailer_unblock_sender(&request.account, &request.network, &request.blocked_address)
            .await?;

        info!(
            account = %request.account,
            network = %request.network,
            unblocked = %request.blocked_address,
            "Unblocked sender via remailer"
        );

        Ok(json!({
            "type": "JsonResult",
            "payload": {
                "type": "ok",
                "message": format!("Unblocked {}", request.blocked_address)
            }
        }))
    }

    async fn handle_remailer_get_blocked_request(
        &self,
        request: RemailerGetBlockedRequest,
    ) -> anyhow::Result<serde_json::Value> {
        let cfg = Config::load_static();

        if !cfg.registrar.is_network_supported(&request.network) {
            return Err(anyhow!("Network {} not supported", request.network));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let age_ms = now.saturating_sub(request.timestamp);
        const MAX_AGE_MS: u64 = 5 * 60 * 1000;

        if age_ms > MAX_AGE_MS {
            return Err(anyhow!(
                "Signature timestamp too old: {} ms (max {} ms)",
                age_ms,
                MAX_AGE_MS
            ));
        }

        let message = format!(
            "Get blocked senders\nAccount: {}\nNetwork: {}\nTimestamp: {}",
            request.account, request.network, request.timestamp
        );

        verify_signature(&request.account, message.as_bytes(), &request.signature)?;

        let pg_conn = PostgresConnection::default().await?;
        let blocked = pg_conn
            .remailer_get_blocked(&request.account, &request.network)
            .await?;

        Ok(json!({
            "type": "JsonResult",
            "payload": {
                "type": "ok",
                "blocked": blocked
            }
        }))
    }

    /// Handle RemailerSendMessage request - forward a message to another user via Matrix
    #[instrument(skip_all, parent = &self.span)]
    async fn handle_remailer_send_message_request(
        &self,
        request: RemailerSendMessageRequest,
    ) -> anyhow::Result<serde_json::Value> {
        let cfg = Config::load_static();

        if !cfg.registrar.is_network_supported(&request.network) {
            return Err(anyhow!("Network {} not supported", request.network));
        }

        // Verify timestamp to prevent replay attacks
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let age_ms = now.saturating_sub(request.timestamp);
        const MAX_AGE_MS: u64 = 5 * 60 * 1000;

        if age_ms > MAX_AGE_MS {
            return Err(anyhow!(
                "Signature timestamp too old: {} ms (max {} ms)",
                age_ms,
                MAX_AGE_MS
            ));
        }

        // Verify signature
        let message = format!(
            "Send message\nFrom: {}\nTo: {}\nNetwork: {}\nRecipient Network: {}\nMessage: {}\nTimestamp: {}",
            request.sender, request.recipient, request.network, request.recipient_network, request.message, request.timestamp
        );

        verify_signature(&request.sender, message.as_bytes(), &request.signature)?;

        // Get recipient's registration to find their Matrix ID
        let pg_conn = PostgresConnection::default().await?;
        let recipient_reg = pg_conn
            .get_registration(&request.recipient, &request.recipient_network)
            .await?;

        let matrix_id = match recipient_reg.and_then(|r| r.matrix) {
            Some(m) if !m.is_empty() => m,
            _ => {
                return Ok(json!({
                    "type": "JsonResult",
                    "payload": {
                        "type": "error",
                        "message": "Recipient has no Matrix ID configured"
                    }
                }));
            }
        };

        // Check if sender is blocked by recipient
        if pg_conn
            .remailer_is_blocked(&request.recipient, &request.recipient_network, &request.sender.to_string())
            .await?
        {
            return Ok(json!({
                "type": "JsonResult",
                "payload": {
                    "type": "error",
                    "message": "You are blocked by this recipient"
                }
            }));
        }

        // Format and send the message
        let formatted_message = format!(
            "📬 Message from {}\nNetwork: {}\n\n{}",
            request.sender, request.network, request.message
        );

        send_matrix_dm(&matrix_id, &formatted_message).await?;

        info!(
            "Remailer: forwarded message from {} to {} ({})",
            request.sender, request.recipient, matrix_id
        );

        Ok(json!({
            "type": "JsonResult",
            "payload": {
                "type": "ok",
                "message": "Message sent successfully"
            }
        }))
    }

    /// Handle InitiateChallenge request - sends challenge to email/matrix before on-chain submission
    #[instrument(skip_all, parent = &self.span)]
    async fn handle_initiate_challenge_request(
        &self,
        request: InitiateChallengeRequest,
    ) -> anyhow::Result<serde_json::Value> {
        let cfg = Config::load_static();

        if !cfg.registrar.is_network_supported(&request.network) {
            return Ok(json!({
                "type": "error",
                "message": format!("Network {} not supported", request.network)
            }));
        }

        // Validate field value is not empty
        if request.field_value.trim().is_empty() {
            return Ok(json!({
                "type": "error",
                "message": "Field value cannot be empty"
            }));
        }

        info!(
            account = %request.account,
            field_type = ?request.field_type,
            network = %request.network,
            "Initiating challenge for field"
        );

        let mut redis_conn = RedisConnection::get_connection().await?;

        // Get or create verification state
        let mut verification = redis_conn
            .get_verification_state(&request.network, &request.account)
            .await?
            .unwrap_or_else(|| AccountVerification::new(request.network.to_string()));

        // Generate a new token for this field
        let token = crate::token::Token::generate_sync(8);

        // Create the account based on field type and value
        let account = match request.field_type {
            AccountType::Email => Account::Email(request.field_value.clone()),
            AccountType::Matrix => Account::Matrix(request.field_value.clone()),
            AccountType::Twitter => Account::Twitter(request.field_value.clone()),
            AccountType::Discord => Account::Discord(request.field_value.clone()),
            AccountType::Github => Account::Github(request.field_value.clone()),
            AccountType::Web => Account::Web(request.field_value.clone()),
            _ => {
                return Ok(json!({
                    "type": "error",
                    "message": format!("Unsupported field type: {:?}", request.field_type)
                }));
            }
        };

        // Add/update the challenge
        verification.add_challenge(&request.field_type, request.field_value.clone(), Some(token.clone()));

        // Build accounts map for Redis
        let mut accounts = std::collections::HashMap::new();
        accounts.insert(account.clone(), false);

        // Save to Redis
        redis_conn
            .init_verification_state(&request.network, &request.account, &verification, &accounts)
            .await?;

        // Send the challenge based on field type
        match request.field_type {
            AccountType::Email => {
                if matches!(cfg.adapter.email.protocol, crate::config::EmailProtocol::Jmap)
                    && matches!(
                        cfg.adapter.email.mode,
                        crate::config::EmailMode::Send | crate::config::EmailMode::Bidirectional
                    )
                {
                    info!(
                        "Sending email challenge to {} for {}/{}",
                        request.field_value, request.network, request.account
                    );
                    if let Err(e) = send_email_challenge(
                        &request.field_value,
                        &token,
                        &request.network,
                        &request.account,
                    )
                    .await
                    {
                        error!("Failed to send email challenge: {}", e);
                        return Ok(json!({
                            "type": "error",
                            "message": format!("Failed to send email challenge: {}", e)
                        }));
                    }
                }
            }
            AccountType::Matrix => {
                // Send Matrix DM with challenge (works with bridges too)
                info!(
                    "Sending Matrix challenge to {} for {}/{}",
                    request.field_value, request.network, request.account
                );
                if let Err(e) = send_matrix_challenge(
                    &request.field_value,
                    &token,
                    &request.network,
                    &request.account,
                )
                .await
                {
                    error!("Failed to send Matrix challenge: {}", e);
                    return Ok(json!({
                        "type": "error",
                        "message": format!("Failed to send Matrix challenge: {}", e)
                    }));
                }
            }
            _ => {
                // Other field types don't have automated challenge sending yet
                info!(
                    "Challenge initiated for {:?} - manual verification required",
                    request.field_type
                );
            }
        }

        // Return success with challenge info
        Ok(json!({
            "type": "JsonResult",
            "payload": {
                "type": "ok",
                "message": {
                    "InitiateChallengeResponse": {
                        "field_type": format!("{:?}", request.field_type),
                        "challenge_sent": matches!(request.field_type, AccountType::Email | AccountType::Matrix),
                        "instructions": match request.field_type {
                            AccountType::Email => "Check your email for the verification code",
                            AccountType::Matrix => "Check your Matrix DMs for the verification code",
                            _ => "Complete the verification challenge"
                        }
                    }
                }
            }
        }))
    }
}

pub async fn spawn_ws_serv() -> anyhow::Result<()> {
    let mut listener = SocketListener::new().await?;
    listener.listen().await
}

struct RedisSubscriber {
    redis_cfg: RedisConfig,
    span: Span,
}

impl RedisSubscriber {
    fn new(redis_cfg: RedisConfig) -> Self {
        let span = info_span!("redis_subscriber");
        Self { redis_cfg, span }
    }

    #[instrument(skip_all, parent = &self.span)]
    pub async fn listen(&mut self) -> anyhow::Result<()> {
        let mut pubsub = RedisConnection::new_pubsub().await?;
        pubsub.psubscribe("__keyspace@0__:*").await?;
        let mut stream = pubsub.on_message();
        while let Some(msg) = stream.next().await {
            info!("Redis event occured");
            if let Err(e) = self.handle_redis_message(msg).await {
                error!(error = %e, "Failed to handle Redis message");
                continue;
            }
        }
        info!("Redis subscription ended");
        Ok(())
    }

    #[instrument(skip_all, parent = &self.span)]
    pub async fn process_state_change(
        &self,
        msg: &Msg,
    ) -> anyhow::Result<Option<(AccountId32, serde_json::Value)>> {
        let mut conn = RedisConnection::get_connection().await?;
        let payload: String = msg.get_payload()?;
        let channel = msg.get_channel_name();

        info!(payload = ?payload, channel = ?channel, "Processing Redis message");

        if !matches!(payload.as_str(), "set" | "del") {
            info!("Ignoring Redis operation: {}", payload);
            return Ok(None);
        }

        let key = match channel.strip_prefix("__keyspace@0__:") {
            Some(k) => k,
            None => return Ok(None),
        };

        let (account_id, network) = match key.split_once('|') {
            Some(parts) => parts,
            None => return Ok(None),
        };

        let id = AccountId32::from_str(account_id)?;
        let network = Network::from_str(network)?;

        let account_state = conn.build_account_state_message(&network, &id, None).await?;

        Ok(Some((id, account_state)))
    }

    #[instrument(skip_all, parent = &self.span)]
    async fn handle_redis_message(&self, msg: Msg) -> anyhow::Result<()> {
        if let Ok(Some((id, value))) = self.process_state_change(&msg).await {
            info!(
                account_id = %id.to_string(),
                new_state = %value.to_string(),
                "Processed new state"
            );
        }
        Ok(())
    }
}

pub async fn spawn_redis_subscriber() -> anyhow::Result<()> {
    let redis_cfg = Config::load_static().redis.clone();
    RedisSubscriber::new(redis_cfg).listen().await
}

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

        if let Ok(account_id) = AccountId32::from_str(parts[3]) {
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

/// Get identity events for a wallet
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

/// Trigger full history backfill for a network (admin endpoint)
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

    // Spawn backfill in background
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

    let app = Router::new()
        .route(redirect_url.path(), get(github_oauth_callback))
        .route("/ping", get(pong))
        .route("/events/{network}/{wallet}", get(get_events))
        .route("/admin/backfill/{network}", axum::routing::post(trigger_backfill));
    let listener = tokio::net::TcpListener::bind(&(http_config.host, http_config.port)).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[instrument(name = "identity_indexer")]
pub async fn spawn_identity_indexer() -> anyhow::Result<()> {
    Indexer::new().await?.index().await
}

#[cfg(test)]
mod unit_test {
    use super::*;
    use serde_json::to_string_pretty;

    #[tokio::test]
    async fn se_de_ws_request() {
        let wallet_id: String = String::from("5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty");
        let ws_msg = to_string_pretty(&serde_json::json!({
            "version": "1.0",
            "type": "SubscribeAccountState",
            "payload": {
                "network": "paseo",
                "account": wallet_id,
            },
        }))
        .unwrap();

        assert!(serde_json::from_str::<VersionedMessage>(&ws_msg).is_ok());

        let ws_msg = to_string_pretty(&serde_json::json!({
            "version": "1.0",
            "type": "VerifyPGPKey",
            "payload": {
                "network": "paseo",
                "account": wallet_id,
                "pubkey": "asdf",
                "signed_challenge": "asdf",
            },
        }))
        .unwrap();

        assert!(serde_json::from_str::<VersionedMessage>(&ws_msg).is_ok());

        let ws_msg = to_string_pretty(&serde_json::json!({
          "version": "1.0",
          "type": "SearchRegistration",
          "payload": {
              "network": "kusama",
              "outputs": ["WalletID", "Discord", "Timeline"],
              "filters": {
                  "fields": [
                      { "field": { "AccountId32": wallet_id }, "strict": false},
                  ],
                  "result_size": 3,
              }
          }
        }))
        .unwrap();

        assert!(serde_json::from_str::<VersionedMessage>(&ws_msg).is_ok());

        let ws_msg = to_string_pretty(&serde_json::json!({
          "version": "1.0",
          "type": "SearchRegistration",
          "payload": {
              "outputs": [],
              "filters": {
                  "fields": [],
              }
          }
        }))
        .unwrap();

        assert!(serde_json::from_str::<VersionedMessage>(&ws_msg).is_ok());
    }
}

#[cfg(test)]
mod test {
    #[allow(unused_imports)]
    use super::*;
    use crate::postgres::{DisplayedInfo, Query, RegistrationQuery, SearchInfo};

    #[test]
    fn generic_search() {
        let request = IncomingSearchRequest::new(
            Some(Network::Paseo),
            vec![DisplayedInfo::Github],
            Filter::new(
                vec![
                    FieldsFilter {
                        strict: true,
                        field: SearchInfo::Twitter("X".to_string()),
                    },
                    FieldsFilter {
                        strict: true,
                        field: SearchInfo::Generic("Y".to_string()),
                    },
                ],
                Some(10),
                None,
            ),
        );
        let query: RegistrationQuery = (&request).into();
        assert_eq!(
            query.statement(),
            "SELECT github FROM (SELECT similarity($1, search_text) AS sim, * FROM registration) WHERE twitter = $2 AND network = $3 AND sim > 0 ORDER BY sim DESC LIMIT 10".to_string()
        );
        assert_eq!(query.params(), vec!["Y", "X", "paseo",]);

        let request = IncomingSearchRequest::new(
            None,
            vec![DisplayedInfo::Github],
            Filter::new(
                vec![FieldsFilter {
                    strict: false,
                    field: SearchInfo::Generic("X".to_string()),
                }],
                Some(10),
                None,
            ),
        );
        let query: RegistrationQuery = (&request).into();

        assert_eq!(
            query.statement(),
            "SELECT github FROM (SELECT similarity($1, search_text) AS sim, * FROM registration) WHERE sim > 0 ORDER BY sim DESC LIMIT 10".to_string()
        );
        assert_eq!(query.params(), vec!["X"]);

        let request = IncomingSearchRequest::new(
            None,
            vec![DisplayedInfo::Github],
            Filter::new(
                vec![FieldsFilter {
                    strict: false,
                    field: SearchInfo::Matrix("X".to_string()),
                }],
                Some(10),
                None,
            ),
        );

        let query: RegistrationQuery = (&request).into();
        assert_eq!(
            query.statement(),
            "SELECT github FROM registration WHERE matrix ILIKE $1 LIMIT 10".to_string()
        );
        assert_eq!(query.params(), vec!["%X%"]);
    }
}
