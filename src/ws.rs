use crate::api::ChallengedAccount;
use crate::api::IncomingSubscribeRequest;
use crate::api::SubscribeAccountState;
use crate::api::VersionedMessage;
use crate::common::get_registration;
use crate::common::identity_data_tostring;
use crate::common::string_to_account_id;
use crate::node::runtime_types::pallet_identity::types::Registration;
use crate::node::runtime_types::people_rococo_runtime::people::IdentityInfo;
use crate::node::Client as NodeClient;
use crate::token::AuthToken;
use anyhow::anyhow;
use futures::channel::mpsc::{self, Sender};
use futures::stream::SplitSink;
use futures::SinkExt;
use futures::StreamExt;
use futures_util::stream::SplitStream;
use redis::{self, Client as RedisClient, Commands};
use serde_json::json;
use sp_core::blake2_256;
use sp_core::Encode;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use subxt::utils::AccountId32;
use tokio::{net::TcpStream, sync::Mutex};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use tracing::{debug, error, info, span, Level};

use tokio;

use crate::{
    api::{Account, AccountVerification, SubscribeAccountStateRequest, VerifyIdentityRequest},
    config::{RedisConfig, GLOBAL_CONFIG},
    node::filter_accounts,
    redis::RedisConnection,
    token::Token,
};

#[derive(Debug, Clone)]
pub struct Listener {
    redis_cfg: RedisConfig,
    socket_addr: SocketAddr,
}

impl Listener {
    pub async fn new() -> Self {
        let cfg = GLOBAL_CONFIG
            .get()
            .expect("GLOBAL_CONFIG is not initialized");
        Self {
            redis_cfg: cfg.redis.clone(),
            socket_addr: cfg.websocket.socket_addrs().unwrap(),
        }
    }

    pub async fn handle_subscription_request(
        &mut self,
        request: SubscribeAccountStateRequest,
        network: &str,
        subscriber: &mut Option<AccountId32>,
    ) -> anyhow::Result<serde_json::Value> {
        let cfg = GLOBAL_CONFIG
            .get()
            .expect("GLOBAL_CONFIG is not initialized");

        if !cfg.registrar.is_network_supported(network) {
            return Ok(serde_json::json!({
                "type": "error",
                "message": format!("Network {} not supported", network)
            }));
        }

        let network_cfg = cfg
            .registrar
            .get_network(network)
            .ok_or_else(|| anyhow!("Network {} not configured", network))?;

        *subscriber = Some(request.payload.clone());
        let client = NodeClient::from_url(&network_cfg.endpoint).await?;
        let registration = get_registration(&client, &request.payload).await?;

        let mut conn = RedisConnection::create_conn(&self.redis_cfg)?;

        // 1) attempt to load existing verification state, if any
        let existing_verification = conn
            .get_verification_state(network, &request.payload)
            .await?;

        // 2) if none found, create a fresh AccountVerification
        let mut verification =
            existing_verification.unwrap_or_else(|| AccountVerification::new(network.to_string()));

        // get the accounts from the chain’s identity info
        let accounts = filter_accounts(
            &registration.info,
            &request.payload,
            network_cfg.registrar_index,
            network,
        )
        .await?;

        // 3) for each discovered account, only create a token if we do not
        //    already have one stored. Otherwise, reuse the old token/challenge.
        for (account, is_done) in &accounts {
            let (acc_type, name) = match account {
                Account::Discord(name) => ("discord", name),
                Account::Twitter(name) => ("twitter", name),
                Account::Matrix(name) => ("matrix", name),
                Account::Display(name) => ("display_name", name),
                Account::Email(name) => ("email", name),
                Account::Github(name) => ("github", name),
                Account::Legal(name) => ("legal", name),
                Account::Web(name) => ("web", name),
                Account::PGPFingerprint(bytes) => ("pgp_fingerprint", &hex::encode(bytes)),
            };

            // only add a new challenge if not already present.
            // if *is_done or it's a display_name, we set `token=None` so it's considered done.
            if !verification.challenges.contains_key(acc_type) {
                let token = if *is_done || matches!(account, Account::Display(_)) {
                    None
                } else {
                    Some(Token::generate().await.show())
                };
                verification.add_challenge(acc_type, name.clone(), token);
            }
        }

        // save new state
        conn.init_verification_state(network, &request.payload, &verification, &accounts)
            .await?;

        // everything below is unchanged: hashing, building JSON response, etc.
        let hash = self.hash_identity_info(&registration.info);

        let fields = conn.extract_info(network, &request.payload).await?;
        let pending_challenges = conn.get_challenges(network, &request.payload).await?;

        Ok(serde_json::json!({
            "type": "JsonResult",
            "payload": {
                "type": "ok",
                "message": {
                    "AccountState": {
                        "account": request.payload.to_string(),
                        "network": network,
                        "hashed_info": hash,
                        "verification_state": {
                            "fields": fields
                        },
                        "pending_challenges": pending_challenges
                    }
                }
            }
        }))
    }

    pub async fn handle_identity_verification_request(
        &self,
        request: VerifyIdentityRequest,
    ) -> anyhow::Result<serde_json::Value> {
        let account_id = string_to_account_id(&request.payload.account)?;
        let mut conn = RedisConnection::create_conn(&self.redis_cfg)?;

        let state = conn
            .get_verification_state("rococo", &account_id)
            .await?
            .ok_or_else(|| anyhow!("No verification state found"))?;

        let acc_type = request.payload.field.to_string();
        let challenge = state
            .challenges
            .get(&acc_type)
            .ok_or_else(|| anyhow!("No challenge found for {}", acc_type))?;

        match &challenge.token {
            Some(token) if token == &request.payload.challenge => {
                // Mark challenge as complete
                conn.update_challenge_status("rococo", &account_id, &acc_type)
                    .await?;

                Ok(serde_json::json!({
                    "type": "ok",
                    "message": true,
                }))
            }
            Some(token) => Ok(serde_json::json!({
                "type": "error",
                "reason": format!(
                    "{} is not equal to the challenge token",
                    token
                ),
            })),
            None => Ok(serde_json::json!({
                "type": "error",
                "reason": "No active challenge found"
            })),
        }
    }

    /// Generates a hex-encoded blake2 hash of the identity info with 0x prefix
    fn hash_identity_info(&self, info: &IdentityInfo) -> String {
        let encoded_info = info.encode();
        let hash = blake2_256(&encoded_info);
        format!("0x{}", hex::encode(hash))
    }

    async fn process_v1(
        &mut self,
        message: VersionedMessage,
        subscriber: &mut Option<AccountId32>,
    ) -> anyhow::Result<serde_json::Value> {
        match message.message_type.as_str() {
            "SubscribeAccountState" => {
                let incoming: IncomingSubscribeRequest = serde_json::from_value(message.payload)
                    .map_err(|e| anyhow!("Invalid SubscribeAccountState payload: {}", e))?;

                let internal_request = SubscribeAccountStateRequest {
                    _type: SubscribeAccountState::SubscribeAccountState,
                    payload: incoming.account,
                };

                self.handle_subscription_request(internal_request, &incoming.network, subscriber)
                    .await
            }
            "VerifyIdentity" => {
                let verify_request: ChallengedAccount = serde_json::from_value(message.payload)
                    .map_err(|e| anyhow!("Invalid VerifyIdentity payload: {}", e))?;

                let internal_request = VerifyIdentityRequest {
                    _type: "VerifyIdentity".to_string(),
                    payload: verify_request,
                };

                self.handle_identity_verification_request(internal_request)
                    .await
            }
            _ => Err(anyhow!(
                "Unsupported message type: {}",
                message.message_type
            )),
        }
    }

    pub async fn _handle_incoming(
        &mut self,
        message: Message,
        subscriber: &mut Option<AccountId32>,
    ) -> anyhow::Result<serde_json::Value> {
        // 1) ensure the message is text
        let text = match message {
            Message::Text(t) => t,
            _ => {
                return Ok(json!({
                    "type": "error",
                    "message": "Unsupported message format"
                }))
            }
        };

        // 2) attempt to parse the JSON into a VersionedMessage
        let versioned_msg: VersionedMessage = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => {
                return Ok(json!({
                    "type": "error",
                    "message": format!("Failed to parse message: {}", e)
                }))
            }
        };

        // 3) check the version
        if versioned_msg.version.as_str() != "1.0" {
            return Ok(json!({
                "type": "error",
                "message": format!("Unsupported version: {}", versioned_msg.version),
            }));
        }

        // 4) handle the v1 version
        match self.process_v1(versioned_msg, subscriber).await {
            Ok(response) => Ok(response),
            Err(e) => Ok(json!({
                "type": "error",
                "message": e.to_string()
            })),
        }
    }

    /// Compares between the accounts on the idendtity object on the check_node
    /// and the received requests
    /// TODO: migrate this to a common module
    pub fn is_complete<'a>(
        registration: &Registration<u128, IdentityInfo>,
        expected: &Vec<Account>,
    ) -> anyhow::Result<(), anyhow::Error> {
        for acc in expected {
            let (stored_acc, expected_acc) = match acc {
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
                Account::Email(email_acc) => {
                    (identity_data_tostring(&registration.info.email), email_acc)
                }
                _ => todo!(),
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

    async fn monitor_hash_changes(client: RedisClient, key: String) -> Option<String> {
        let mut pubsub = client.get_async_pubsub().await.unwrap();
        let channel = format!("__keyspace@0__:{}", key);
        pubsub.subscribe(channel).await.unwrap();
        while let Some(_) = pubsub.on_message().next().await {
            let mut con = client.get_connection().unwrap();
            let done: String = con.hget(&key, String::from("done")).unwrap();
            let done: bool = serde_json::from_str(&done).unwrap();
            if done {
                return Some(String::from("Done"));
            }
        }
        return None;
    }

    pub async fn filter_message(message: &Message) -> Option<AccountId32> {
        if let Message::Text(text) = message {
            let parsed: VersionedMessage = serde_json::from_str(text).ok()?;
            let account_str = parsed.payload.as_str()?;
            return AccountId32::from_str(account_str).ok();
        }
        None
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

    async fn process_websocket(
        &mut self,
        write: Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>,
        mut read: SplitStream<WebSocketStream<TcpStream>>,
        span: tracing::Span,
    ) {
        let mut subscriber: Option<AccountId32> = None;
        let (sender, mut receiver) = mpsc::channel::<serde_json::Value>(100);

        loop {
            tokio::select! {
                Some(msg) = receiver.next() => {
                    if !self.handle_channel_message(&write, msg, &span).await {
                        break;
                    }
                }

                Some(msg_result) = read.next() => {
                    match msg_result {
                        Ok(Message::Close(_)) => {
                            info!(parent: &span, "Received close frame");
                            break;
                        }
                        _ => {
                            if !self.handle_ws_message(&write, msg_result, &mut subscriber, sender.clone(), &span).await {
                                break;
                            }
                        }
                    }
                }

                else => {
                    info!(parent: &span, "WebSocket or channel stream ended");
                    break;
                }
            }
        }

        // Cleanup
        if let Some(id) = subscriber {
            info!(parent: &span, subscriber_id = %id, "Cleaning up subscriber");
        }
        info!(parent: &span, "WebSocket connection closed");
    }

    async fn handle_channel_message(
        &self,
        write: &Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>,
        msg: serde_json::Value,
        span: &tracing::Span,
    ) -> bool {
        let resp_type = msg
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        match serde_json::to_string(&msg) {
            Ok(serialized) => {
                debug!(parent: span, response_type = %resp_type, "Sending response");
                match Self::send_message(write, serialized).await {
                    Ok(_) => true,
                    Err(e) => {
                        error!(parent: span, error = %e, "Failed to send message");
                        false
                    }
                }
            }
            Err(e) => {
                error!(parent: span, error = %e, "Failed to serialize response");
                true
            }
        }
    }

    async fn handle_ws_message(
        &mut self,
        write: &Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>,
        msg_result: Result<Message, tokio_tungstenite::tungstenite::Error>,
        subscriber: &mut Option<AccountId32>,
        sender: Sender<serde_json::Value>,
        span: &tracing::Span,
    ) -> bool {
        match msg_result {
            Ok(Message::Text(bytes)) => {
                // Convert Utf8Bytes to string using to_string()
                let text = bytes.to_string();
                self.handle_text_message(write, text, subscriber, sender, span)
                    .await
            }
            Ok(Message::Close(_)) => {
                info!(parent: span, "Received close frame");
                false
            }
            Ok(_) => {
                debug!(parent: span, "Received non-text message");
                true
            }
            Err(e) => {
                error!(parent: span, error = %e, "WebSocket error");
                false
            }
        }
    }

    async fn handle_text_message(
        &mut self,
        write: &Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>,
        text: String,
        subscriber: &mut Option<AccountId32>,
        sender: Sender<serde_json::Value>,
        span: &tracing::Span,
    ) -> bool {
        let parsed: VersionedMessage = match serde_json::from_str(&text) {
            Ok(msg) => msg,
            Err(_) => {
                error!(parent: span, "Failed to parse WebSocket message");
                return true;
            }
        };

        info!(
            parent: span,
            message_version = %parsed.version,
            message_type = %parsed.message_type,
            "Received WebSocket message"
        );

        match self
            ._handle_incoming(Message::Text(text.into()), subscriber)
            .await
        {
            Ok(response) => {
                let serialized = match serde_json::to_string(&response) {
                    Ok(s) => s,
                    Err(e) => {
                        error!(parent: span, error = %e, "Failed to serialize response");
                        return true;
                    }
                };

                if let Err(e) = Self::send_message(write, serialized).await {
                    error!(parent: span, error = %e, "Failed to send response");
                    return false;
                }

                if let Some(id) = subscriber.take() {
                    info!(parent: span, subscriber_id = %id, "New subscriber registered");
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
            Err(e) => self.handle_error_response(write, e, span).await,
        }
    }

    async fn handle_successful_response(
        &self,
        write: &Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>,
        response: serde_json::Value,
        subscriber: &mut Option<AccountId32>,
        sender: Sender<serde_json::Value>,
        span: &tracing::Span,
    ) -> bool {
        debug!("Handling successful response: {:?}", response);

        let serialized = match serde_json::to_string(&response) {
            Ok(s) => s,
            Err(e) => {
                error!(parent: span, error = %e, "Failed to serialize response");
                return true;
            }
        };

        let resp_type = response
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        debug!(parent: span, response_type = %resp_type, "Sending response");

        if let Err(e) = Self::send_message(write, serialized).await {
            error!(parent: span, error = %e, "Failed to send response");
            return false;
        }

        if let Some(id) = subscriber.take() {
            info!(parent: span, subscriber_id = %id, "New subscriber registered");
            let mut cloned_self = self.clone();
            tokio::spawn(async move {
                if let Err(e) = cloned_self.spawn_redis_listener(sender, id, response).await {
                    error!(error = %e, "Redis listener error");
                }
            });
        }

        true
    }

    async fn handle_error_response(
        &self,
        write: &Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>,
        error: anyhow::Error,
        span: &tracing::Span,
    ) -> bool {
        error!(parent: span, error = %error, "Error handling message");

        let error_response = serde_json::json!({
            "version": "1.0",
            "error": error.to_string()
        });

        match serde_json::to_string(&error_response) {
            Ok(serialized) => match Self::send_message(write, serialized).await {
                Ok(_) => true,
                Err(e) => {
                    error!(parent: span, error = %e, "Failed to send error response");
                    false
                }
            },
            Err(e) => {
                error!(parent: span, error = %e, "Failed to serialize error response");
                true
            }
        }
    }

    /// Handles incoming websocket connection
    pub async fn handle_connection(&mut self, stream: std::net::TcpStream) {
        let peer_addr = stream
            .peer_addr()
            .map_or("unknown".to_string(), |addr| addr.to_string());
        let conn_span = span!(Level::INFO, "ws_connection", peer_addr = %peer_addr);

        info!(parent: &conn_span, "New WebSocket connection attempt");

        let tokio_stream = match tokio::net::TcpStream::from_std(stream) {
            Ok(stream) => {
                debug!(parent: &conn_span, "Successfully converted to tokio TcpStream");
                stream
            }
            Err(e) => {
                error!(parent: &conn_span, error = %e, "Failed to convert to tokio TcpStream");
                return;
            }
        };

        let ws_stream = match tokio_tungstenite::accept_async(tokio_stream).await {
            Ok(stream) => {
                info!(parent: &conn_span, "WebSocket handshake successful");
                stream
            }
            Err(e) => {
                error!(parent: &conn_span, error = %e, "WebSocket handshake failed");
                return;
            }
        };

        let (write, read) = ws_stream.split();
        let write = Arc::new(Mutex::new(write));

        info!(parent: &conn_span, "Starting WebSocket message processing");
        self.process_websocket(write, read, conn_span).await;
    }

    /// websocket listener
    pub async fn listen(&mut self) -> ! {
        let listener = match tokio::net::TcpListener::bind(self.socket_addr).await {
            Ok(l) => l,
            Err(e) => {
                error!("Failed to bind to address: {}", e);
                std::process::exit(1);
            }
        };
        info!("WebSocket server listening on {}", self.socket_addr);

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    info!("Incoming connection from {:?}...", addr);
                    let mut clone = self.clone();
                    tokio::spawn(async move {
                        clone.handle_connection(stream.into_std().unwrap()).await;
                    });
                    info!("Connection handler spawned");
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
    }

    async fn spawn_redis_listener(
        &mut self,
        mut sender: Sender<serde_json::Value>,
        account: AccountId32,
        response: serde_json::Value,
    ) -> anyhow::Result<()> {
        let redis_cfg = self.redis_cfg.clone();
        info!("Starting Redis listener task!");

        tokio::spawn(async move {
            let mut redis_conn = match RedisConnection::create_conn(&redis_cfg) {
                Ok(conn) => conn,
                Err(e) => {
                    error!("Failed to create Redis connection: {}", e);
                    return;
                }
            };

            let mut pubsub = redis_conn.as_pubsub();
            let network = &response["payload"]["message"]["AccountState"]["network"];
            let channel = format!(
                "__keyspace@0__:{}:{}",
                account,
                network.as_str().unwrap_or_default(),
            );

            info!("Subscribing to channel: {}", channel);
            if let Err(e) = pubsub.subscribe(&channel) {
                error!("Failed to subscribe to channel: {}", e);
                return;
            }

            debug!("Starting message processing loop");
            loop {
                // get message or break on error
                let msg = match pubsub.get_message() {
                    Ok(msg) => msg,
                    Err(e) => {
                        error!("Error getting Redis message: {}", e);
                        break;
                    }
                };

                debug!("Redis event received: {:?}", msg);

                // process message, continue on error
                let result = match RedisConnection::process_state_change(&redis_cfg, &msg).await {
                    Ok(result) => result,
                    Err(e) => {
                        info!("Failed to process Redis message {:?}: {:#?}", msg, e);
                        continue;
                    }
                };

                // extract object if it exists, continue if none
                let (_, obj) = match result {
                    Some(data) => data,
                    None => continue,
                };

                // send message, break if channel closed
                if let Err(_) = sender.send(obj).await {
                    info!("WebSocket channel closed, stopping Redis listener");
                    break;
                }
            }
            debug!("Redis listener loop ended");
        });

        debug!("Redis listener task spawned");
        Ok(())
    }
}

/// Spawns a websocket server to listen for incoming registration requests
pub async fn spawn_ws_serv() -> anyhow::Result<()> {
    let listener = Listener::new().await;
    let addr = listener.socket_addr;

    let tcp_listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| {
            error!("Failed to bind to address: {}", e);
            std::process::exit(1);
        });

    info!("WebSocket server listening on {}", addr);

    loop {
        match tcp_listener.accept().await {
            Ok((stream, addr)) => {
                info!("Incoming connection from {:?}...", addr);
                let mut clone = listener.clone();
                tokio::spawn(async move {
                    clone.handle_connection(stream.into_std().unwrap()).await;
                });
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
            }
        }
    }
}
