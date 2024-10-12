use crate::node;
use crate::watcher::RegistrarIndex;
use crate::signer::Signer;

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;
use futures_util::{SinkExt, StreamExt};
use serde::{Serialize, Deserialize};
use dashmap::DashMap;
use tokio::sync::broadcast;
use tokio::time::{timeout, Duration};
use thiserror::Error;
use rand::Rng;
use subxt::utils::AccountId32 as AccountId;

const MAX_MESSAGE_SIZE: usize = 1024 * 1024; // 1 MB
const TIMEOUT_DURATION: Duration = Duration::from_secs(300); // 5 minutes
const OLC_ALPHABET: &str = "23456789CFGHJMPQRVWX"; // human-friendly challenges

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VersionedMessage {
    version: String,
    #[serde(flatten)]
    message: WebSocketMessage,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
#[non_exhaustive]
pub enum WebSocketMessage {
    SubscribeAccountState(String),
    NotifyAccountState(NotifyAccountState),
    RequestVerificationChallenge(RequestVerificationChallenge),
    VerifyIdentity(VerifyIdentity),
    JsonResult(JsonResult<ResponseAccountState>),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NotifyAccountState {
    pub account: String,
    pub info: node::IdentityInfo,
    pub judgements: Vec<(RegistrarIndex, node::Judgement)>,
    pub verification_state: VerificationState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResponseAccountState {
    pub account: String,
    pub info: node::IdentityInfo,
    pub judgements: Vec<(RegistrarIndex, node::Judgement)>,
    pub verification_state: VerificationState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerificationState {
    pub verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RequestVerificationChallenge {
    pub account: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerifyIdentity {
    pub account: String,
    pub challenge: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "message")]
pub enum JsonResult<T> {
    Ok(T),
    Err(String),
}

#[derive(Error, Debug)]
pub enum WebSocketError {
    #[error("WebSocket error: {0}")]
    WebSocketError(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("Send error: {0}")]
    SendError(#[from] tokio::sync::broadcast::error::SendError<WebSocketMessage>),
    #[error("Message too large")]
    MessageTooLarge,
    #[error("Connection timed out")]
    ConnectionTimeout,
    #[error("Judgement signing error: {0}")]
    JudgementSigningError(String),
}

pub struct WebSocketServer {
    client: Arc<node::Client>,
    registrar_index: RegistrarIndex,
    signer: Arc<Signer>,
    sessions: Arc<DashMap<String, Vec<broadcast::Sender<WebSocketMessage>>>>,
    challenges: Arc<DashMap<String, String>>, // account -> challenge
    verification_states: Arc<DashMap<String, VerificationState>>,
}

impl WebSocketServer {
    pub fn new(client: Arc<node::Client>, registrar_index: RegistrarIndex, signer: Arc<Signer>) -> Self {
        WebSocketServer {
            client,
            registrar_index,
            signer,
            sessions: Arc::new(DashMap::new()),
            challenges: Arc::new(DashMap::new()),
            verification_states: Arc::new(DashMap::new()),
        }
    }

    pub async fn start(self: Arc<Self>, port: u16) -> anyhow::Result<()> {
        let addr = SocketAddr::from(([0, 0, 0, 0], port));
        let listener = TcpListener::bind(&addr).await?;

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let server = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = server.handle_connection(stream).await {
                            tracing::error!("Error in WebSocket connection: {:?}", e);
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("Error accepting connection: {:?}", e);
                }
            }
        }
    }

    async fn handle_connection(self: Arc<Self>, stream: TcpStream) -> Result<(), WebSocketError> {
        let ws_stream = tokio_tungstenite::accept_async(stream).await?;
        let (mut write, mut read) = ws_stream.split();

        let (tx, mut rx) = broadcast::channel(100);

        loop {
            match timeout(TIMEOUT_DURATION, tokio::select! {
                Some(message) = read.next() => {
                    let message = message?;
                    if let Message::Text(text) = message {
                        if text.len() > MAX_MESSAGE_SIZE {
                            return Err(WebSocketError::MessageTooLarge);
                        }
                        let versioned_msg: VersionedMessage = serde_json::from_str(&text)?;
                        self.handle_message(versioned_msg.message, tx.clone()).await?;
                    }
                    Ok(())
                }
                Ok(response) = rx.recv() => {
                    let response_json = serde_json::to_string(&response)?;
                    write.send(Message::Text(response_json)).await?;
                    Ok(())
                }
            }).await {
                Ok(result) => result?,
                Err(_) => return Err(WebSocketError::ConnectionTimeout),
            }
        }
    }

    async fn handle_message(self: Arc<Self>, message: WebSocketMessage, sender: broadcast::Sender<WebSocketMessage>) -> Result<(), WebSocketError> {
        match message {
            WebSocketMessage::SubscribeAccountState(account) => {
                self.subscribe_account_state(account, sender).await?;
            }
            WebSocketMessage::RequestVerificationChallenge(request) => {
                self.request_verification_challenge(request, sender).await?;
            }
            WebSocketMessage::VerifyIdentity(verify) => {
                self.verify_identity(verify, sender).await?;
            }
            _ => {
                tracing::warn!("Unhandled message type received");
            }
        }
        Ok(())
    }

    async fn subscribe_account_state(&self, account: String, sender: broadcast::Sender<WebSocketMessage>) -> Result<(), WebSocketError> {
        let registration = node::get_registration(&self.client, &account).await.map_err(|e| {
            tracing::error!("Error fetching registration: {:?}", e);
            WebSocketError::SerializationError(serde_json::Error::custom(format!("Failed to fetch registration: {}", e)))
        })?;

        let verification_state = self.get_verification_state(&account).await;

        let response = JsonResult::Ok(ResponseAccountState {
            account: account.clone(),
            info: registration.info,
            judgements: registration.judgements.0,
            verification_state,
        });

        self.sessions
            .entry(account)
            .or_default()
            .push(sender.clone());

        sender.send(WebSocketMessage::JsonResult(response))?;
        Ok(())
    }

    async fn request_verification_challenge(&self, request: RequestVerificationChallenge, sender: broadcast::Sender<WebSocketMessage>) -> Result<(), WebSocketError> {
        let challenge = generate_base20_challenge();
        self.challenges.insert(request.account.clone(), challenge.clone());

        let response = JsonResult::Ok(challenge);
        sender.send(WebSocketMessage::JsonResult(response))?;
        Ok(())
    }

    async fn verify_identity(&self, verify: VerifyIdentity, sender: broadcast::Sender<WebSocketMessage>) -> Result<(), WebSocketError> {
        let stored_challenge = self.challenges.get(&verify.account);

        let result = if let Some(stored_challenge) = stored_challenge {
            if *stored_challenge == verify.challenge {
                self.challenges.remove(&verify.account);
                // TODO: verify the identity info hash
                self.update_verification_state(&verify.account, true);
                JsonResult::Ok(true)
            } else {
                JsonResult::Err("Invalid challenge".to_string())
            }
        } else {
            JsonResult::Err("No challenge found".to_string())
        };

        sender.send(WebSocketMessage::JsonResult(result))?;

        if result == JsonResult::Ok(true) {
            self.notify_account_state(verify.account).await?;
        }

        Ok(())
    }

    pub async fn finalize_verification(&self, account: &str, judgement: &node::Judgement) -> Result<(), WebSocketError> {
        let idinfo_hash = "0x00000000000000000000000000"; // TODO: hash blake2b-256(identityOf.info)
        // Provide the judgement using the Signer
        self.signer.provide_judgement(account.parse()?, judgement.clone(), self.registrar_index, idinfo_hash).await
            .map_err(|e| WebSocketError::JudgementSigningError(e.to_string()))?;

        // Update the verification state
        let verified = matches!(judgement, node::Judgement::Reasonable | node::Judgement::KnownGood);
        self.update_verification_state(account, verified);

        // Notify clients about the finalized verification
        self.notify_account_state(account.to_string()).await?;

        Ok(())
    }

    async fn get_verification_state(&self, account: &str) -> VerificationState {
        self.verification_states
            .entry(account.to_string())
            .or_insert_with(|| VerificationState { verified: false })
            .clone()
    }

    fn update_verification_state(&self, account: &str, verified: bool) {
        self.verification_states
            .insert(account.to_string(), VerificationState { verified });
    }

    pub async fn cancel_challenges(&self, account: &str) -> Result<(), WebSocketError> {
        self.challenges.remove(account);
        self.notify_account_state(account.to_string()).await?;
        Ok(())
    }

    async fn notify_account_state(&self, account: String) -> Result<(), WebSocketError> {
        let registration = node::get_registration(&self.client, &account).await.map_err(|e| {
            tracing::error!("Error fetching registration: {:?}", e);
            WebSocketError::SerializationError(serde_json::Error::custom("Failed to fetch registration"))
        })?;

        let verification_state = self.get_verification_state(&account).await;

        let notification = NotifyAccountState {
            account: account.clone(),
            info: registration.info,
            judgements: registration.judgements.0,
            verification_state,
        };

        if let Some(subscribers) = self.sessions.get(&account) {
            for subscriber in subscribers.value() {
                if let Err(e) = subscriber.send(WebSocketMessage::NotifyAccountState(notification.clone())) {
                    tracing::warn!("Failed to send notification: {:?}", e);
                }
            }
        }
        Ok(())
    }

    pub async fn initiate_challenge(&self, account: &str, _field: &str) -> Result<(), WebSocketError> {
        let challenge = generate_base20_challenge();
        self.challenges.insert(account.to_string(), challenge);
        self.notify_account_state(account.to_string()).await?;
        Ok(())
    }
}

fn generate_base20_challenge() -> String {
    let mut rng = rand::thread_rng();
    (0..8)
        .map(|_| OLC_ALPHABET.chars().nth(rng.gen_range(0..20)).unwrap())
        .collect()
}
