#![allow(dead_code)]

use matrix_sdk::{
    config::{RequestConfig, StoreConfig, SyncSettings},
    deserialized_responses::RawSyncOrStrippedState,
    encryption::{identities::Device, BackupDownloadStrategy, EncryptionSettings},
    matrix_auth::MatrixSession,
    room::Room,
    ruma::{
        self,
        events::room::{
            create::RoomCreateEventContent,
            member::StrippedRoomMemberEvent,
            message::{
                MessageType, OriginalSyncRoomMessageEvent, RoomMessageEventContent,
                TextMessageEventContent,
            },
        },
    },
    Client,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::time::{sleep, Duration};
use tracing::{info, error};
use anyhow::{Result, Context};

use std::path::Path;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use subxt::utils::AccountId32;

use crate::{
    api::{Account, AccountMetadata, VerifStatus, RedisConnection},
    token::{AuthToken, Token},
    config::{RedisConfig, MatrixConfig},
};

// Configuration constants
const REQUEST_TIMEOUT: u64 = 60;
const SYNC_TIMEOUT: u64 = 30;
const MAX_RETRY_DELAY: u64 = 3600;
const INITIAL_RETRY_DELAY: u64 = 2;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum RegistrationStatus {
    Pending(String),
    Done(String),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RegistrationResponse {
    status: RegistrationStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Nickname(String);

/// Client builder configuration with standard settings
fn create_client_config(homeserver: &str, state_dir: &Path) -> matrix_sdk::ClientBuilder {
    Client::builder()
        .homeserver_url(homeserver)
        .store_config(StoreConfig::new())
        .request_config(
            RequestConfig::new()
                .timeout(Duration::from_secs(REQUEST_TIMEOUT))
                .retry_timeout(Duration::from_secs(REQUEST_TIMEOUT)),
        )
        .sqlite_store(state_dir, None)
        .with_encryption_settings(EncryptionSettings {
            auto_enable_cross_signing: true,
            auto_enable_backups: true,
            backup_download_strategy: BackupDownloadStrategy::AfterDecryptionFailure,
        })
}

/// Attempts to verify a device using its verification method
async fn verify_device(device: &Device) -> Result<()> {
    device.verify()
        .await
        .map_err(|_| anyhow::anyhow!("Failed to verify device"))
}

/// Handles session restoration or creation
async fn handle_session(
    client: &Client,
    username: &str,
    password: &str,
    session_path: &Path,
) -> Result<()> {
    if session_path.exists() {
        restore_existing_session(client, session_path, username).await
    } else {
        create_new_session(client, username, password, session_path).await
    }
}

async fn restore_existing_session(
    client: &Client,
    session_path: &Path,
    username: &str,
) -> Result<()> {
    info!("Restoring session from {}", session_path.display());
    let session = tokio::fs::read_to_string(session_path)
        .await
        .context("Failed to read session file")?;
    let session: MatrixSession = serde_json::from_str(&session)
        .context("Failed to parse session JSON")?;
    client.restore_session(session).await?;
    info!("Logged in as {}", username);
    Ok(())
}

async fn create_new_session(
    client: &Client,
    username: &str,
    password: &str,
    session_path: &Path,
) -> Result<()> {
    info!("Creating new session for {}", username);
    client
        .matrix_auth()
        .login_username(username, password)
        .initial_device_display_name("w3r")
        .await?;

    let session = client
        .matrix_auth()
        .session()
        .context("Session missing after login")?;
    
    info!("Writing session to {}", session_path.display());
    let session_json = serde_json::to_string(&session)?;
    tokio::fs::write(session_path, session_json).await?;
    info!("Logged in as {}", username);
    Ok(())
}

/// Handles device verification status and process
async fn handle_device_verification(client: &Client) -> Result<()> {
    let user_id = client.user_id()
        .context("Missing user ID")?;
    let device_id = client.device_id()
        .context("Missing device ID")?;

    let device = client
        .encryption()
        .get_device(user_id, device_id)
        .await?
        .context("Could not retrieve device from client")?;

    if device.is_verified() {
        info!(
            "Session {:?}:{:?} is verified!",
            device.display_name(),
            device.device_id()
        );
    } else {
        info!("Session is not verified");
        info!(
            "Verifying session {:?}:{:?}",
            device.display_name(),
            device.device_id()
        );
        verify_device(&device).await?;
        info!("Verification completed");
    }
    Ok(())
}

/// Sets up and imports secrets for the client
async fn setup_secret_store(client: &Client, security_key: &str) -> Result<()> {
    info!("Importing secrets");
    let secret_store = client
        .encryption()
        .secret_storage()
        .open_secret_store(security_key)
        .await?;
    secret_store.import_secrets().await?;
    Ok(())
}

/// Performs login to the matrix account specified in the config.
/// Checks for previous session information in `<state_dir>/session.json`
/// and uses it if found.
async fn login(cfg: MatrixConfig) -> Result<Client> {
    let state_dir = Path::new(&cfg.state_dir);
    let session_path = state_dir.join("session.json");

    info!("Creating client");
    let client = create_client_config(&cfg.homeserver, state_dir)
        .build()
        .await
        .context("Failed to build client")?;

    handle_session(&client, &cfg.username, &cfg.password, &session_path).await?;
    setup_secret_store(&client, &cfg.security_key).await?;
    handle_device_verification(&client).await?;

    Ok(client)
}

pub struct MatrixBot {
    redis: Arc<Mutex<RedisConnection>>,
    accounts: Arc<Mutex<HashMap<Account, AccountMetadata>>>,
    origin: Arc<Mutex<HashMap<AccountId32, HashMap<Account, VerifStatus>>>>,
    response_sender: mpsc::Sender<RegistrationResponse>,
}

impl MatrixBot {
    pub async fn new(redis_config: &RedisConfig) -> Result<(Self, mpsc::Receiver<RegistrationResponse>)> {
        let (tx, rx) = mpsc::channel(100);
        Ok((Self {
            redis: Arc::new(Mutex::new(RedisConnection::create_conn(&redis_config.url)?)),
            accounts: Arc::new(Mutex::new(HashMap::new())),
            origin: Arc::new(Mutex::new(HashMap::new())), // init empty origin map
            response_sender: tx,
        }, rx))
    }
}

/// Starts the matrix bot to monitor bridged messages.
/// - Sender: Sends registration request to the matrix bot
/// - Receiver: Receives registration status from the matrix bot
pub async fn start_bot(cfg: MatrixConfig, redis_config: RedisConfig) 
    -> Result<mpsc::Receiver<RegistrationResponse>> 
{
    let client = login(cfg).await?;
    let (bot, rx) = MatrixBot::new(&redis_config).await?;
    let bot = Arc::new(bot);

    client.add_event_handler(on_stripped_state_member);
    client.add_event_handler({
        let bot = bot.clone();
        move |ev, room| {
            let bot = bot.clone();
            async move {
                on_room_message(ev, room, bot.as_ref()).await;
            }
        }
    });

    info!(
        "Encryption Status: {:#?}",
        client.encryption().cross_signing_status().await
    );

    if let Some(device_id) = client.device_id() {
        info!("Logged in with device ID {device_id:?}");
    }

    start_sync_loop(client).await?; // Add the ? here
    Ok(rx)
}

async fn start_sync_loop(client: Client) -> Result<()> {
    tokio::spawn(async move {
        let settings = SyncSettings::default()
            .timeout(Duration::from_secs(SYNC_TIMEOUT));
            
        match client.sync(settings).await {
            Ok(_) => info!("Sync completed successfully"),
            Err(e) => error!("Sync failed: {e:?}"),
        }
    });
    
    Ok(())
}

/// Handles automatic room joining for invites
async fn on_stripped_state_member(event: StrippedRoomMemberEvent, client: Client, room: Room) {
    if event.state_key != client.user_id().unwrap() {
        return;
    }

    tokio::spawn(async move {
        join_room_with_retry(&room).await;
    });
}

async fn join_room_with_retry(room: &Room) {
    info!("Joining room {}", room.room_id());
    let mut delay = INITIAL_RETRY_DELAY;

    while let Err(err) = room.join().await {
        // Retry auto-join due to synapse sending invites before the
        // invited user can join. For more information see:
        // https://github.com/matrix-org/synapse/issues/4345
        if delay > MAX_RETRY_DELAY {
            error!("Failed to join room {} after maximum retries: {err:?}", room.room_id());
            return;
        }

        info!(
            "Failed to join room {} ({err:?}), retrying in {delay}s",
            room.room_id()
        );

        sleep(Duration::from_secs(delay)).await;
        delay *= 2;
    }

    info!("Successfully joined room {}", room.room_id());
}

/// Extracts the account from room state event's bridge identifiers
fn extract_account_from_state(state: RawSyncOrStrippedState<RoomCreateEventContent>) -> Option<Account> {
    // converting the casted value to a json object to access it's property
    let RawSyncOrStrippedState::Sync(s) = state else {
        return None;
    };

    let obj: Value = serde_json::from_str(s.json().get()).ok()?;
    
    // get's the DM identifier smth like ['Discord:user']
    let identifiers = obj
        .get("content")?
        .get("com.beeper.bridge.identifiers")?;

    // extract's the sender ['Discord:user_x']
    let sender = identifiers
        .as_array()?
        .first()?
        .to_string();

    // creating an account from the extracted sender
    Account::from_string(sender)
}

#[derive(Debug)]
enum MessageAction {
    SendChallenge,
    VerifyChallenge(String),
}

impl MessageAction {
    fn from_content(content: &str) -> Self {
        match content {
            "Send challenge" => MessageAction::SendChallenge,
            response => MessageAction::VerifyChallenge(response.to_string()),
        }
    }
}

async fn on_room_message(
    ev: OriginalSyncRoomMessageEvent, 
    room: Room, 
    bot: &MatrixBot
) {
    let MessageType::Text(text_content) = ev.content.msgtype else {
        return;
    };

    let states = match room.get_state_events(ruma::events::StateEventType::RoomMember).await {
        Ok(states) => states,
        Err(e) => {
            error!("Failed to get room states: {}", e);
            return;
        }
    };

    for state in states {
        // some blackmagic event casting
        let state_content: RawSyncOrStrippedState<RoomCreateEventContent> = state.cast();
        
        if let Some(account) = extract_account_from_state(state_content) {
            if let Err(e) = handle_verification(account, &text_content.body, bot).await {
                error!("Failed to handle verification: {}", e);
            }
        }
    }
}

async fn handle_verification(
    account: Account,
    message: &str, 
    bot: &MatrixBot,
) -> Result<()> {
    let mut redis = bot.redis.lock().await;
    let account_key = serde_json::to_string(&account)?;
    
    // Get account metadata
    let wallet_id = redis.get_wallet_id(&account_key);
    let stored_token = redis.get_challenge_token(&account_key);
    let current_status = redis.get_status(&account_key);

    // Verify token
    if message != stored_token.show() {
        info!("Received invalid token from {account:?}. Expected {}, got {message}", 
            stored_token.show());
        return Ok(());
    }

    match current_status {
        VerifStatus::Done => {
            info!("Account {account:?} already verified");
            return Ok(());
        }
        VerifStatus::Pending => {
            redis.set_status(&account_key, VerifStatus::Done)?;
            redis.remove_account(&wallet_id, &account)?;

            if redis.is_all_verified(&wallet_id)? {
                redis.signal_done(&wallet_id)?;
                bot.response_sender
                    .send(RegistrationResponse {
                        status: RegistrationStatus::Done(String::from("done")),
                    })
                    .await?;
            }
        }
    }

    Ok(())
}

async fn handle_incoming(
    acc: Account,
    text_content: &TextMessageEventContent,
    room: &Room,
    bot: &MatrixBot,
) -> anyhow::Result<()> {
    info!("\nAcc: {:#?}\nContent: {:#?}", acc, text_content);

    let mut accounts = bot.accounts.lock().await;
    if let Some(metadata) = accounts.get_mut(&acc) {
        if text_content.body == metadata.token.show() {
            let mut redis = bot.redis.lock().await;
            redis.set_status(&serde_json::to_string(&acc)?, VerifStatus::Done)?;
            redis.remove_account(&metadata.id, &acc)?;

            if redis.is_all_verified(&metadata.id)? {
                info!("\nAll accounts for wallet {} are verified!", metadata.id);
                bot.response_sender.send(RegistrationResponse {
                    status: RegistrationStatus::Done(String::from("done")),
                }).await?;
                redis.signal_done(&metadata.id)?;
            }
        } else {
            info!(
                "Received incorrect token from {:?}. Expected {:?}, got {:?}",
                acc, metadata.token.show(), text_content.body
            );
        }
    }

    Ok(())
}

async fn send_challenges(
    accounts: &[String], 
    redis: &mut RedisConnection,
    room: &Room,
) -> anyhow::Result<()> {
    for account in accounts {
        let wallet_id = redis.get_wallet_id(account);
        let token = redis.get_challenge_token(account);
        
        let message = format!(
            "wallet id: {}\nchallange: {}", 
            wallet_id.to_string(),
            token.show()
        );
        
        room.send(RoomMessageEventContent::text_plain(message)).await?;
    }
    Ok(())
}

async fn process_verification(
    accounts: &[String],
    redis: &mut RedisConnection,
    account: &Account,
    challenge_response: &str,
) -> anyhow::Result<()> {
    for acc_key in accounts {
        if let VerifStatus::Pending = redis.get_status(acc_key) {
            let challenge = redis.get_challenge_token(acc_key);
            
            if challenge_response == challenge.show() {
                verify_account(redis, acc_key, account)?;
                break;
            }
        }
    }
    Ok(())
}

fn verify_account(
    redis: &mut RedisConnection,
    account_key: &str,
    account: &Account,
) -> anyhow::Result<()> {
    redis.set_status(account_key, VerifStatus::Done)?;
    let wallet_id = redis.get_wallet_id(account_key);
    redis.remove_account(&wallet_id, account)?;
    
    if redis.is_all_verified(&wallet_id)? {
        redis.signal_done(&wallet_id)?;
    }
    
    Ok(())
}
