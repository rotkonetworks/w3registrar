#![allow(dead_code)]

use crate::config::MatrixConfig;
use matrix_sdk::{
    config::{RequestConfig, StoreConfig, SyncSettings},
    deserialized_responses::RawSyncOrStrippedState,
    encryption::{identities::Device, BackupDownloadStrategy, EncryptionSettings},
    matrix_auth::MatrixSession,
    room::Room,
    ruma::{
        self,
        api::client::filter::{FilterDefinition, LazyLoadOptions, RoomEventFilter, RoomFilter},
        events::room::{
            create::RoomCreateEventContent,
            member::StrippedRoomMemberEvent,
            message::{MessageType, OriginalSyncRoomMessageEvent, TextMessageEventContent},
        },
    },
    Client,
};
use redis;
use serde_json::Value;
use std::str::FromStr;
use subxt::utils::AccountId32;
use tokio::time::{sleep, Duration};
use tracing::info;

use std::path::Path;

use crate::api::Account;
use crate::GLOBAL_CONFIG;
use crate::{api::RedisConnection, node::register_identity};

/// Verifies a Matrix device for secure communication
/// This is required for end-to-end encryption functionality
async fn verify_device(device: &Device) -> anyhow::Result<()> {
    match device.verify().await {
        Ok(_) => Ok(()),
        Err(_) => Err(anyhow::Error::msg("Can't verify your device")),
    }
}

/// Establishes authenticated connection to Matrix server
/// Handles session persistence and restoration from disk
/// Sets up encryption and verifies device if needed
///
/// # Arguments
/// * `cfg` - Matrix configuration including server details and credentials
async fn login(cfg: MatrixConfig) -> anyhow::Result<Client> {
    let state_dir = Path::new(&cfg.state_dir);
    let session_path = state_dir.join("session.json");

    info!("Creating matrix client");
    let client = Client::builder()
        .homeserver_url(cfg.homeserver)
        .store_config(StoreConfig::default())
        .request_config(
            RequestConfig::new()
                .timeout(Duration::from_secs(60))
                .retry_timeout(Duration::from_secs(60)),
        )
        .sqlite_store(state_dir, None)
        .with_encryption_settings(EncryptionSettings {
            auto_enable_cross_signing: true,
            auto_enable_backups: true,
            backup_download_strategy: BackupDownloadStrategy::AfterDecryptionFailure,
        })
        .build()
        .await?;

    if session_path.exists() {
        info!("Restoring session in {}", session_path.display());
        let session = tokio::fs::read_to_string(session_path).await?;
        let session: MatrixSession = serde_json::from_str(&session)?;
        client.restore_session(session).await?;
        info!("Logged in as {}", cfg.username);
    } else {
        info!("Logging in as {}", cfg.username);
        client
            .matrix_auth()
            .login_username(cfg.username, cfg.password.as_str())
            .initial_device_display_name("w3r")
            .await?;

        info!("Writing session to {}", session_path.display());
        let session = client.matrix_auth().session().expect("Session missing");
        let session = serde_json::to_string(&session)?;
        info!("Session content before save: {}", session);
        tokio::fs::write(session_path, session).await?;
    }

    info!("Importing secrets");
    let secret_store = client
        .encryption()
        .secret_storage()
        .open_secret_store(cfg.security_key.as_str())
        .await?;
    secret_store.import_secrets().await?;

    let device = client
        .encryption()
        .get_device(client.user_id().unwrap(), client.device_id().unwrap())
        .await?;
    match device {
        Some(d) => {
            if d.is_verified() {
                info!(
                    "Session {:?}:{:?} is verified!",
                    d.display_name(),
                    d.device_id()
                );
            } else {
                info!("Session is NOT verified!");
                info!(
                    "Verifying session {:?}:{:?}",
                    d.display_name(),
                    d.device_id()
                );
                verify_device(&d).await?;
                info!("Verification done!");
            }
        }
        None => {
            info!("Could not retrieve the device from client, {:?}", client);
        }
    }

    Ok(client)
}

struct MatrixBot {
    redis_conn: redis::Connection,
}

/// Initializes and runs the Matrix bot
/// Sets up event handlers for room invites and messages
pub async fn start_bot() -> anyhow::Result<()> {
    let cfg = GLOBAL_CONFIG
        .get()
        .expect("GLOBAL_CONFIG is not initialized");

    let redis_cfg = cfg.redis.clone();
    let matrix_cfg = cfg.adapter.matrix.clone();
    let registrar_cfg = cfg.registrar.clone();

    let client = login(matrix_cfg).await?;

    // setup event filters
    let mut room = RoomEventFilter::default();
    room.lazy_load_options = LazyLoadOptions::Enabled {
        include_redundant_members: true,
    };
    let mut room_ev = RoomFilter::default();
    room_ev.state = room;
    let mut filter = FilterDefinition::default();
    filter.room = room_ev;
    let settings = SyncSettings::new().filter(filter.into());

    // initial sync and handler setup
    client.sync_once(settings).await?;
    client.add_event_handler_context((redis_cfg.to_owned(), registrar_cfg.to_owned()));
    client.add_event_handler(on_stripped_state_member);
    client.add_event_handler(on_room_message);

    info!(
        "Encryption Status: {:#?}",
        client.encryption().cross_signing_status().await
    );

    info!("Listening for messages...");
    if let Some(device_id) = client.device_id() {
        info!("Logged in with device ID {:#?}", device_id);
    }

    let settings = SyncSettings::default().timeout(Duration::from_secs(30));
    client.sync(settings).await?;

    Ok(())
}

/// Handles room member state changes (e.g. invites)
/// Automatically joins rooms when invited
/// Uses exponential backoff for retrying failed joins
async fn on_stripped_state_member(event: StrippedRoomMemberEvent, client: Client, room: Room) {
    if event.state_key != client.user_id().unwrap() {
        return;
    }

    tokio::spawn(async move {
        info!("Joining room {}", room.room_id());
        let mut delay = 2;

        while let Err(err) = room.join().await {
            // retry auto join due to synapse sending invites, before the
            // invited user can join for more information see
            // https://github.com/matrix-org/synapse/issues/4345
            info!(
                "Failed to join room {} ({err:?}), retrying in {delay}s",
                room.room_id()
            );

            sleep(Duration::from_secs(delay)).await;
            delay *= 2;

            if delay > 3600 {
                info!("Can't join room {} ({err:?})", room.room_id());
                break;
            }
        }
        info!("Successfully joined room {}", room.room_id());
    });
}

/// Extract sender account from state event
fn extract_sender_account(
    state: &RawSyncOrStrippedState<RoomCreateEventContent>,
) -> Option<Account> {
    let RawSyncOrStrippedState::Sync(s) = state else {
        return None;
    };

    // Parse JSON content
    let obj = serde_json::from_str::<Value>(s.json().get()).ok()?;

    // Extract bridge identifiers
    let arr = obj
        .get("content")?
        .get("com.beeper.bridge.identifiers")?
        .as_array()?;

    // Get first identifier and process it
    let sender = arr.first()?.as_str()?;

    Account::from_str(sender).ok()
}

/// Processes incoming room messages
async fn on_room_message(ev: OriginalSyncRoomMessageEvent, _room: Room) {
    let MessageType::Text(text_content) = ev.content.msgtype else {
        return;
    };

    let state_events = match _room
        .get_state_events(ruma::events::StateEventType::RoomMember)
        .await
    {
        Ok(events) => events,
        Err(e) => {
            info!("Failed to get state events: {:?}", e);
            return;
        }
    };

    for state in state_events {
        let state_cast: RawSyncOrStrippedState<RoomCreateEventContent> = state.cast();

        let Some(account) = extract_sender_account(&state_cast) else {
            continue;
        };

        if let Err(e) = handle_incoming(account.clone(), &text_content).await {
            info!(
                "Error handling incoming message for account {:?}: {:?}",
                account, e
            );
            continue;
        }
    }
}

/// Entry point for handling incoming messages
/// Looks up associated accounts and delegates to handle_content
///
/// # Arguments
/// * `acc` - Parsed account information from message
/// * `text_content` - Content of the message
async fn handle_incoming(
    acc: Account,
    text_content: &TextMessageEventContent,
) -> anyhow::Result<()> {
    info!("\nAcc: {:#?}\nContent: {:#?}", acc, text_content);
    let cfg = GLOBAL_CONFIG.get().unwrap();
    let redis_cfg = cfg.redis.clone();
    let mut redis_connection = RedisConnection::create_conn(&redis_cfg)?;

    // handle each instance of the account
    let accounts_key = redis_connection.search(&format!("{}:*", acc))?;

    if accounts_key.is_empty() {
        return Ok(());
    }

    for acc_str in accounts_key {
        info!("Account: {}", acc_str);

        // extract account ID from the account string
        // <acc:name>:<acc_type>:<wallet_id>
        let parts: Vec<&str> = acc_str.splitn(4, ':').collect();
        if parts.len() != 4 {
            continue;
        }

        let account = Account::from_str(&format!("{}:{}", parts[0], parts[1]))?;
        let network = parts[2];

        // this unwrap is fine, we checked above
        if let Ok(account_id) = AccountId32::from_str(parts[3]) {
            if handle_content(
                text_content,
                &mut redis_connection,
                network,
                &account_id,
                &account,
            )
            .await?
            {
                break;
            }
        }
    }
    Ok(())
}

/// Processes message content for verification
/// Validates message against expected challenge token
/// Updates verification state and triggers registration if all challenges complete
///
/// # Arguments
/// * `text_content` - Content to validate
/// * `redis_connection` - Redis connection for state management
/// * `network` - Network identifier
/// * `account_id` - Account being verified
/// * `account` - Account information
async fn handle_content(
    text_content: &TextMessageEventContent,
    redis_connection: &mut RedisConnection,
    network: &str,
    account_id: &AccountId32,
    account: &Account,
) -> anyhow::Result<bool> {
    let cfg = GLOBAL_CONFIG.get().unwrap();
    let account_type = &account.account_type().to_string();

    // get the current state
    let state = match redis_connection
        .get_verification_state(network, account_id)
        .await?
    {
        Some(state) => state,
        None => return Ok(false),
    };

    // get the challenge for the account type
    let challenge = match state.challenges.get(account_type) {
        Some(challenge) => challenge,
        None => return Ok(false),
    };

    info!("Checking if all challenges are already done...");
    // challenge is already completed
    if challenge.done {
        return Ok(false);
    }

    // verify the token
    let token = match &challenge.token {
        Some(token) => token,
        None => return Ok(false),
    };

    // check if the message matches the token (fixed comparison)
    if text_content.body != *token {
        return Ok(false);
    }

    // update challenge status
    let result = redis_connection
        .update_challenge_status(network, account_id, account_type)
        .await?;

    let state = match redis_connection
        .get_verification_state(network, account_id)
        .await?
    {
        Some(state) => state,
        None => return Ok(false),
    };

    // register identity if all challenges are completed
    if state.all_done {
        register_identity(account_id, network).await?;
    }

    Ok(result)
}
