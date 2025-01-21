#![allow(dead_code)]

use matrix_sdk::{
    config::{RequestConfig, StoreConfig, SyncSettings},
    deserialized_responses::RawSyncOrStrippedState,
    encryption::{identities::Device, BackupDownloadStrategy, EncryptionSettings},
    event_handler::Ctx,
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
use tokio::sync::broadcast;
use tokio::time::{sleep, Duration};
use tracing::info;

use std::path::Path;

use crate::{api::RedisConnection, config::RegistrarConfig, node::register_identity};
use crate::{
    api::{Account, AccountType},
    config::{MatrixConfig, RedisConfig, GLOBAL_CONFIG},
};

const STATE_DIR: &str = "/tmp/matrix_";

/// Verifies a [Device] with the `.verify` method
async fn verify_device(device: &Device) -> anyhow::Result<()> {
    match device.verify().await {
        Ok(_) => Ok(()),
        Err(_) => Err(anyhow::Error::msg("Can't verify your device")),
    }
}

/// Preform the login to the matrix account specified in the [Config], while
/// checking for previous sessions info in from the `<state_dir>/session.json`
/// and if found, it will attempt to use it.
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
                    "Seession {:?}:{:?} is verified!",
                    d.display_name(),
                    d.device_id()
                );
            } else {
                info!("Seession is NOT verified!");
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
            info!("Could not retrive the device from client, {:?}", client);
        }
    }

    Ok(client)
}
struct MatrixBot {
    redis_conn: redis::Connection,
}

/// Spanws a Matrix client to handle incoming messages from beeper
pub async fn start_bot(mut shutdown_rx: broadcast::Receiver<()>) -> anyhow::Result<()> {
    let cfg = GLOBAL_CONFIG
        .get()
        .expect("GLOBAL_CONFIG is not initialized");
    let redis_cfg = cfg.redis.clone();
    let matrix_cfg = cfg.adapter.matrix.clone();
    let registrar_cfg = cfg.registrar.clone();

    let client = login(matrix_cfg).await?;

    client.add_event_handler_context((redis_cfg.to_owned(), registrar_cfg.to_owned()));

    // Store the handler handles
    let member_handle = client.add_event_handler(on_stripped_state_member);
    let message_handle = client.add_event_handler(on_room_message);

    info!(
        "Encryption Status: {:#?}",
        client.encryption().cross_signing_status().await
    );

    info!("Listening for messages...");
    if let Some(device_id) = client.device_id() {
        info!("Logged in with device ID {:#?}", device_id);
    }

    // start sync in a separate task
    let sync_client = client.clone();
    let settings = SyncSettings::default().timeout(Duration::from_secs(30));

    let (sync_stop_tx, mut sync_stop_rx) = tokio::sync::mpsc::channel(1);
    let sync_task = tokio::spawn(async move {
        tokio::select! {
            sync_result = sync_client.sync(settings) => {
                match sync_result {
                    Ok(_) => info!("Matrix sync completed successfully"),
                    Err(e) => tracing::error!("Matrix sync error: {:#?}", e),
                }
            }
            _ = sync_stop_rx.recv() => {
                info!("Sync stop signal received");
            }
        }
    });

    // wait for shutdown signal or sync completion
    tokio::select! {
        _ = shutdown_rx.recv() => {
            info!("Received shutdown signal, stopping Matrix bot");

            // remove event handlers
            client.remove_event_handler(member_handle);
            client.remove_event_handler(message_handle);

            // stop the sync
            let _ = sync_stop_tx.send(()).await;
            drop(client);

            // set a timeout for clean shutdown
            sleep(Duration::from_secs(5)).await;
            info!("Clean shutdown timeout reached");
        }
        _ = sync_task => {
            info!("Matrix sync ended unexpectedly");
        }
    }

    info!("Matrix bot stopped");
    Ok(())
}

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

async fn on_room_message(ev: OriginalSyncRoomMessageEvent, _room: Room) {
    let MessageType::Text(text_content) = ev.content.msgtype else {
        return;
    };
    for state in _room
        .get_state_events(ruma::events::StateEventType::RoomMember)
        .await
        .unwrap()
    {
        // some blackmagic event casting
        let x: RawSyncOrStrippedState<RoomCreateEventContent> = state.cast();
        match x {
            RawSyncOrStrippedState::Sync(s) => {
                // converting the casted value to a jsob object to access it's property
                // TODO: unnest this :)
                let obj: Value = serde_json::from_str(s.json().get()).unwrap();
                let identifiers = obj
                    .get("content")
                    .unwrap()
                    // get's the DM identifier smth like ['Discord:user']
                    .get("com.beeper.bridge.identifiers");
                match identifiers {
                    Some(v) => {
                        match v {
                            Value::Array(arr) => {
                                // extract's the sender src ['Discord:user_x']
                                let sender = arr.first().unwrap().to_string();
                                let sender = sender
                                    .strip_prefix('"')
                                    .and_then(|s| s.strip_suffix('"'))
                                    .unwrap_or("");
                                // creating an account from the extracted sender
                                match Account::from_str(&sender) {
                                    Ok(account) => {
                                        handle_incoming(account, &text_content).await.unwrap();
                                    }
                                    Err(e) => info!(
                                        "Couldn't create Account object from {:?}: {:?}",
                                        sender, e
                                    ),
                                }
                            }
                            _ => {}
                        }
                    }
                    None => {}
                }
            }
            _ => {}
        }
    }
}

async fn handle_incoming(
    acc: Account,
    text_content: &TextMessageEventContent,
) -> anyhow::Result<()> {
    info!("\nAcc: {:#?}\nContent: {:#?}", acc, text_content);
    let cfg = GLOBAL_CONFIG.get().unwrap();
    let redis_cfg = cfg.redis.clone();
    let mut redis_connection = RedisConnection::create_conn(&redis_cfg)?;

    // Parse the account information to extract account type
    let account_type = acc.account_type().to_string();

    // Handle each instance of the account
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

        let account = Account::from_str(&format!("{}:{}",parts[0], parts[1]))?;
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

/// Handles the incoming message as `text_content`, as it checks it against the expected
/// challenge. If matched, it sets done=true for the account. This also checks if all
/// accounts under a given `wallet_id` are registered - if so, it marks the `wallet_id`
/// as done (given in concatenation with the account identifier)
// TODO: Generalize this, since it's being used also in `email.rs` but in a slightly
// different form
async fn handle_content(
    text_content: &TextMessageEventContent,
    redis_connection: &mut RedisConnection,
    network: &str,
    account_id: &AccountId32,
    account: &Account,
) -> anyhow::Result<bool> {
    let cfg = GLOBAL_CONFIG.get().unwrap();
    let account_type = &account.account_type().to_string();

    let network_setting = match cfg.registrar.networks.get(network) {
        Some(setting) => setting,
        None => return Ok(false),
    };

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
    redis_connection
        .update_challenge_status(network, account_id, account_type)
        .await?;

    // register identity if all challenges are completed
    if state.all_done {
        register_identity(
            account_id,
            network_setting.registrar_index,
            &network_setting.endpoint,
        )
        .await?;
    }

    Ok(true)
}
