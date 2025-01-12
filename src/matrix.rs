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

use crate::{
    api::Account,
    config::{MatrixConfig, RedisConfig, GLOBAL_CONFIG},
};
use crate::{api::RedisConnection, config::RegistrarConfig, node::register_identity};

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
        .store_config(StoreConfig::new())
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
pub async fn start_bot() -> anyhow::Result<()> {
    let cfg = GLOBAL_CONFIG
        .get()
        .expect("GLOBAL_CONFIG is not initialized");
    let redis_cfg = cfg.redis.clone();
    let matrix_cfg = cfg.matrix.clone();
    let registrar_cfg = cfg.registrar.clone();

    // cfg.matrix, &cfg.redis, &cfg.registrar

    let client = login(matrix_cfg).await?;

    client.add_event_handler_context((redis_cfg.to_owned(), registrar_cfg.to_owned()));
    client.add_event_handler(on_stripped_state_member);
    client.add_event_handler(on_room_message);
    // create and add context here
    // Note that the context can be used only in this function, unless returned
    // which cannot happen since the add_event_handler_context takes ownership
    // of it
    info!(
        "Encryption Status: {:#?}",
        client.encryption().cross_signing_status().await
    );

    info!("Listening for messages...");
    if let Some(device_id) = client.device_id() {
        info!("Logged in with device ID {:#?}", device_id);
    }

    tokio::spawn(async move {
        let settings = SyncSettings::default().timeout(Duration::from_secs(30));
        match client.sync(settings).await {
            Ok(_) => info!("sync is done Successfully!"),
            Err(e) => tracing::error!("can't sync duo to {:#?}", e),
        };
    });
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

async fn on_room_message(
    ev: OriginalSyncRoomMessageEvent,
    _room: Room,
    ctx: Ctx<(RedisConfig, RegistrarConfig)>,
) {
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
                                // creating an account from the extracted sender
                                match Account::from_str(&sender) {
                                    Ok(acc) => handle_incoming(
                                        acc,
                                        &text_content,
                                        &_room,
                                        &ctx.0 .0,
                                        ctx.0 .1.registrar_index,
                                        &ctx.0 .1.endpoint,
                                    )
                                    .await
                                    .unwrap(),
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
    _room: &Room,
    redis_cfg: &RedisConfig,
    reg_index: u32,
    endpoint: &str,
) -> anyhow::Result<()> {
    info!("\nAcc: {:#?}\nContent: {:#?}", acc, text_content);
    let mut redis_connection = RedisConnection::create_conn(redis_cfg)?;

    // Parse the account information to extract account type
    let account_type = acc.account_type().to_string();
    let network = "rococo"; // or get from configuration

    // Handle each instance of the account
    let accounts = redis_connection.search(format!("{}:*", serde_json::to_string(&acc)?))?;
    
    if accounts.is_empty() {
        return Ok(());
    }

    for acc_str in accounts {
        info!("Account: {}", acc_str);
        
        // extract account ID from the account string
        let parts: Vec<&str> = acc_str.split(':').collect();
        if parts.len() < 2 {
            continue;
        }
        
        if let Ok(account_id) = AccountId32::from_str(parts[parts.len()-1]) {
            if handle_content(
                text_content,
                &mut redis_connection,
                network,
                &account_id,
                &account_type,
                reg_index,
                endpoint,
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
async fn handle_content(
    text_content: &TextMessageEventContent,
    redis_connection: &mut RedisConnection,
    network: &str,
    account_id: &AccountId32,
    account_type: &str,
    reg_index: u32,
    endpoint: &str,
) -> anyhow::Result<bool> {
    // get the current state
    let state = match redis_connection.get_verification_state(network, account_id).await? {
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
        register_identity(account_id, reg_index, endpoint).await?;
    }

    Ok(true)
}
