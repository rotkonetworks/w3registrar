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
use redis::{self};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use subxt::utils::AccountId32;
use tokio::time::{sleep, Duration};
use tracing::info;

use std::path::Path;

use crate::{api::RedisConnection, config::RegistrarConfig, node::register_identity};
use crate::{
    api::{Account, VerifStatus},
    config::{MatrixConfig, RedisConfig, GLOBAL_CONFIG},
    token::AuthToken,
};

const STATE_DIR: &str = "/tmp/matrix_";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum RegistrationStatus {
    Pending(String),
    Done(String),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RegistrationResponse {
    status: RegistrationStatus,
}

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
                                match Account::from_string(sender.clone()) {
                                    // TODO: this looks sooo ugly
                                    Some(acc) => handle_incoming(
                                        acc,
                                        &text_content,
                                        &_room,
                                        &ctx.0 .0,
                                        ctx.0 .1.registrar_index,
                                        &ctx.0 .1.endpoint,
                                    )
                                    .await
                                    .unwrap(),
                                    None => info!("Couldn't create Acc object from {:?}", sender),
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

// TODO: this signature looks ugly
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
    // since an account could be registred by more than wallet, we need to poll each
    // instance of that account
    let accounts = redis_connection.search(format!("{}:*", serde_json::to_string(&acc)?))?;
    // TODO: handle the account VerifStatus in the HahsMap of accounts under the wallet_id
    if accounts.is_empty() {
        return Ok(());
    }

    for acc in accounts {
        info!("Account: {}", acc);
        if handle_content(
            text_content,
            &mut redis_connection,
            &acc,
            reg_index,
            endpoint,
        )
        .await?
        {
            break;
        }
    }
    Ok(())
}

/// Handles the incoming message as `text_content`, as it checks it agains the expected
/// challenge, and if matched it changes the status of `account` to [VerifStatus::Done], this
/// also checks if all acconts under a given `wallet_id` are registred, if so, it changes
/// the `status` of the `wallet_id` (given in concatination with the account identifier)
/// to [VerifStatus::Done]
async fn handle_content(
    text_content: &TextMessageEventContent,
    redis_connection: &mut RedisConnection,
    account: &str,
    reg_index: u32,
    endpoint: &str,
) -> anyhow::Result<bool> {
    // NOTE: this will change after this is merged (if-let chaining)
    // https://github.com/rust-lang/rust/pull/132833
    if let Ok(Some(false)) = redis_connection.is_verified(&account) {
        let challenge = redis_connection
            .get_challenge_token_from_account_info(&account)?
            .unwrap();
        if text_content.body.eq(&challenge.show()) {
            redis_connection.set_status(&account, VerifStatus::Done)?;
            let id = redis_connection.get_wallet_id(&account);
            signal_done_if_needed(redis_connection, id, reg_index, endpoint).await?;
            return Ok(true);
        }
    }
    Ok(false)
}

async fn signal_done_if_needed(
    redis_connection: &mut RedisConnection,
    id: AccountId32,
    reg_index: u32,
    endpoint: &str,
) -> anyhow::Result<()> {
    if redis_connection.is_all_verified(&id)? {
        register_identity(&id, reg_index, endpoint).await?;
        redis_connection.signal_done(&id)?;
        info!("All requested accounts from {:?} are now verified", id);
    }
    Ok(())
}
