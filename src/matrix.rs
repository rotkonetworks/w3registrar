use matrix_sdk::ruma::events::room::message::MessageType;
use matrix_sdk::ruma::events::room::message::OriginalSyncRoomMessageEvent;
use matrix_sdk::ruma::events::room::member::StrippedRoomMemberEvent;
use matrix_sdk::Client;
use matrix_sdk::config::SyncSettings;
use matrix_sdk::room::Room;
use matrix_sdk::ruma::events::AnySyncMessageLikeEvent;
use matrix_sdk::encryption::{BackupDownloadStrategy, EncryptionSettings};
use matrix_sdk::matrix_auth::MatrixSession;
use tokio::time::sleep;
use tokio::time::Duration;

use std::path::Path;

const STATE_DIR: &str = "/tmp/matrix";

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct BotConfig {
    pub homeserver: String,
    pub username: String,
    pub password: String,
    pub security_key: String,
    pub admins: Vec<Nickname>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Nickname(String);

pub async fn start_bot(cfg: BotConfig) -> anyhow::Result<()> {
    let state_dir = Path::new(STATE_DIR);
    let session_path = state_dir.join("session.json");

    info!("Creating client");
    let client = Client::builder()
        .homeserver_url(cfg.homeserver)
        .sqlite_store(STATE_DIR, None)
        .with_encryption_settings(EncryptionSettings {
            auto_enable_cross_signing: true,
            auto_enable_backups: true,
            backup_download_strategy: BackupDownloadStrategy::AfterDecryptionFailure,
        })
        .build().await.unwrap();

    if session_path.exists() {
        info!("Restoring session in {}", session_path.display());
        let session = tokio::fs::read_to_string(session_path).await?;
        let session: MatrixSession = serde_json::from_str(&session)?;
        client.restore_session(session).await?;
    } else {
        info!("Logging in as {}", cfg.username);
        client
            .matrix_auth()
            .login_username(cfg.username, cfg.password.as_str())
            .initial_device_display_name("w3-reg-bot")
            .await?;

        info!("Writing session to {}", session_path.display());
        let session = client.matrix_auth().session().expect("Session missing");
        let session = serde_json::to_string(&session)?;
        tokio::fs::write(session_path, session).await?;
    }

    if let Some(device_id) = client.device_id() {
        info!("Logged in with device ID {}", device_id);
    }

    // Perform an initial sync to set up state.
    info!("Performing initial sync");
    let response = client.sync_once(SyncSettings::default()).await.unwrap();
    // Add event handlers to be notified of incoming messages.
    // We do this after the initial sync to avoid responding to messages before
    // the bot was running.
    client.add_event_handler(on_any_message_like_event);
    client.add_event_handler(on_stripped_state_member);
    client.add_event_handler(on_room_message);

    // Import secrets. This should enable cross-signing and verify the session.
    info!("Importing secrets");
    let secret_store = client
        .encryption()
        .secret_storage()
        .open_secret_store(cfg.security_key.as_str()).await?;
    secret_store.import_secrets().await?;

    info!("{:#?}", client.encryption().cross_signing_status().await.unwrap());

    // Since we called `sync_once` before we entered our sync loop we must pass
    // that sync token to `sync`.
    info!("Listening for messages...");
    let settings = SyncSettings::default().token(response.next_batch);
    client.sync(settings).await?;

    Ok(())
}

async fn on_any_message_like_event(e: AnySyncMessageLikeEvent) {
    info!("Received {:#?}", e);
}

async fn on_stripped_state_member(
    event: StrippedRoomMemberEvent,
    client: Client,
    room: Room,
) {
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
            info!("Failed to join room {} ({err:?}), retrying in {delay}s", room.room_id());

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

async fn on_room_message(e: OriginalSyncRoomMessageEvent, _room: Room) {
    if let MessageType::Text(text) = e.content.msgtype {
        info!("Received message from {}:\n\t\n\t{}\n", e.sender, text.body);
    };
}