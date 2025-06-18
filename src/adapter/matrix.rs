#![allow(dead_code)]

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
            message::{
                MessageType, OriginalSyncRoomMessageEvent, RoomMessageEventContent,
                TextMessageEventContent,
            },
        },
    },
    Client,
};
use serde_json::Value;
use w3r_macro::AdapterDerive;
use std::path::Path;
use std::str::FromStr;
use subxt::utils::AccountId32;
use tokio::time::{sleep, Duration};
use tracing::{error, info, instrument, warn};

use crate::api::{Account, RedisConnection};
use crate::GLOBAL_CONFIG;
use crate::{adapter::Adapter, api::Network, node::register_identity};

// TODO: move those "independent" functions inside the Matrix struct (handle_content, etc.)

#[derive(AdapterDerive)]
struct Matrix {
    client: Client,
    settings: SyncSettings,
}


impl Matrix {
    #[instrument(skip_all)]
    async fn login() -> anyhow::Result<Client> {
        let cfg = GLOBAL_CONFIG.get().unwrap().adapter.matrix.clone();
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

    #[instrument(skip_all)]
    async fn new() -> anyhow::Result<Self> {
        let client = Self::login().await?;
        let mut room = RoomEventFilter::default();
        room.lazy_load_options = LazyLoadOptions::Enabled {
            include_redundant_members: true,
        };
        let mut room_ev = RoomFilter::default();
        room_ev.state = room;
        let mut filter = FilterDefinition::default();
        filter.room = room_ev;
        let settings = SyncSettings::new()
            .filter(filter.into())
            .timeout(Duration::from_secs(30));
        Ok(Self { client, settings })
    }

    async fn listen(self) {
        loop {
            if let Err(e) = self.run_sync().await {
                error!("Matrix listener failed: {}. Restarting in 5s...", e);
                sleep(Duration::from_secs(5)).await;
            } else {
                warn!("Matrix sync exited unexpectedly. Restarting...");
            }
        }
    }

    async fn run_sync(&self) -> anyhow::Result<()> {
        self.client.sync_once(self.settings.clone()).await?;
        self.client
            .add_event_handler(Self::on_stripped_state_member);
        self.client.add_event_handler(Self::on_room_message);

        info!(
            "Encryption Status: {:#?}",
            self.client.encryption().cross_signing_status().await
        );
        if let Some(device_id) = self.client.device_id() {
            info!("Logged in with device ID {:#?}", device_id);
        }

        info!("Listening for messages...");
        self.client.sync(self.settings.clone()).await?;

        panic!("FATAL: Matrix sync stopped unexpectedly. Forcing restart.");
    }

    #[instrument(skip_all)]
    async fn on_room_message(ev: OriginalSyncRoomMessageEvent, _room: Room) {
        let MessageType::Text(text_content) = ev.content.msgtype else {
            return;
        };
        info!("Received a text message!");

        let state_events = match _room
            .get_state_events(ruma::events::StateEventType::RoomMember)
            .await
        {
            Ok(events) => events,
            Err(e) => {
                error!("Failed to get state events: {:?}", e);
                return;
            }
        };

        for state in state_events {
            let state_cast: RawSyncOrStrippedState<RoomCreateEventContent> = state.cast();

            info!("Extracting sender account..");
            let Some(account) = extract_sender_account(&state_cast) else {
                continue;
            };
            info!("Account: {:?}", account);

            if let Err(e) = Self::handle_incoming(account.clone(), &text_content).await {
                error!(
                    "Error handling incoming message for account {:?}: {:?}",
                    account, e
                );
                continue;
            }
        }
    }

    #[instrument(skip_all)]
    async fn on_stripped_state_member(event: StrippedRoomMemberEvent, client: Client, room: Room) {
        if event.state_key != client.user_id().unwrap() {
            return;
        }

        tokio::spawn(async move {
            const MAX_RETRY_DELAY: u64 = 16;
            const MAX_RETRIES: u32 = 3;

            // early return if unable to determine DM status
            let is_dm = match room.is_direct().await {
                Ok(is_direct) => is_direct,
                Err(e) => {
                    error!("Failed to check DM status: {}", e);
                    return;
                }
            };

            if !is_dm {
                return;
            }

            // join room with exponential backoff
            let mut retry_count = 0;
            let mut delay = 2;

            while retry_count < MAX_RETRIES {
                match room.join().await {
                    Ok(_) => {
                        info!("Joined DM room {}", room.room_id());

                        if let Err(e) = room
                            .send(RoomMessageEventContent::text_plain(
                                "Please submit your verification challenge.",
                            ))
                            .await
                        {
                            error!("Failed to send challenge prompt: {}", e);
                        }
                        return;
                    }
                    Err(e) => {
                        retry_count += 1;
                        if retry_count == MAX_RETRIES {
                            error!("Failed to join room after {} attempts: {}", MAX_RETRIES, e);
                            return;
                        }
                        sleep(Duration::from_secs(delay)).await;
                        delay = delay.saturating_mul(2).min(MAX_RETRY_DELAY);
                    }
                }
            }
        });
    }

    /// Entry point for handling incoming messages
    /// Looks up associated accounts and delegates to handle_content
    ///
    /// # Arguments
    /// * `acc` - Parsed account information from message
    /// * `text_content` - Content of the message
    #[instrument(skip_all)]
    async fn handle_incoming(
        acc: Account,
        text_content: &TextMessageEventContent,
    ) -> anyhow::Result<()> {
        info!(sender=?acc,body=?text_content.body,"Received matrix message");
        let cfg = GLOBAL_CONFIG.get().unwrap();
        let redis_cfg = cfg.redis.clone();
        let mut redis_connection = RedisConnection::get_connection(&redis_cfg).await?;
        let query = format!("{acc}|*");
        info!(query=?query, "Search query");

        let accounts_key = redis_connection.search(&query).await?;

        if accounts_key.is_empty() {
            return Ok(());
        }

        for acc_str in accounts_key {
            info!("Account: {}", acc_str);
            let parts: Vec<&str> = acc_str.splitn(4, '|').collect();
            if parts.len() != 4 {
                continue;
            }
            let account = Account::from_str(&format!("{}|{}", parts[0], parts[1]))?;
            let network = Network::from_str(parts[2])?;

            if let Ok(account_id) = AccountId32::from_str(parts[3]) {
                if let Ok(()) = <Matrix as Adapter>::handle_content(
                    &text_content.body,
                    &mut redis_connection,
                    &network,
                    &account_id,
                    &account,
                )
                .await
                {
                    break;
                }
            }
        }
        Ok(())
    }
}

/// Verifies a Matrix device for secure communication
/// This is required for end-to-end encryption functionality
#[instrument(skip_all)]
async fn verify_device(device: &Device) -> anyhow::Result<()> {
    match device.verify().await {
        Ok(_) => Ok(()),
        Err(_) => Err(anyhow::Error::msg("Can't verify your device")),
    }
}

/// Initializes and runs the Matrix bot
/// Sets up event handlers for room invites and messages
#[instrument(name = "matrix_listener")]
pub async fn start_bot() -> anyhow::Result<()> {
    Matrix::new().await?.listen().await;
    unreachable!("Matrix listener should never return");
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
    let sender = match obj.get("content")?.get("com.beeper.bridge.identifiers") {
        Some(sender) => {
            let arr = sender.as_array()?;
            &arr.first()?.as_str()?.replace(":", "|")
        }
        None => obj.get("state_key")?.as_str()?,
    };
    info!("Sender: {}", sender);

    Account::from_str(sender).ok()
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
#[instrument(skip_all)]
async fn handle_content(
    text_content: &TextMessageEventContent,
    redis_connection: &mut RedisConnection,
    network: &Network,
    account_id: &AccountId32,
    account: &Account,
) -> anyhow::Result<bool> {
    let account_type = &account.account_type();

    // get the current state
    let state = match redis_connection
        .get_verification_state(network, account_id)
        .await?
    {
        Some(state) => state,
        None => return Ok(false),
    };

    // get the challenge for the account type
    let challenge = match state.challenges.get(&account_type.to_string()) {
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
    if state.completed {
        register_identity(account_id, network).await?;
    }

    Ok(result)
}
