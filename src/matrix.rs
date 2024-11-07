#![allow(dead_code)]

use flume::{Receiver, Sender};
use matrix_sdk::{
    config::SyncSettings,
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
            message::{MessageType, OriginalSyncRoomMessageEvent},
        },
    },
    Client,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{sync::Mutex, time::{sleep, Duration}};
use tracing::info;

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use crate::api::{Account, AcctMetadata, RegistrationRequest, VerifStatus};

const STATE_DIR: &str = "/tmp/matrix";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum RegistrationStatus {
    Pending(String),
    Done(String),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RegistrationResponse {
    status: RegistrationStatus,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Config {
    pub homeserver: String,
    pub username: String,
    pub password: String,
    pub security_key: String,
    pub admins: Vec<Nickname>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Nickname(String);

/// Verifies a [Device] with the `.verify` method
async fn verify_device(device: &Device) -> anyhow::Result<()> {
    match device.verify().await {
        Ok(_) => return Ok(()),
        Err(_) => Err(anyhow::Error::msg("Can't verify your device")),
    }
}

/// Preform the login to the matrix account specified in the [Config], while
/// checking for previous sessions info in from the `<state_dir>/session.json`
/// and if found, it will attempt to use it.
async fn login(cfg: Config, state_dir: &str) -> anyhow::Result<Client> {
    let state_dir = Path::new(state_dir);
    let session_path = state_dir.join("session.json");

    info!("Creating client");
    let client = Client::builder()
        .homeserver_url(cfg.homeserver.to_owned())
        .sqlite_store(state_dir, None)
        .with_encryption_settings(EncryptionSettings {
            auto_enable_cross_signing: true,
            auto_enable_backups: true,
            backup_download_strategy: BackupDownloadStrategy::AfterDecryptionFailure,
        })
        .build()
        .await
        .unwrap();

    if session_path.exists() {
        info!("Restoring session in {}", session_path.display());
        let session = tokio::fs::read_to_string(session_path).await?;
        let session: MatrixSession = serde_json::from_str(&session)?;
        client.restore_session(session).await?;
    } else {
        info!("Logging in as {}", cfg.username);
        client
            .matrix_auth()
            .login_username(cfg.username.to_owned(), cfg.password.as_str())
            .initial_device_display_name("w3r")
            .await?;

        info!("Writing session to {}", session_path.display());
        let session = client.matrix_auth().session().expect("Session missing");
        let session = serde_json::to_string(&session)?;
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
        .await
        .unwrap();
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

    return Ok(client);
}

/// Starts the matrix bot, this function should be used to
/// login to the specified matrix account in the config, and start monitor
/// bridged messages
pub async fn start_bot(
    cfg: Config,
) -> anyhow::Result<(Receiver<RegistrationResponse>, Sender<RegistrationRequest>)> {
    let client = login(cfg, STATE_DIR).await?;
    if let Some(device_id) = client.device_id() {
        info!("Logged in with device ID {:#?}", device_id);
    }
    // Perform an initial sync to set up state.
    info!("Performing initial sync");

    let (send_response_to_serv, rescive_response_from_matrix) =
        flume::unbounded::<RegistrationResponse>();
    let (send_registration_to_matrix, recive_registration_from_serv) =
        flume::unbounded::<RegistrationRequest>();

    let requestd_accounts: Arc<Mutex<HashMap<Account, AcctMetadata>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let _requested_accounts = requestd_accounts.clone();
    let origin: Arc<Mutex<Origin>> = Arc::new(Mutex::new(Origin::default()));
    let mut _origin = origin.clone();

    // listens for incomming registration requests sent from the HTTP server
    let _ = tokio::spawn(async move {
        for reg in recive_registration_from_serv.iter() {
            info!("Registration recived for {:#?}", reg);
            for acc in reg.accounts.iter() {
                requestd_accounts.lock().await.insert(
                    acc.to_owned(),
                    AcctMetadata {
                        status: crate::api::VerifStatus::Pending,
                        id: reg.id.clone(),
                    },
                );
            }
                _origin.lock().await.origin.extend(Origin::derive(reg).origin)
        }
    });

    let response = client.sync_once(SyncSettings::default()).await.unwrap();

    client.add_event_handler_context(ReqHandler {
        sender: send_response_to_serv,
        tracker: _requested_accounts,
        origin,
    });

    client.add_event_handler(on_stripped_state_member);
    client.add_event_handler(on_room_message);
    // create and add context here
    // Note that the context can be used only in this function, unless returned
    // which cannot happen since the add_event_handler_context takes ownership
    // of it
    info!(
        "Encryption Status: {:#?}",
        client.encryption().cross_signing_status().await.unwrap()
    );

    tokio::spawn(async move {
        info!("Listening for messages...");
        let settings = SyncSettings::default().token(response.next_batch);
        client.sync(settings).await.unwrap();
    });

    Ok((rescive_response_from_matrix, send_registration_to_matrix))
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

/// Used to handle incoming registration requests
#[derive(Clone)]
pub struct ReqHandler {
    /// Send registration status to the local HTTP server
    sender: Sender<RegistrationResponse>,
    /// Contains a vector of __all__ received registration accounts
    tracker: Arc<Mutex<HashMap<Account, AcctMetadata>>>,
    /// ID's and associated accounts
    origin: Arc<Mutex<Origin>>,
}

async fn on_room_message(ev: OriginalSyncRoomMessageEvent, _room: Room, ctx: Ctx<ReqHandler>) {
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
                                // extract's the sender ['Discord:user_x']
                                let sender = arr.get(0).unwrap().to_string();
                                info!("\nSender: {:#?}\nContent: {:#?}", sender, text_content);
                                // creating an account from the extracted sender
                                match Account::from_string(sender.clone()) {
                                    Some(acc) => {
                                        info!("\nAcc: {:#?}", acc);
                                        // checks if this is a registred user from the HTTP server
                                        match ctx.tracker.lock().await.get_mut(&acc) {
                                            Some(v) => {
                                                info!("\nAcc meta: {:#?}", v);
                                                // gets the global object of all registed id's and
                                                // their associated accounts (Discord+Twitter 4 now)
                                                let mut all_verified = true;
                                                let mut origin = ctx.origin.lock().await;
                                                // gets accounts that are related to to this id
                                                let accs = origin.origin.get_mut(&v.id).unwrap();
                                                // check status of this account
                                                match accs.get_mut(&acc) {
                                                    Some(verif_status) => {
                                                        verif_status.set_done().await.unwrap();
                                                        // here we need to check if all accounts are registred
                                                        for (acc, status) in accs {
                                                            info!(
                                                                "\nAcc: {:?}\nStatus: {:?}",
                                                                acc, status
                                                            );
                                                            match status {
                                                                VerifStatus::Pending => {
                                                                    all_verified = false;
                                                                    break;
                                                                }
                                                                _ => {}
                                                            }
                                                        }
                                                        v.status = VerifStatus::Done;
                                                        // if all registration sis done,inform the HTTP server
                                                        if all_verified {
                                                            info!(
                                                                "\nAll Accs {:?} are registred!",
                                                                acc
                                                            );
                                                            ctx.sender
                                                                .send(RegistrationResponse {
                                                                    status:
                                                                        RegistrationStatus::Done(
                                                                            String::from("done"),
                                                                        ),
                                                                })
                                                                .unwrap();
                                                        }
                                                    }
                                                    None => {
                                                        info!("\nUnable to get the verification status for {:?}", acc);
                                                    }
                                                }
                                            }
                                            None => {}
                                        }
                                    }
                                    None => {
                                        info!("Couldn't create Acc object from {:?}", sender);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    None => {}
                }
            }
            RawSyncOrStrippedState::Stripped(_) => {}
        }
    }
}

/// Tree of ID's and their associated accounts along with their status
/// Used to hold/keep track of verification requests
#[derive(Default, Clone)]
struct Origin {
    origin: HashMap<usize, HashMap<Account, VerifStatus>>,
}

impl Origin {
    /// Constructs an [Origin] form [RegistrationRequest] giving all the associated
    /// accounts the [RegistrationStatus::Pending] status
    pub fn derive(image: RegistrationRequest) -> Self {
        let mut leaf: HashMap<Account, VerifStatus> = HashMap::new();
        let mut head: HashMap<usize, HashMap<Account, VerifStatus>> = HashMap::new();
        let id = image.id;
        for req in image.accounts {
            leaf.insert(req, VerifStatus::Pending);
        }
        head.insert(id, leaf);
        Self { origin: head }
    }

    /// Updates the request tree given a [RegistrationRequest]
    pub fn insert(&mut self, image: RegistrationRequest) {
        let id = image.id;
        let thing = self.origin.get_mut(&id);
        match thing {
            Some(v) => {
                for acc in image.accounts {
                    v.insert(acc, VerifStatus::Pending);
                }
            }
            None => {
                self.merge(Origin::derive(image));
            }
        }
    }

    /// merges two [Origin]s aka request trees toegether
    pub fn merge(&mut self, image: Origin) {
        self.origin.extend(image.origin);
    }
}
