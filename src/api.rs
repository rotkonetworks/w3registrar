#![allow(dead_code)]

use anyhow::anyhow;
use futures::StreamExt;
use futures_util::{stream::SplitSink, SinkExt};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr, str::FromStr, sync::Arc, time::Duration};
use subxt::utils::AccountId32;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{
        mpsc::{Receiver, Sender},
        Mutex,
    },
};
use tokio_tungstenite::{tungstenite::Message, WebSocketStream};
use tracing::{error, info};

use crate::{
    matrix::{self, Config, RegistrationResponse},
    node::{
        self,
        api::runtime_types::{
            pallet_identity::types::{Data as IdentityData, Judgement},
            people_rococo_runtime::people::IdentityInfo,
        },
        runtime_types::pallet_identity::types::Registration,
        Client,
    },
    token::Token,
};

#[derive(Clone, Debug)]
pub enum VerifStatus {
    Done,
    Pending,
}

impl VerifStatus {
    pub async fn set_done(&mut self) -> anyhow::Result<()> {
        *self = Self::Done;
        return anyhow::Result::Ok(());
    }
}

#[derive(Debug)]
pub struct AcctMetadata {
    pub status: VerifStatus,
    pub id: AccountId32,
    pub token: Token,
}

pub struct RequestTracker {
    pub req: HashMap<Account, VerifStatus>,
    pub acc_id: AccountId32,
}

impl RequestTracker {
    fn new(req: HashMap<Account, VerifStatus>, acc_id: AccountId32) -> Self {
        Self { req, acc_id }
    }

    fn all_done(&self) -> bool {
        for acc in self.req.values() {
            match acc {
                VerifStatus::Done => {}
                VerifStatus::Pending => return false,
            }
        }
        return true;
    }

    fn is_done(&self, acc: &Account) -> bool {
        match self.req.get(acc) {
            Some(v) => match v {
                VerifStatus::Done => return true,
                VerifStatus::Pending => return false,
            },
            None => return false,
        }
    }
}

impl From<RegistrationRequest> for RequestTracker {
    fn from(value: RegistrationRequest) -> Self {
        let mut map: HashMap<Account, VerifStatus> = HashMap::new();
        for acc in value.accounts {
            map.insert(acc, VerifStatus::Pending);
        }
        RequestTracker::new(map, AccountId32::from_str(&value.id).unwrap())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Hash, PartialEq, Eq)]
pub enum Account {
    Twitter(String),
    Discord(String),
}

impl Account {
    /// Derives an [Account] from a String in the following template
    /// <platform>:<acc-name>
    pub fn from_string(value: String) -> Option<Self> {
        match value.split_once(":") {
            Some((l, r)) => {
                info!("\nPlatform: {}\nName: {}", l, r);
                match &l[1..] {
                    "discord" => return Some(Self::Discord(String::from(&r[..r.len() - 1]))),
                    "twitter" => return Some(Self::Twitter(String::from(&r[..r.len() - 1]))),
                    _ => return None,
                }
            }
            None => return None,
        }
    }

    pub fn inner(&self) -> String {
        match self {
            Account::Twitter(v) => v.to_owned(),
            Account::Discord(v) => v.to_owned(),
        }
    }
}

/// TODO: move this to a "common" module
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RegistrationRequest {
    pub accounts: Vec<Account>,
    pub name: String,
    pub id: String,
    pub timeout: u64,
    pub reg_index: u32,
}

/// TODO: move this to a "common" module
#[derive(Debug)]
pub struct FullRegistrationRequest {
    pub accounts: Vec<Account>,
    pub name: String,
    pub id: AccountId32,
    pub timeout: u64,
    pub stream: Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>,
}

// TODO: make register_user and wait_for_response methods
struct Conn {
    sender: Sender<RegistrationRequest>,
    receiver: Receiver<RegistrationResponse>,
}

// TODO: refacor the address, port, size limit, and number of concurent connections
// TODO: return something that the watcher can use to commmunicate with the two services
// this thing will be used to:
// - check if a verification is already done for an acc of an owner(id)
// - manage verified accs of an owner(id) on the chain
// - set verified accounts
// - TBD...
//
/// Spawns the HTTP server, and the Matrix client
pub async fn spawn_services(cfg: Config) -> anyhow::Result<()> {
    let (recv, send) = matrix::start_bot(cfg).await.unwrap();
    spawn_ws_serv(send, recv, [127, 0, 0, 1], 8080).await
}

#[derive(Clone, Debug)]
struct Listiner {
    ip: [u8; 4],
    port: u16,
    sender: Arc<Mutex<Sender<FullRegistrationRequest>>>,
    receiver: Arc<Mutex<Receiver<RegistrationResponse>>>,
}

/// Converts the inner of [IdentityData] to a [String]
fn identity_data_tostring(data: &IdentityData) -> Option<String> {
    info!("Data: {:?}", data);
    match data {
        IdentityData::Raw0(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw1(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw2(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw3(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw4(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw5(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw6(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw7(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw8(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw9(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw10(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw11(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw12(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw13(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw14(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw15(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw16(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw17(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw18(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw19(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw20(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw21(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw22(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw23(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw24(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw25(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw26(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw27(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw28(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw29(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw30(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw31(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw32(v) => Some(String::from_utf8_lossy(v).to_string()),
        _ => None,
    }
}

impl Listiner {
    pub async fn new(
        ip: [u8; 4],
        port: u16,
        sender: Arc<Mutex<Sender<FullRegistrationRequest>>>,
        receiver: Arc<Mutex<Receiver<RegistrationResponse>>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            ip,
            port,
            sender,
            receiver,
        })
    }

    // TODO: check if Judgement is requested (JudgementRequested)
    /// checks if the registration request is well synchronized with the registrar node
    pub async fn check_node(
        id: AccountId32,
        accounts: Vec<Account>,
    ) -> anyhow::Result<(), anyhow::Error> {
        let client = Client::from_url("wss://dev.rotko.net/people-rococo").await?;
        let registration = node::get_registration(&client, &id).await;
        info!("registration: {:#?}", registration);
        match registration {
            Ok(reg) => {
                Self::is_complete(&reg, &accounts)?;
                Self::has_paid_fee(reg.judgements.0)?;
                Ok(())
            }
            Err(_) => Err(anyhow!(
                "coudn't get registration of {} from the BC node",
                id
            )),
        }
    }

    /// Checks if fee is paid
    fn has_paid_fee(judgements: Vec<(u32, Judgement<u128>)>) -> anyhow::Result<(), anyhow::Error> {
        if judgements
            .iter()
            .any(|(_, j)| matches!(j, Judgement::FeePaid(_)))
        {
            Ok(())
        } else {
            Err(anyhow!("fee is not paid!"))
        }
    }

    /// Compares between the accounts on the idendtity object on the check_node
    /// and the recived requests
    pub fn is_complete<'a>(
        registration: &Registration<u128, IdentityInfo>,
        expected: &Vec<Account>,
    ) -> anyhow::Result<(), anyhow::Error> {
        for acc in expected {
            match acc {
                Account::Twitter(twit_acc) => {
                    match identity_data_tostring(&registration.info.twitter) {
                        Some(identity_twit_acc) => {
                            if !twit_acc.eq(&identity_twit_acc) {
                                return Err(anyhow!(
                                    "got {}, expected {}",
                                    twit_acc,
                                    identity_twit_acc
                                ));
                            }
                        }
                        None => {
                            return Err(anyhow!("twitter acc {} not in the identity obj", twit_acc))
                        }
                    }
                }
                Account::Discord(discord_acc) => {
                    match identity_data_tostring(&registration.info.discord) {
                        Some(identity_discord_acc) => {
                            if !discord_acc.eq(&identity_discord_acc) {
                                return Err(anyhow!(
                                    "got {}, expected {}",
                                    discord_acc,
                                    identity_discord_acc,
                                ));
                            }
                        }
                        None => {
                            return Err(anyhow!("discord acc {} not in identity obj", discord_acc))
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn handle_incoming<'a>(
        message: Message,
        sender: Arc<Mutex<Sender<FullRegistrationRequest>>>,
        receiver: Arc<Mutex<Receiver<RegistrationResponse>>>,
        out: Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>,
    ) -> anyhow::Result<&'a str> {
        match message {
            Message::Text(t) => {
                // TODO: handle the unwrap
                match serde_json::from_str::<RegistrationRequest>(&t) {
                    Ok(reg_req) => match Self::check_node(
                        AccountId32::from_str(&reg_req.id.clone())?,
                        reg_req.accounts.clone(),
                    )
                    .await
                    {
                        Ok(()) => {
                            sender
                                .lock()
                                .await
                                .send(FullRegistrationRequest {
                                    id: AccountId32::from_str(&reg_req.id.clone())?,
                                    accounts: reg_req.accounts.clone(),
                                    name: reg_req.name,
                                    timeout: reg_req.timeout,
                                    stream: out,
                                })
                                .await
                                .unwrap();
                            match tokio::time::timeout(
                                Duration::from_secs(reg_req.timeout),
                                receiver.lock().await.recv(),
                            )
                            .await
                            {
                                Ok(Some(_)) => {
                                    node::register_identity(
                                        AccountId32::from_str(&reg_req.id.clone())?,
                                        reg_req.reg_index,
                                    )
                                    .await?;
                                    return Ok("Done");
                                }
                                _ => return Err(anyhow!("expired")),
                            }
                        }
                        Err(e) => return Err(anyhow!("not registred, error: {}", e)),
                    },
                    Err(e) => return Err(anyhow!("unrecognize request, error: {}", e)),
                }
            }
            Message::Close(_) => return Err(anyhow!("closing connection")),
            _ => return Err(anyhow!("unrecognized message format!")),
        }
    }

    // TODO: change return type to Result
    pub async fn handle_connection(&self, stream: TcpStream) {
        let ws_stream = tokio_tungstenite::accept_async(stream)
            .await
            .expect("Error during the websocket handshake occurred");
        let (outgoing, mut incoming) = ws_stream.split();
        let out = Arc::new(Mutex::new(outgoing));

        while let Some(Ok(message)) = incoming.next().await {
            let _out = Arc::clone(&out);
            match Self::handle_incoming(
                message,
                Arc::clone(&self.sender),
                Arc::clone(&self.receiver),
                _out,
            )
            .await
            {
                Ok(v) => {
                    info!("{}", format!(r#"{{status: {:?}}}"#, v));
                    out.lock()
                        .await
                        .send(Message::Text(format!(r#"{{status: {:?}}}"#, v)))
                        .await
                        .unwrap();
                }
                Err(e) => {
                    info!("{}", format!(r#"{{status: {:?}}}"#, e));
                    out.lock()
                        .await
                        .send(Message::Text(format!(r#"{{status: {:?}}}"#, e)))
                        .await
                        .unwrap();
                }
            }
        }
    }

    pub async fn listen(self: Arc<Self>) -> anyhow::Result<()> {
        let addr = SocketAddr::from((self.ip, self.port));
        let listener = TcpListener::bind(&addr).await?;
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    info!("incoming connection from {:?}...", addr);
                    let server = self.clone();
                    tokio::spawn(async move {
                        server.handle_connection(stream).await;
                    });
                    info!("connection is being processed...");
                }
                Err(e) => {
                    error!("could not accept ws connection! {}", e);
                }
            }
        }
    }
}

pub async fn spawn_ws_serv(
    sender: Arc<Mutex<Sender<FullRegistrationRequest>>>,
    receiver: Arc<Mutex<Receiver<RegistrationResponse>>>,
    ip: [u8; 4],
    port: u16,
) -> anyhow::Result<()> {
    Listiner::new(ip, port, sender, receiver)
        .await
        .listen()
        .await
}
