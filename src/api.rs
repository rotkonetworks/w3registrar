#![allow(dead_code)]

use anyhow::anyhow;
use futures::StreamExt;
use futures_util::{stream::SplitSink, SinkExt};
use redis;
use redis::{Client as RedisClient, Commands};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
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
    config::{RedisConfig, WatcherConfig, WebsocketConfig},
    matrix::{self, RegistrationResponse},
    node::{
        self,
        api::runtime_types::{
            pallet_identity::types::{Data as IdentityData, Judgement},
            people_rococo_runtime::people::IdentityInfo,
        },
        identity::events::JudgementRequested,
        runtime_types::pallet_identity::types::Registration,
        Client as NodeClient,
    },
    token::AuthToken,
    token::Token,
    Config,
};

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
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

#[derive(Debug, serde::Serialize, serde::Deserialize)]
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
        RequestTracker::new(map, value.id.to_owned())
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

    pub fn into_accounts(value: &IdentityInfo) -> Vec<Account> {
        let mut result = vec![];
        if let Some(acc) = identity_data_tostring(&value.discord) {
            result.push(Account::Discord(acc))
        }
        if let Some(acc) = identity_data_tostring(&value.twitter) {
            result.push(Account::Twitter(acc))
        }
        return result;
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
    pub id: AccountId32,
    pub timeout: u64,
    pub reg_index: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RegistrationElement {
    accounts: Vec<(Account, VerifStatus)>,
    request_status: VerifStatus,
}

impl RegistrationElement {
    pub fn new(accounts: Vec<(Account, VerifStatus)>, request_status: VerifStatus) -> Self {
        Self {
            accounts,
            request_status,
        }
    }

    pub fn extend(&mut self, accounts: Vec<Account>) {
        for account in accounts {
            self.accounts.push((account, VerifStatus::Pending));
        }
    }
}
// TODO: make register_user and wait_for_response methods
struct Conn {
    sender: Sender<RegistrationRequest>,
    receiver: Receiver<RegistrationResponse>,
}

/// Spawns the Websocket client, Matrix client and the Node(substrate) listener
pub async fn spawn_services(cfg: Config) -> anyhow::Result<()> {
    matrix::start_bot(cfg.matrix, &cfg.redis).await?;
    spawn_node_listener(cfg.watcher, &cfg.redis).await?;
    spawn_ws_serv(cfg.websocket, &cfg.redis).await
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

#[derive(Debug, Clone)]
struct Listener {
    ip: [u8; 4],
    port: u16,
    redis_cfg: RedisConfig,
}

impl Listener {
    pub async fn new(websocket_cfg: WebsocketConfig, redis_cfg: RedisConfig) -> Self {
        Self {
            ip: websocket_cfg.ip,
            port: websocket_cfg.port,
            redis_cfg,
        }
    }

    // TODO: check if Judgement is requested (JudgementRequested)
    /// checks if the registration request is well synchronized with the registrar node
    pub async fn check_node(
        id: AccountId32,
        accounts: Vec<Account>,
    ) -> anyhow::Result<(), anyhow::Error> {
        let client = NodeClient::from_url("wss://dev.rotko.net/people-rococo").await?;
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
    /// TODO: migrate this to a common module
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
    /// TODO: migrate this to a common module
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

    async fn monitor_hash_changes(client: RedisClient, key: String) -> Option<String> {
        let mut pubsub = client.get_async_pubsub().await.unwrap();
        let channel = format!("__keyspace@0__:{}", key);
        pubsub.subscribe(channel).await.unwrap();
        while let Some(_) = pubsub.on_message().next().await {
            let mut con = client.get_connection().unwrap();
            let status: String = con.hget(&key, String::from("status")).unwrap();
            let status: VerifStatus = serde_json::from_str(&status).unwrap();
            match status {
                VerifStatus::Done => {
                    return Some(String::from("Done"));
                }
                _ => {}
            }
        }
        return None;
    }

    /// Handels WS incomming connections as a [RegistrationRequest]
    ///
    /// # Returns
    /// * `Ok("Judged with reasonable")` if the registration process is completed successfully
    /// * `Err("...")` if:
    ///     - request body cannot be deserialize to a [RegistrationRequest]
    ///     - unable to establish a redis connection
    ///     - unable to submit data to the redis server
    ///     - registration has expired (check timeout field in the [RegistrationRequest])
    ///     - serialization error of [VerifStatus], [AccountId32], ...
    pub async fn handle_incoming<'a>(
        &self,
        message: Message,
        out: Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>,
    ) -> anyhow::Result<&'a str> {
        match message {
            Message::Text(t) => {
                match serde_json::from_str::<RegistrationRequest>(&t) {
                    Ok(reg_req) => {
                        // TODO:check if a verification is already done for an acc of an owner(id)
                        match Self::check_node(reg_req.id.clone(), reg_req.accounts.clone()).await {
                            Ok(()) => {
                                let mut conn = RedisConnection::create_conn(&self.redis_cfg)?;

                                redis::pipe()
                                    .cmd("HSET")
                                    .arg(serde_json::to_string(&reg_req.id.to_owned())?)
                                    .arg("accounts")
                                    .arg(serde_json::to_string::<HashSet<&Account>>(
                                        &HashSet::from_iter(reg_req.accounts.iter()),
                                    )?)
                                    .arg("status")
                                    .arg(serde_json::to_string(&VerifStatus::Pending)?)
                                    .cmd("EXPIRE") // expire time
                                    .arg(serde_json::to_string(&reg_req.id.to_owned())?)
                                    .arg(reg_req.timeout)
                                    .exec(&mut conn.conn)?;

                                for account in reg_req.accounts {
                                    let token = Token::generate().await;
                                    out.lock()
                                        .await
                                        .send(Message::Text(format!(
                                            r#"{{{:?}: {}}}"#,
                                            account,
                                            token.show()
                                        )))
                                        .await?;

                                    // acc stuff
                                    redis::pipe()
                                        .cmd("HSET") // create a set
                                        .arg(format!(
                                            "{}:{}",
                                            serde_json::to_string(&account)?,
                                            serde_json::to_string(&reg_req.id.clone())?
                                        ))
                                        .arg("status")
                                        .arg(serde_json::to_string(&VerifStatus::Pending)?)
                                        .arg("wallet_id")
                                        .arg(serde_json::to_string(&reg_req.id.clone())?)
                                        .arg("token")
                                        .arg(serde_json::to_string(&token)?)
                                        .cmd("EXPIRE") // expire time
                                        .arg(serde_json::to_string(&account)?)
                                        .arg(reg_req.timeout)
                                        .exec(&mut conn.conn)?;
                                }

                                match tokio::time::timeout(
                                    Duration::from_secs(reg_req.timeout),
                                    Self::monitor_hash_changes(
                                        RedisClient::open(
                                            self.redis_cfg.to_full_domain().as_str(),
                                        )?,
                                        serde_json::to_string(&reg_req.id.to_owned())?,
                                    ),
                                )
                                .await
                                {
                                    Ok(Some(_source)) => {
                                        node::register_identity(reg_req.id, reg_req.reg_index).await
                                    }
                                    _ => return Err(anyhow!("expired")),
                                }
                            }
                            Err(e) => return Err(anyhow!("not registred, error: {}", e)),
                        }
                    }
                    Err(e) => return Err(anyhow!("unrecognize request, error: {}", e)),
                }
            }
            Message::Close(_) => return Err(anyhow!("closing self.connection")),
            _ => return Err(anyhow!("unrecognized message format!")),
        }
    }

    /// Handles incoming websocket connection
    pub async fn handle_connection(&self, stream: TcpStream) {
        let ws_stream = tokio_tungstenite::accept_async(stream)
            .await
            .expect("Error during the websocket handshake occurred");
        let (outgoing, mut incoming) = ws_stream.split();
        let out = Arc::new(Mutex::new(outgoing));
        while let Some(Ok(message)) = incoming.next().await {
            let _out = Arc::clone(&out);
            match self.handle_incoming(message, _out).await {
                Ok(v) => {
                    info!("{}", format!(r#"{{"status": "{:?}""}}"#, v));
                    out.lock()
                        .await
                        .send(Message::Text(format!(r#"{{"status": "{:?}"}}"#, v)))
                        .await
                        .unwrap();
                }
                Err(e) => {
                    info!("{}", format!(r#"{{"status": "{:?}"}}"#, e));
                    out.lock()
                        .await
                        .send(Message::Text(format!(r#"{{"status": "{:?}"}}"#, e)))
                        .await
                        .unwrap();
                }
            }
        }
    }

    pub async fn listen(self) -> anyhow::Result<()> {
        let addr = SocketAddr::from((self.ip, self.port));
        let listener = TcpListener::bind(&addr).await?;
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    info!("incoming connection from {:?}...", addr);
                    let clone = self.clone();
                    tokio::spawn(async move {
                        clone.handle_connection(stream).await;
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

/// Spawns a websocket server to listen for incoming registration requests
pub async fn spawn_ws_serv(
    websocket_cfg: WebsocketConfig,
    redis_cfg: &RedisConfig,
) -> anyhow::Result<()> {
    Listener::new(websocket_cfg, redis_cfg.to_owned())
        .await
        .listen()
        .await
}

/// Spanws a new node (substrate) listener to listen for incoming events, in particular
/// `requestJudgement` requests
pub async fn spawn_node_listener(
    watcher_cfg: WatcherConfig,
    redis_cfg: &RedisConfig,
) -> anyhow::Result<()> {
    NodeListener::new(watcher_cfg.endpoint, redis_cfg.to_owned())
        .await?
        .listen()
        .await
}

/// Used to listen/interact with BC events on the substrate node
#[derive(Debug, Clone)]
struct NodeListener {
    client: NodeClient,
    redis_cfg: RedisConfig,
}

impl NodeListener {
    /// Creates a new [NodeListener]
    ///
    /// # Panics
    /// This function will fail if the _redis_url_ is an invalid url to a redis server
    /// or if _node_url_ is not a valid url for a substrate BC node
    pub async fn new(node_url: String, redis_cfg: RedisConfig) -> anyhow::Result<Self> {
        Ok(Self {
            client: NodeClient::from_url(&node_url).await?,
            redis_cfg,
        })
    }

    /// Listens for incoming events on the substrate node, in particular
    /// the `requestJudgement` event
    pub async fn listen(self) -> anyhow::Result<()> {
        let mut block_stream = self.client.blocks().subscribe_finalized().await?;
        tokio::spawn(async move {
            while let Some(item) = block_stream.next().await {
                let block = item.unwrap();
                for event in block.events().await.unwrap().iter() {
                    match event.unwrap().as_event::<JudgementRequested>() {
                        Ok(Some(req)) => {
                            let clone = self.clone();
                            tokio::spawn(async move {
                                info!("Judgement requested from other client!");
                                info!("status: {:?}", clone.handle_registration(&req.who).await);
                            });
                        }
                        _ => {}
                    }
                }
            }
        });
        Ok(())
    }

    async fn handle_registration(&self, who: &AccountId32) -> anyhow::Result<(), anyhow::Error> {
        let registration = node::get_registration(&self.client, who).await;
        match registration {
            Ok(reg) => {
                Listener::has_paid_fee(reg.judgements.0)?;
                let mut conn = RedisConnection::create_conn(&self.redis_cfg)?;

                // TODO: make all commands chained together and then executed
                // all at once!
                redis::pipe()
                    .cmd("HSET")
                    .arg(serde_json::to_string(who)?)
                    .arg("accounts")
                    .arg(serde_json::to_string::<HashSet<&Account>>(
                        &HashSet::from_iter(Account::into_accounts(&reg.info).iter()),
                    )?)
                    .arg("status")
                    .arg(serde_json::to_string(&VerifStatus::Pending)?)
                    .cmd("EXPIRE") // expire time
                    .arg(serde_json::to_string(who)?)
                    .arg(300)
                    .exec(&mut conn.conn)?;

                for account in Account::into_accounts(&reg.info) {
                    // acc stuff
                    redis::pipe()
                        .cmd("HSET") // create a set
                        .arg(serde_json::to_string(&account)?)
                        .arg("status")
                        .arg(serde_json::to_string(&VerifStatus::Pending)?)
                        .arg("wallet_id")
                        .arg(serde_json::to_string(who)?)
                        .arg("token")
                        .arg(serde_json::to_string(&Token::generate().await)?)
                        .cmd("EXPIRE") // expire time
                        .arg(serde_json::to_string(&account)?)
                        .arg(300)
                        .exec(&mut conn.conn)?;
                }
                return Ok(());
            }
            Err(_) => return Err(anyhow!("could not get registration for {}", who)),
        }
    }
}

pub struct RedisConnection {
    conn: redis::Connection,
}

impl RedisConnection {
    /// Connect to running redis server given [RedisConfig]
    pub fn create_conn(addr: &RedisConfig) -> anyhow::Result<Self> {
        let client = RedisClient::open(addr.to_full_domain())?;
        let mut conn = client.get_connection()?;

        let _: () = redis::cmd("CONFIG")
            .arg("SET")
            .arg("notify-keyspace-events")
            .arg("KEA")
            .query(&mut conn)?;
        info!("redis connection configured");
        Ok(Self { conn })
    }

    /// Search through the redis DB for keys that are similar to the `pattern`
    pub fn search(&mut self, pattern: String) -> Vec<String> {
        let mut keys = vec![];
        let mut res = self.conn.scan_match::<&str, String>(&pattern).unwrap();
        while let Some(item) = res.next() {
            keys.push(item);
        }
        return keys;
    }

    /// Get the chalange [Token] from a hashset with `account` as a name, `token`
    /// as the key paire of the desired token using an establisehd redis connection
    ///
    /// # Note:
    /// The `account` should be in the "[Account]:[AccountId32]" format
    pub fn get_challange_token(&mut self, account: &str) -> Token {
        let token: String = self.conn.hget(account, "token").unwrap();
        serde_json::from_str(&token).unwrap()
    }

    /// Get the [AccountId32] from a hashset with `account` as a name, `wallet_id`
    /// as the key paire of the desired wallet id using an establisehd redis connection
    ///
    /// # Note:
    /// The `account` should be in the "[Account]:[AccountId32]" format
    pub fn get_wallet_id(&mut self, account: &str) -> AccountId32 {
        let account = self
            .conn
            .hget::<&str, &str, String>(account, "wallet_id")
            .unwrap();
        serde_json::from_str(&account).unwrap()
    }

    /// Get the status [VerifStatus] from a hashset with `account` as a name, `status`
    /// as the key paire of the desired status using an establisehd redis connection
    ///
    /// # Note:
    /// The `account` should be in the "[Account]:[AccountId32]" format
    pub fn get_status(&mut self, account: &str) -> VerifStatus {
        let status: String = self.conn.hget(account, "status").unwrap();
        serde_json::from_str::<VerifStatus>(&status).unwrap()
    }

    /// Set the `status` value of an hashset of name `account` to the `status` param
    ///
    /// # Note:
    /// The `account` should be in the "[Account]:[AccountId32]" format
    pub fn set_status(&mut self, account: &str, status: VerifStatus) -> anyhow::Result<()> {
        self.conn.hset::<&str, &str, String, ()>(
            account,
            "status",
            serde_json::to_string(&status)?,
        )?;
        Ok(())
    }

    /// Checks if all acccounts under the hashset of the `id` key is verified
    pub fn is_all_verified(&mut self, id: &AccountId32) -> anyhow::Result<bool> {
        let metadata: String = self.conn.hget(&serde_json::to_string(id)?, "accounts")?;
        let metadata: HashSet<Account> = serde_json::from_str(&metadata)?;
        Ok(metadata.len() == 0)
    }

    /// Set the status field of a hashset with `id` as a name to [VerifStatus::Done]
    /// using an establisehd redis connection
    ///
    /// # Note:
    /// The `account` should be in the "[Account]:[AccountId32]" format
    pub fn signal_done(&mut self, id: &AccountId32) -> anyhow::Result<()> {
        self.conn.hset::<String, &str, String, ()>(
            serde_json::to_string(&id)?,
            "status",
            serde_json::to_string(&VerifStatus::Done)?,
        )?;
        Ok(())
    }

    /// Remove the `account` from the list of the pending account on the hashset
    /// with `id` as a key
    pub fn remove_acc(&mut self, id: &AccountId32, account: &Account) -> anyhow::Result<()> {
        let metadata: String = self.conn.hget(&serde_json::to_string(id)?, "accounts")?;
        let mut metadata: HashSet<Account> = serde_json::from_str(&metadata)?;

        metadata.remove(account);
        self.conn.hset::<String, &str, String, ()>(
            serde_json::to_string(&id)?,
            "accounts",
            serde_json::to_string(&metadata)?,
        )?;
        Ok(())
    }
}
