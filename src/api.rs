#![allow(dead_code)]

use anyhow::anyhow;
use futures::StreamExt;
use futures_util::{stream::SplitSink, SinkExt};
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
    token::{AuthToken,Token},
    config::Config,
};

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub enum VerifStatus {
    Done,
    Pending,
}

impl VerifStatus {
    pub async fn set_done(&mut self) -> anyhow::Result<()> {
        *self = Self::Done;
        anyhow::Result::Ok(())
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AccountMetadata {
    pub status: VerifStatus,
    pub id: AccountId32,
    pub token: Token,
}

pub struct RequestTracker {
    pub requests: HashMap<Account, VerifStatus>,
    pub account_id: AccountId32,
}

impl RequestTracker {
    fn new(requests: HashMap<Account, VerifStatus>, account_id: AccountId32) -> Self {
        Self { requests, account_id }
    }

    fn all_done(&self) -> bool {
        for account in self.requests.values() {
            match account {
                VerifStatus::Done => {}
                VerifStatus::Pending => return false,
            }
        }
        true
    }

    fn is_done(&self, account: &Account) -> bool {
        match self.requests.get(account) {
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
        for account in value.accounts {
            map.insert(account, VerifStatus::Pending);
        }
        RequestTracker { requests: map, account_id: value.id.to_owned() }
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
    pub fn extract_accounts_from_identity(value: &IdentityInfo) -> Vec<Account> {
        let mut result = vec![];
        if let Some(acc) = identity_data_to_string(&value.discord) {
            result.push(Account::Discord(acc))
        }
        if let Some(acc) = identity_data_to_string(&value.twitter) {
            result.push(Account::Twitter(acc))
        }
        // TODO: add matrix itself?
        result
    }

    pub fn get_account_name(&self) -> String {
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

// TODO: refactor the address, port, size limit, and number of concurrent connections
// TODO: return something that the node can use to communicate with the two services
// this thing will be used to:
// - check if a verification is already done for an acc of an owner(id)
// - ...
/// Spawns the HTTP server, and the Matrix client
pub async fn spawn_services(config: Config) -> anyhow::Result<()> {
    matrix::start_bot(config.matrix.clone(), config.redis.clone()).await?;
    spawn_node_listener(&config).await?;
    spawn_websocket_service(&config).await
}

/// Converts the inner of [IdentityData] to a [String]
fn identity_data_to_string(data: &IdentityData) -> Option<String> {
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
struct WebSocketListener {
    ip: [u8; 4],
    port: u16,
}

impl WebSocketListener {
    pub async fn new(ip: [u8; 4], port: u16) -> Self {
        Self { ip, port }
    }

    async fn store_account_data(
        conn: &mut RedisConnection,
        account: &Account,
        reg_req: &RegistrationRequest,
        token: &Token,
    ) -> anyhow::Result<()> {
        redis::pipe()
            .cmd("HSET")
            .arg(serde_json::to_string(account)?)
            .arg("status")
            .arg(serde_json::to_string(&VerifStatus::Pending)?)
            .arg("wallet_id")
            .arg(serde_json::to_string(&reg_req.id)?)
            .arg("token")
            .arg(serde_json::to_string(token)?)
            .cmd("EXPIRE")
            .arg(serde_json::to_string(account)?)
            .arg(reg_req.timeout)
            .exec(&mut conn.conn)
            .map_err(|e| anyhow!("Failed to store account data: {}", e))?;

        Ok(())
    }

    // TODO: check if Judgement is requested (JudgementRequested)
    /// checks if the registration request is well synchronized with the registrar node
    pub async fn check_node(
        config: &Config,
        id: AccountId32,
        accounts: Vec<Account>,
    ) -> anyhow::Result<()> {
        let client = NodeClient::from_url(&config.node.endpoint).await?;
        let registration = node::get_registration(&client, &id).await?;
        Self::is_complete(&registration, &accounts)?;
        Self::has_paid_fee(&registration.judgements.0)?;
        Ok(())
    }

    /// Checks if fee is paid
    /// TODO: migrate this to a common module
    fn has_paid_fee(judgements: &Vec<(u32, Judgement<u128>)>) -> anyhow::Result<(), anyhow::Error> {
        if judgements
            .iter()
                .any(|(_, j)| matches!(j, Judgement::FeePaid(_)))
        {
            Ok(())
        } else {
            Err(anyhow!("fee is not paid!"))
        }
    }

    /// Compares between the accounts on the identity object on the check_node
    /// and the received requests
    /// TODO: migrate this to a common module
    pub fn is_complete(
        registration: &Registration<u128, IdentityInfo>,
        expected: &Vec<Account>,
    ) -> anyhow::Result<()> {
        for account in expected {
            Self::validate_account(account, &registration.info)?;
        }
        Ok(())
    }

    fn validate_account(account: &Account, info: &IdentityInfo) -> anyhow::Result<()> {
        let (expected_name, identity_data, account_type) = match account {
            Account::Twitter(name) => (name, &info.twitter, "twitter"),
            Account::Discord(name) => (name, &info.discord, "discord"),
        };

        let identity_name = identity_data_to_string(identity_data)
            .ok_or_else(|| anyhow!("{} acc {} not in identity obj", account_type, expected_name))?;

        if expected_name != &identity_name {
            return Err(anyhow!("got {}, expected {}", expected_name, identity_name));
        }

        Ok(())
    }

    // monitor changes in identity hash
    async fn monitor_hash_changes(client: RedisClient, key: String) -> Option<String> {
        let mut pubsub = client.get_async_pubsub().await.unwrap();
        let channel = format!("__keyspace@0__:{}", key);
        pubsub.subscribe(channel).await.unwrap();
        while let Some(_) = pubsub.on_message().next().await {
            let mut conn = client.get_connection().unwrap();
            let status: String = conn.hget(&key, String::from("status")).unwrap();
            let status: VerifStatus = serde_json::from_str(&status).unwrap();
            match status {
                VerifStatus::Done => {
                    return Some(String::from("Done"));
                }
                _ => {}
            }
        }
        None
    }

    /// Handles WS incoming connections
    pub async fn handle_incoming(
        &self,
        message: Message,
        out: Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>,
        config: &Config,
    ) -> anyhow::Result<()> {
        match message {
            Message::Text(text) => self.process_registration_request(&text, out, config).await,
            Message::Close(_) => Err(anyhow!("closing connection")),
            _ => Err(anyhow!("unrecognized message format")),
        }
    }

    async fn process_registration_request(
        &self,
        text: &str,
        out: Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>,
        config: &Config,
    ) -> anyhow::Result<()> {
        let reg_req = Self::parse_registration_request(text)?;
        Self::check_node(config, reg_req.id.clone(), reg_req.accounts.clone()).await?;

        let mut conn = RedisConnection::create_conn(&config.redis.url)?;
        Self::store_registration_data(&mut conn, &reg_req)?;

        for account in &reg_req.accounts {
            Self::process_account(&mut conn, account, &reg_req, &out).await?;
        }

        Self::await_registration_completion(&reg_req, &config).await?;
        node::register_identity(reg_req.id, reg_req.reg_index, &config).await.map(|_| ())
    }

    fn parse_registration_request(text: &str) -> anyhow::Result<RegistrationRequest> {
        serde_json::from_str(text)
            .map_err(|e| anyhow!("unrecognized request: {}", e))
    }

    fn store_registration_data(
        conn: &mut RedisConnection, 
        reg_req: &RegistrationRequest,
    ) -> anyhow::Result<()> {
        let id_str = serde_json::to_string(&reg_req.id)?;
        let accounts: HashSet<&Account, std::collections::hash_map::RandomState> =
            HashSet::from_iter(reg_req.accounts.iter());
        let accounts_str = serde_json::to_string(&accounts)?;
        let status_str = serde_json::to_string(&VerifStatus::Pending)?;

        redis::pipe()
            .cmd("HSET")
            .arg(&id_str)
            .arg("accounts")
            .arg(&accounts_str)
            .arg("status")
            .arg(&status_str)
            .cmd("EXPIRE")
            .arg(&id_str)
            .arg(reg_req.timeout)
            .exec(&mut conn.conn)
            .map_err(|e| anyhow!("failed to store registration: {}", e))
    }

    async fn process_account(
        conn: &mut RedisConnection,
        account: &Account,
        reg_req: &RegistrationRequest,
        out: &Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>,
    ) -> anyhow::Result<()> {
        let token = Token::generate().await;

        Self::send_token_message(out, account, &token).await?;
        Self::store_account_data(conn, account, reg_req, &token).await?;

        Ok(())
    }

    async fn send_token_message(
        out: &Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>,
        account: &Account,
        token: &Token,
    ) -> anyhow::Result<()> {
        out.lock()
            .await
            .send(Message::Text(format!(
                        r#"{{{:?}: {}}}"#,
                        account,
                        token.show()
            )))
            .await
            .map_err(|e| anyhow!("failed to send token: {}", e))
    }

    async fn await_registration_completion(reg_req: &RegistrationRequest, config: &Config) -> anyhow::Result<()> {
        let client = RedisClient::open(config.redis.url.as_str())?;
        let id_str = serde_json::to_string(&reg_req.id)?;

        match tokio::time::timeout(
            Duration::from_secs(reg_req.timeout),
            WebSocketListener::monitor_hash_changes(client, id_str),
        ).await {
            Ok(Some(_)) => Ok(()),
            _ => Err(anyhow!("registration timeout")),
        }
    }

    // TODO: change return type to Result
    pub async fn handle_connection(&self, stream: TcpStream, config: &Config) {
        let ws_stream = tokio_tungstenite::accept_async(stream)
            .await
            .expect("Error during the websocket handshake occurred");
        let (outgoing, mut incoming) = ws_stream.split();
        let out = Arc::new(Mutex::new(outgoing));
        while let Some(Ok(message)) = incoming.next().await {
            let _out = Arc::clone(&out);
            match self.handle_incoming(message, _out, config).await {
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

    pub async fn listen(self, config: &Config) -> anyhow::Result<()> {
        let addr = SocketAddr::from((self.ip, self.port));
        let listener = TcpListener::bind(&addr).await?;
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    info!("incoming connection from {:?}...", addr);
                    let clone = self.clone();
                    let config_clone = config.clone();
                    tokio::spawn(async move {
                        clone.handle_connection(stream, &config_clone).await;
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
pub async fn spawn_websocket_service(cfg: &Config) -> anyhow::Result<()> {
    let websocket_config = &cfg.websocket;
    WebSocketListener::new(websocket_config.ip, websocket_config.port).await.listen(cfg).await
}

/// Spawns a new client (substrate) to listen for incoming events, in particular
/// `requestJudgement` requests
pub async fn spawn_node_listener(cfg: &Config) -> anyhow::Result<()> {
    NodeListener::new(cfg.node.endpoint.clone()).await.listen(cfg).await
}

/// Used to listen/interact with BC events on the substrate node
#[derive(Debug, Clone)]
struct NodeListener {
    client: NodeClient,
}

impl NodeListener {
    // TODO: change return from Self to Result<Self>
    /// Creates a new [NodeListener]
    ///
    /// # Panics
    /// This function will fail if the _redis_url_ is an invalid url to a redis DB
    /// or if _node_url_ is not a valid url for a substrate BC node
    pub async fn new(node_url: String) -> Self {
        Self {
            client: NodeClient::from_url(&node_url).await.unwrap(),
        }
    }

    fn is_complete(
        registration: &Registration<u128, IdentityInfo>,
        expected: &Vec<Account>,
    ) -> anyhow::Result<()> {
        for account in expected {
            WebSocketListener::validate_account(account, &registration.info)?;
        }
        Ok(())
    }

    fn has_paid_fee(judgements: &Vec<(u32, Judgement<u128>)>) -> anyhow::Result<(), anyhow::Error> {
        if judgements
            .iter()
            .any(|(_, j)| matches!(j, Judgement::FeePaid(_)))
        {
            Ok(())
        } else {
            Err(anyhow!("fee is not paid!"))
        }
    }


    /// Listens for incoming BC events on the substrate node
    pub async fn listen(self, config: &Config) -> anyhow::Result<()> {
        let config = config.clone();
        tokio::spawn(async move {
            let mut block_stream = self.client.blocks().subscribe_finalized().await.unwrap();
            while let Some(item) = block_stream.next().await {
                let block = item.unwrap();
                for event in block.events().await.unwrap().iter() {
                    match event.unwrap().as_event::<JudgementRequested>() {
                        Ok(Some(req)) => {
                            let clone = self.clone();
                            let config_clone = config.clone();
                            tokio::spawn(async move {
                                info!("Judgement requested from other client!");
                                info!("status: {:?}", clone.handle_registration(&req.who, &config_clone).await);
                            });
                        }
                        _ => {}
                    }
                }
            }
        });
        Ok(())
    }

    pub fn create_redis_connection(config: &Config) -> anyhow::Result<RedisConnection> {
        RedisConnection::create_conn(&config.redis.url)
            .map_err(|e| anyhow!("Failed to create Redis connection: {}", e))
    }

    async fn get_and_validate_registration(
        client: &NodeClient,
        who: &AccountId32,
    ) -> Result<Registration<u128, IdentityInfo>, anyhow::Error> {
        node::get_registration(client, who)
            .await
            .map_err(|_| anyhow!("could not get registration for {}", who))
    }

    async fn handle_registration(&self, who: &AccountId32, config: &Config) -> Result<(), anyhow::Error> {
        let registration = Self::get_and_validate_registration(&self.client, who).await?;

        // Validate fee payment 
        // TODO: there is more registrars in mainnet than ours
        WebSocketListener::has_paid_fee(&registration.judgements.0)?;

        // Set up Redis connection
        let mut conn = Self::create_redis_connection(config)?;

        // Store wallet registration data
        Self::store_wallet_registration(&mut conn, who, &registration, config.redis.timeout)?;

        // Store individual account data
        for account in Account::extract_accounts_from_identity(&registration.info) {
            Self::store_account_data(&mut conn, &account, who, config.redis.timeout).await?;
        }

        Ok(())
    }
}
pub struct RedisConnection {
    conn: redis::Connection,
}

impl RedisConnection {
    /// TODO
    pub fn create_conn(addr: &str) -> anyhow::Result<Self> {
        let client = RedisClient::open(addr)?;
        let mut conn = client.get_connection()?;

        let _: () = redis::cmd("CONFIG")
            .arg("SET")
            .arg("notify-keyspace-events")
            .arg("KEA")
            .query(&mut conn)?;
        info!("redis connection configured");
        Ok(Self { conn })
    }

    /// searchs through the redis DB for keys that are similar to the `pattern`
    pub fn search(&mut self, pattern: String) -> Vec<String> {
        self.conn
            .scan_match::<&str, String>(&pattern)
            .unwrap()
            .collect()
    }

    /// TODO
    pub fn get_challenge_token(&mut self, account: &str) -> Token {
        let token: String = self.conn.hget(account, "token").unwrap();
        serde_json::from_str(&token).unwrap()
    }

    /// Gets the wallet_id of an account in the format of "[Account]:[AccountId32]"
    pub fn get_wallet_id(&mut self, account: &str) -> AccountId32 {
        let account = self
            .conn
            .hget::<&str, &str, String>(account, "wallet_id")
            .unwrap();
        serde_json::from_str(&account).unwrap()
    }

    /// TODO
    pub fn get_status(&mut self, account: &str) -> VerifStatus {
        let status: String = self.conn.hget(account, "status").unwrap();
        serde_json::from_str::<VerifStatus>(&status).unwrap()
    }

    /// TODO
    pub fn set_status(&mut self, account: &str, status: VerifStatus) -> anyhow::Result<()> {
        self.conn.hset::<&str, &str, String, ()>(
            account,
            "status",
            serde_json::to_string(&status)?,
        )?;
        Ok(())
    }

    /// Checks if all accounts under the hashset of the `id` key is verified
    pub fn is_all_verified(&mut self, id: &AccountId32) -> anyhow::Result<bool> {
        let metadata: String = self
            .conn
            .hget(&serde_json::to_string(id).unwrap(), "accounts")?;
        let metadata: HashSet<Account> = serde_json::from_str(&metadata)?;
        Ok(metadata.len() == 0)
    }

    /// Sets the _status_ field of the hashset of `id` to [VerifStatus::Done]
    pub fn signal_done(&mut self, id: &AccountId32) -> anyhow::Result<()> {
        self.conn.hset::<String, &str, String, ()>(
            serde_json::to_string(&id)?,
            "status",
            serde_json::to_string(&VerifStatus::Done)?,
        )?;
        Ok(())
    }

    /// Removes the `account` from the list of the pending account on the hashset 
    /// with `id` as a key
    pub fn remove_account(&mut self, id: &AccountId32, account: &Account) -> anyhow::Result<()> {
        let metadata: String = self
            .conn
            .hget(&serde_json::to_string(id).unwrap(), "accounts")?;
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





impl NodeListener {
    async fn check_node(
        config: &Config,
        id: AccountId32,
        accounts: Vec<Account>,
    ) -> anyhow::Result<(), anyhow::Error> {
        let client = NodeClient::from_url(&config.node.endpoint).await?;
        let registration = node::get_registration(&client, &id).await?;
        info!("registration: {:#?}", registration);
        Self::is_complete(&registration, &accounts)?;
        Self::has_paid_fee(&registration.judgements.0)?;
        Ok(())
    }

    fn store_wallet_registration(
        conn: &mut RedisConnection,
        who: &AccountId32,
        reg: &Registration<u128, IdentityInfo>,
        timeout: u64,
    ) -> Result<(), anyhow::Error> {
        let accounts = Account::extract_accounts_from_identity(&reg.info);
        let account_set = HashSet::<&Account>::from_iter(accounts.iter());

        redis::pipe()
            .cmd("HSET")
            .arg(serde_json::to_string(who)?)
            .arg("accounts")
            .arg(serde_json::to_string(&account_set)?)
            .arg("status")
            .arg(serde_json::to_string(&VerifStatus::Pending)?)
            .cmd("EXPIRE")
            .arg(serde_json::to_string(who)?)
            .arg(timeout)
            .exec(&mut conn.conn)
            .map_err(|e| anyhow!("Failed to store wallet registration: {}", e))?;

        Ok(())
    }

    async fn store_account_data(
        conn: &mut RedisConnection,
        account: &Account,
        who: &AccountId32,
        timeout: u64,
    ) -> Result<(), anyhow::Error> {
        let token = Token::generate().await;

        redis::pipe()
            .cmd("HSET")
            .arg(serde_json::to_string(account)?)
            .arg("status")
            .arg(serde_json::to_string(&VerifStatus::Pending)?)
            .arg("wallet_id")
            .arg(serde_json::to_string(who)?)
            .arg("token")
            .arg(serde_json::to_string(&token)?)
            .cmd("EXPIRE")
            .arg(serde_json::to_string(account)?)
            .arg(timeout)
            .exec(&mut conn.conn)
            .map_err(|e| anyhow!("Failed to store account data: {}", e))?;

        Ok(())
    }
}
