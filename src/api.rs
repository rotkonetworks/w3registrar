#![allow(dead_code)]
use std::{collections::HashMap, time::Duration};

use actix_web::{middleware, web, App, HttpRequest, HttpResponse, HttpServer};
use flume::{Receiver, Sender};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::info;

use crate::matrix::{self, Config, RegistrationResponse};

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
    pub id: usize,
}

pub struct RequestTracker {
    pub req: HashMap<Account, VerifStatus>,
    pub acc_id: usize,
}

impl RequestTracker {
    fn new(req: HashMap<Account, VerifStatus>, acc_id: usize) -> Self {
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
            // let password = Alphanumeric.sample_string(&mut rand::thread_rng(), 16);
            map.insert(acc, VerifStatus::Pending);
        }
        RequestTracker::new(map, value.id)
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
}

/// TODO: move this to a "common" module
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RegistrationRequest {
    pub accounts: Vec<Account>,
    pub name: String,
    pub id: usize,
    pub timeout: u64,
}

/// This handler uses json extractor with limit
/// This should will wait for the verification status to be
/// handled by the matrix HS, and will return only if:
/// - verification is done successfully
/// - verification deadline has arrived
//
// TODO: add other response types like:
// * user is already verified
// * verification request already exist
// #[post("/register")]
async fn verify(
    item: web::Json<RegistrationRequest>,
    con: web::Data<Conn>,
    req: HttpRequest,
) -> HttpResponse {
    let timeout = item.0.timeout;
    if timeout > 360 {
        return HttpResponse::Ok().json(json!({
            "status": "invalid timeout (shoudl be less/or equal to 360)",
        }));
    }
    // TODO: check if accounts are already verified
    // sneding request to the matrix HS
    con.sender.send(item.0).unwrap();
    if con.reciver.is_disconnected() {
        return HttpResponse::Ok().json(json!({
            "status": "dropped",
        }));
    }

    // waiting for response from the matrix HS
    match con.reciver.recv_timeout(Duration::from_secs(timeout)) {
        Ok(v) => {
            info!("Verification is done for {:#?}", v);
            return HttpResponse::Ok().json(v);
        }
        Err(e) => {
            info!("Verification expired: {:?}", e);
            return HttpResponse::Ok().json(json!({
                "status": "expired",
            }));
        }
    };
}

// TODO: make register_user and wait_for_response methods
struct Conn {
    sender: Sender<RegistrationRequest>,
    reciver: Receiver<RegistrationResponse>,
}

// TODO: refacor the address, port, size limit, and number of concurent connections
// TODO: return something that the watcher can use to commmunicate with the two services
// this thing will be used to:
// - check if a verification is already done for an acc of an owner(id)
// - manage verified accs of an owner(id) on the chain
// - set verified accounts
// - TBD...
/// Spawns the HTTP server, and the Matrix client
pub async fn spawn_services(cfg: Config) -> Result<(), std::io::Error> {
    tokio::spawn(async {
        // spawning the matrix home server
        let (recv, send) = matrix::start_bot(cfg).await.unwrap();
        spaw_http_serv("/register", send, recv, "127.0.0.1", 8080).await.unwrap(); 
    });
    Ok(())
}

pub async fn spaw_http_serv(
    registration_endpoint: &'static str,
    sender: Sender<RegistrationRequest>,
    reciver: Receiver<RegistrationResponse>,
    ip: &'static str,
    port: u16
) -> Result<(), std::io::Error> {
    HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default())
            .app_data(web::JsonConfig::default().limit(1024))
            .service(
                web::resource(registration_endpoint)
                    .app_data(web::Data::new(Conn {
                        sender: sender.clone(),
                        reciver: reciver.clone(),
                    }))
                    .route(web::post().to(verify)),
            )
    })
    .bind((ip, port))
    .unwrap()
    .run()
    .await
}
