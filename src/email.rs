#![allow(unused)]

use anyhow::anyhow;
use std::net::TcpStream;
use std::str::FromStr;
use std::time::Duration;

use crate::{
    api::{Account, AccountType, RedisConnection},
    config::RedisConfig,
    node::register_identity,
};
use imap::Session;
use native_tls::{TlsConnector, TlsStream};
use subxt::utils::AccountId32;
use tracing::{error, info};

use crate::config::GLOBAL_CONFIG;

/// Represents an email message with optional body content and sender information
/// Used for processing incoming verification emails
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Mail {
    pub body: Option<String>,
    pub sender: String,
}

impl Mail {
    /// Creates a new Mail instance with the given sender and optional body
    fn new(sender: String, body: Option<String>) -> Self {
        Self { body, sender }
    }
    /// Processes the content of an email message for account verification
    /// Checks if the email body matches the expected verification token and updates
    /// verification state in Redis accordingly
    ///
    /// # Arguments
    /// * `redis_connection` - Active Redis connection for state management
    /// * `account_id` - The account ID being verified
    /// * `network` - The network identifier (e.g., "polkadot", "kusama")
    async fn handle_content_(
        // TOOO: refactor this use same trait with matrix?
        &self,
        redis_connection: &mut RedisConnection,
        account_id: &AccountId32,
        network: &str,
    ) -> anyhow::Result<()> {
        let account_type = AccountType::Email.to_string();
        let state = match redis_connection
            .get_verification_state(network, account_id)
            .await?
        {
            Some(state) => state,
            None => return Ok(()),
        };
        info!("Verification state: {:?}", state);

        // TODO: hardcoded?
        let challenge = match state.challenges.get(&account_type) {
            Some(challenge) => challenge,
            None => return Ok(()),
        };
        info!("Challenge: {:?}", challenge);

        if challenge.done {
            return Ok(());
        }

        let token = match &challenge.token {
            Some(token) => token,
            None => return Ok(()),
        };
        info!("Token: {:?}", token);

        let body_token = self.body
            .as_ref()
            .and_then(|b| b.lines().next())
            .map(|l| l.trim().to_owned());

        if body_token.ne(&Some(token.to_owned())) {
            info!("Wrong token, got {:?} but expected {:?}", self.body, token);
            return Ok(());
        }

        redis_connection
            .update_challenge_status(network, account_id, &account_type)
            .await?;

        let state = match redis_connection
            .get_verification_state(network, account_id)
            .await?
        {
            Some(state) => state,
            None => return Ok(()),
        };

        // how this will change if we aready instanced the state?
        if state.all_done {
            info!("All challenges are done!");
            let judgement_result = register_identity(account_id, network).await?;
            info!("Judgement result: {:?}", judgement_result);
        }
        return Ok(());
    }

    /// Entry point for processing incoming emails
    /// Looks up associated accounts and delegates to handle_content_ for verification
    async fn handle_content(&self, redis_cfg: &RedisConfig) -> anyhow::Result<()> {
        let account = Account::Email(self.sender.clone());

        let mut redis_connection = RedisConnection::create_conn(redis_cfg)?;
        // <<type>|<name>>|<network>|<wallet_id>
        let search_querry = format!("{}|*", account);
        let accounts = redis_connection.search(&search_querry)?;

        if accounts.is_empty() {
            info!("No account found for {}", search_querry);
            return Ok(());
        }

        for acc_str in accounts {
            info!("Account: {}", acc_str);
            let info: Vec<&str> = acc_str.split(":").collect();
            if info.len() != 4 {
                continue;
            }

            let network = info[2];
            // let account = Account::from_str(&format!("{}|{}", info[0], info[1]))?;
            let id = info[3];
            if let Ok(wallet_id) = AccountId32::from_str(id) {
                // TODO: make the network name enum instead of str
                self.handle_content_(&mut redis_connection, &wallet_id, network)
                    .await?;
            }
        }
        Ok(())
    }
}

/// IMAP mail server connection manager that handles email verification messages
pub struct MailServer {
    session: Session<TlsStream<TcpStream>>,
    redis_cfg: RedisConfig,
    mailbox: String,
}

#[derive(Clone, Debug)]
struct MailOath {
    username: String,
    access_token: String,
}

impl MailOath {
    fn new(username: String, access_token: String) -> Self {
        Self {
            username,
            access_token,
        }
    }
}

impl imap::Authenticator for MailOath {
    type Response = String;
    fn process(&self, _: &[u8]) -> Self::Response {
        format!(
            "user={}\x01auth=Bearer {}\x01\x01",
            self.username, self.access_token
        )
    }
}

impl MailServer {
    /// Creates a new MailServer instance by establishing IMAP connection
    /// Uses TLS for secure communication and authenticates using provided credentials
    async fn new() -> anyhow::Result<Self> {
        let cfg = GLOBAL_CONFIG
            .get()
            .expect("GLOBAL_CONFIG is not initialized");

        let email_cfg = cfg.adapter.email.clone();
        info!("trying to connect..");

        let tls_connector = TlsConnector::builder()
            .build()
            .map_err(|e| anyhow!("Failed to build TLS connector: {}", e))?;

        let client = tokio::time::timeout(Duration::from_secs(10), async {
            imap::connect_starttls(
                (email_cfg.server.clone(), email_cfg.port),
                email_cfg.server.clone(),
                &tls_connector,
            )
        })
        .await
        .map_err(|_| anyhow!("Timeout while connecting to email server"))??;

        info!("Email connected!");
        //client.debug = false;
        info!("trying to login as {:?}", email_cfg.username.clone(),);

        let mut session = tokio::time::timeout(Duration::from_secs(10), async {
            client.login(email_cfg.username.clone(), email_cfg.password.clone())
        })
        .await
        .map_err(|_| anyhow!("Timeout during login"))?
        .expect("Unable to login!");

        // for debugging print last mail
        //session
        //    .select(email_cfg.mailbox.clone())
        //    .expect("Unable to select mailbox");
        //
        //let msgs = session.search("ALL")?;
        //if let Some(max_uid) = msgs.iter().max() {
        //    // If there's at least one message, we try to fetch & parse it
        //    let fetches = session.uid_fetch(format!("{}", max_uid), "RFC822")?;
        //    if let Some(msg) = fetches.get(0) {
        //        let parsed = mail_parser::MessageParser::default()
        //            .parse(msg.body().unwrap_or_default())
        //            .unwrap_or_default();
        //        let from = parsed.return_address().unwrap_or("(no sender)").to_string();
        //        let subject = parsed.subject().unwrap_or("(no subject)").to_string();
        //        info!(
        //            "Last email in mailbox => from: {}, subject: {}",
        //            from, subject
        //        );
        //    }
        //} else {
        //    info!("No messages found in mailbox.");
        //}
        
        info!("Sucessfull login to mail account {}", email_cfg.email);

        Ok(Self {
            redis_cfg: cfg.redis.clone(),
            mailbox: email_cfg.mailbox.clone(),
            session,
        })
    }

    /// Starts listening for incoming emails on the configured mailbox
    /// Spawns a background task that continuously checks for new messages
    async fn listen(mut self) -> anyhow::Result<()> {
        self.session
            .select(self.mailbox.clone())
            .expect("Unable to select mailbox");
        info!("Selected mailbox `{}`", self.mailbox);
        loop {
            if let Err(e) = self.check_mailbox().await {
                error!("Error reading mailbox: {}", e);
                return Err(anyhow!(e));
            }
        }
        Ok(())
    }

    /// Marks an email as seen and removes it from the unread queue
    async fn flag_seen(&mut self, id: u32) -> anyhow::Result<()> {
        self.session
            .uid_store(format!("{}", id), "+FLAGS (\\SEEN)")?;
        self.session.expunge()?;
        Ok(())
    }

    /// Retrieves and parses an email message by its ID
    /// Extracts sender address and message body
    async fn get_mail(&mut self, id: u32) -> anyhow::Result<Mail> {
        let mail = self.session.uid_fetch(format!("{}", id), "RFC822")?;
        let mail = mail.get(0).expect("smth went wrong uwu");
        let parsed = mail_parser::MessageParser::default()
            .parse(mail.body().unwrap_or_default())
            .unwrap_or_default();
        let address = parsed.return_address().unwrap().to_string();
        let x = parsed.body_text(0).map(|body| body.to_string());
        Ok(Mail::new(address, x))
    }

    /// Polls mailbox for new unread messages and processes them
    /// Uses IMAP IDLE for efficient notification of new messages
    async fn check_mailbox(&mut self) -> anyhow::Result<()> {
        let idle_handle = self.session.idle()?;
        info!("Waiting for incoming mails...");
        match idle_handle.wait() {
            Ok(()) => {
                info!("Recived a mail!");
                let mail_id = self.session.search("UNSEEN")?;
                for id in mail_id {
                    let mail = self.get_mail(id).await?;
                    self.flag_seen(id).await?;
                    info!("\nEmail Message\nSender: {}\nMessage: {}\nRaw Mail: {:#?}", mail.sender, mail.body.as_deref().unwrap_or("(no content)"), mail);
                    mail.handle_content(&self.redis_cfg).await?;
                }
                return Ok(());
            }
            Err(e) => return Err(anyhow!("Error waiting for mail: {}", e)),
        }
    }
}

pub async fn watch_mailserver() -> anyhow::Result<()> {
    MailServer::new().await?.listen().await
}
