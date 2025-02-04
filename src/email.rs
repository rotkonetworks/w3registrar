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
            None => {
                info!(
                    "No verification state found for {} on {}",
                    account_id, network
                );
                return Ok(());
            }
        };
        info!("Verification state: {:?}", state);

        let challenge = match state.challenges.get(&account_type) {
            Some(challenge) => challenge,
            None => {
                info!("No email challenge found in state");
                return Ok(());
            }
        };
        info!("Challenge: {:?}", challenge);

        if challenge.done {
            info!("Challenge already completed");
            return Ok(());
        }

        let token = match &challenge.token {
            Some(token) => token,
            None => {
                info!("No token found in challenge");
                return Ok(());
            }
        };
        info!("Expected token: {:?}", token);

        let body_token = self
            .body
            .as_ref()
            .and_then(|b| b.lines().next())
            .map(|l| l.trim().to_owned());

        info!("Received email body: {:?}", self.body);
        info!("Extracted token from email: {:?}", body_token);

        if body_token.ne(&Some(token.to_owned())) {
            info!(
                "Token mismatch - Expected: {:?}, Got: {:?}",
                token, body_token
            );
            return Ok(());
        }

        info!("Token matched! Updating challenge status..");

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

        if state.all_done {
            info!("All challenges are done!");
            let judgement_result = register_identity(account_id, network).await?;
            info!("Judgement result: {:?}", judgement_result);
        }
        Ok(())
    }

    /// Entry point for processing incoming emails
    /// Uses a single Redis connection for processing all accounts
    async fn handle_content(&self, redis_cfg: &RedisConfig) -> anyhow::Result<()> {
        let account = Account::Email(self.sender.clone());
        let mut redis_connection = RedisConnection::create_conn(redis_cfg)?;

        // <<type>|<name>>|<network>|<wallet_id>
        let search_query = format!("{}|*", account);
        let accounts = redis_connection.search(&search_query)?;

        if accounts.is_empty() {
            info!("No account found for {}", search_query);
            return Ok(());
        }

        for acc_str in accounts {
            info!("Account: {}", acc_str);
            let info: Vec<&str> = acc_str.split("|").collect();
            if info.len() != 4 {
                continue;
            }

            let network = info[2];
            let id = info[3];
            if let Ok(wallet_id) = AccountId32::from_str(id) {
                // reuse the same redis connection for each account
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

        info!("Checking existing emails on startup...");
        self.check_mailbox().await?;

        loop {
            if let Err(e) = self.check_mailbox().await {
                error!("Error reading mailbox: {}", e);
                return Err(anyhow!(e));
            }
        }
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
        info!("Attempting to fetch mail with UID {}", id);

        let fetched_mails = self.session.fetch(format!("{}", id), "RFC822")?;
        if fetched_mails.is_empty() {
            info!("No mail found with MSN {}, trying UID fetch", id);
            let fetched_mails = self.session.uid_fetch(format!("{}", id), "RFC822")?;
            if fetched_mails.is_empty() {
                return Err(anyhow!("No mail found with either MSN or UID {}", id));
            }
        }

        let mail = fetched_mails
            .get(0)
            .ok_or_else(|| anyhow!("Fetch succeeded but returned empty result for {}", id))?;

        let parsed = mail_parser::MessageParser::default()
            .parse(mail.body().unwrap_or_default())
            .ok_or_else(|| anyhow!("Failed to parse mail content"))?;

        let address = parsed
            .return_address()
            .ok_or_else(|| anyhow!("No return address found"))?
            .to_string();

        let body = parsed.body_text(0).map(|body| body.to_string());

        info!(
            "Successfully fetched and parsed mail {} from {}",
            id, address
        );

        Ok(Mail::new(address, body))
    }

    /// Polls mailbox for new unread messages and processes them
    /// Uses IMAP IDLE for efficient notification of new messages
    async fn check_mailbox(&mut self) -> anyhow::Result<()> {
        let idle_handle = self.session.idle()?;
        info!("Waiting for incoming mails...");

        idle_handle
            .wait()
            .map_err(|e| anyhow!("IMAP IDLE error: {}", e))?;
        info!("Received new mail notification");

        let search_date = (chrono::Utc::now() - chrono::Duration::hours(1))
            .format("%d-%b-%Y")
            .to_string();

        let recent_ids = self
            .session
            .search(&format!("SENTSINCE {}", search_date))
            .map_err(|e| anyhow!("IMAP search failed: {}", e))?;

        if recent_ids.is_empty() {
            info!("No emails in the last hour");
            return Ok(());
        }

        info!("Found {} recent emails", recent_ids.len());

        // process one email at a time
        for id in recent_ids {
            info!("Fetching email ID: {}", id);
            match self.get_mail(id).await {
                Ok(mail) => {
                    info!(
                        "Got mail from: {}, Content: {:?}",
                        mail.sender,
                        mail.body.as_deref().unwrap_or("(no content)")
                    );

                    match mail.handle_content(&self.redis_cfg).await {
                        Ok(_) => info!("Successfully processed mail from {}", mail.sender),
                        Err(e) => error!("Failed to process mail content: {}", e),
                    }
                }
                Err(e) => {
                    error!("Failed to get mail {}: {}", id, e);
                }
            }
        }

        info!("Finished processing email batch");
        Ok(())
    }

    /// a mail parser
    async fn parse_mail(&mut self, mail: &imap::types::Fetch) -> anyhow::Result<Mail> {
        let parsed = mail_parser::MessageParser::default()
            .parse(mail.body().unwrap_or_default())
            .ok_or_else(|| anyhow!("Failed to parse mail content"))?;

        let address = parsed
            .return_address()
            .ok_or_else(|| anyhow!("No return address found"))?
            .to_string();

        let body = parsed.body_text(0).map(|body| body.to_string());

        Ok(Mail::new(address, body))
    }
}

pub async fn watch_mailserver() -> anyhow::Result<()> {
    MailServer::new().await?.listen().await
}
