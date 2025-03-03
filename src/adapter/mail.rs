#![allow(unused)]

use anyhow::anyhow;
use std::net::TcpStream;
use std::str::FromStr;
use std::time::Duration;

use crate::{
    adapter::Adapter,
    api::{Account, AccountType, RedisConnection},
    config::RedisConfig,
    node::register_identity,
};
use imap::Session;
use native_tls::{TlsConnector, TlsStream};
use subxt::utils::AccountId32;
use tracing::{error, info};

use crate::config::GLOBAL_CONFIG;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Mail {
    pub body: Option<String>,
    pub sender: String,
}

impl Adapter for Mail {}

impl Mail {
    fn new(sender: String, body: Option<String>) -> Self {
        Self { body, sender }
    }

    async fn process_email(&self, redis_cfg: &RedisConfig) -> anyhow::Result<()> {
        let account = Account::Email(self.sender.clone());
        let mut redis_connection = RedisConnection::get_connection(redis_cfg).await?;

        let search_query = format!("{}|*", account);
        let accounts = redis_connection.search(&search_query).await?;

        if accounts.is_empty() {
            info!("verification: no account found for {}", search_query);
            return Ok(());
        }

        for acc_str in accounts {
            info!("verification: processing account {}", acc_str);
            let info: Vec<&str> = acc_str.split("|").collect();
            if info.len() != 4 {
                continue;
            }

            let network = info[2];
            let id = info[3];
            if let Ok(wallet_id) = AccountId32::from_str(id) {
                if let Some(text) = self
                    .body
                    .as_ref()
                    .and_then(|b| b.lines().next())
                    .map(|l| l.trim().to_owned())
                {
                    match <Mail as Adapter>::handle_content(
                        &text,
                        &mut redis_connection,
                        network,
                        &wallet_id,
                        &account,
                    )
                    .await
                    {
                        Ok(_) => info!("verification: success for {}/{}", account, network),
                        Err(e) => error!("verification: failed for {}/{}: {}", account, network, e),
                    }
                }
            }
        }
        Ok(())
    }
}

struct MailServer {
    session: Session<TlsStream<TcpStream>>,
    redis_cfg: RedisConfig,
    mailbox: String,
}

impl MailServer {
    fn connect() -> Option<(Session<TlsStream<TcpStream>>, RedisConfig, String)> {
        let cfg = match GLOBAL_CONFIG.get() {
            Some(cfg) => cfg,
            None => {
                error!("mail: global config not initialized");
                return None;
            }
        };

        let email_cfg = cfg.adapter.email.clone();
        info!("mail: connecting to {}", email_cfg.server);

        let tls_connector = match TlsConnector::builder().build() {
            Ok(tls) => tls,
            Err(e) => {
                error!("mail: tls connector failed: {}", e);
                return None;
            }
        };

        let client = match imap::connect_starttls(
            (email_cfg.server.clone(), email_cfg.port),
            email_cfg.server.clone(),
            &tls_connector,
        ) {
            Ok(client) => client,
            Err(e) => {
                error!("mail: connection failed: {}", e);
                return None;
            }
        };

        info!("mail: login as {}", email_cfg.username);

        let session = match client.login(email_cfg.username.clone(), email_cfg.password.clone()) {
            Ok(session) => session,
            Err((e, _)) => {
                error!("mail: login failed: {:?}", e);
                return None;
            }
        };

        info!("mail: connected to {}", email_cfg.email);

        Some((session, cfg.redis.clone(), email_cfg.mailbox.clone()))
    }

    fn new() -> Option<Self> {
        let (session, redis_cfg, mailbox) = Self::connect()?;

        Some(Self {
            session,
            redis_cfg,
            mailbox,
        })
    }

    fn check_emails(&mut self) -> Option<Vec<Mail>> {
        if let Err(e) = self.session.select(&self.mailbox) {
            error!("mail: mailbox select failed: {}: {}", self.mailbox, e);
            return None;
        }

        info!("mail: checking {}", self.mailbox);

        let search_date = (chrono::Utc::now() - chrono::Duration::minutes(1))
            .format("%d-%b-%Y")
            .to_string();

        let unseen_ids = match self
            .session
            .search(format!("SENTSINCE {}", search_date))
        {
            Ok(ids) => ids,
            Err(e) => {
                error!("mail: search failed: {}", e);
                return None;
            }
        };

        if unseen_ids.is_empty() {
            return Some(Vec::new());
        }

        info!("mail: found {} new messages", unseen_ids.len());

        let mut emails = Vec::new();
        for id in unseen_ids {
            match self.fetch_mail(id) {
                Ok(mail) => {
                    info!("mail: received from {}", mail.sender);
                    emails.push(mail);

                    // mark as seen and immediately expunge to apply the change
                    if let Err(e) = self.session.uid_store(format!("{}", id), "+FLAGS (\\Seen)") {
                        error!("mail: failed to mark as seen: {}", e);
                    }
                    // force server to apply the flag changes
                    let _ = self.session.expunge();
                }
                Err(e) => {
                    error!("mail: fetch failed for {}: {}", id, e);
                }
            }
        }

        Some(emails)
    }

    fn fetch_mail(&mut self, id: u32) -> anyhow::Result<Mail> {
        let fetch_result = self.session.fetch(format!("{}", id), "RFC822")?;

        if fetch_result.is_empty() {
            return Err(anyhow!("No email found with ID {}", id));
        }

        let mail = fetch_result
            .first()
            .ok_or_else(|| anyhow!("Failed to get email {}", id))?;

        let parsed = mail_parser::MessageParser::default()
            .parse(mail.body().unwrap_or_default())
            .ok_or_else(|| anyhow!("Failed to parse email content"))?;

        let address = parsed
            .return_address()
            .ok_or_else(|| anyhow!("No sender address found"))?
            .to_string();

        let body = parsed.body_text(0).map(|body| body.to_string());

        Ok(Mail::new(address, body))
    }
}

pub async fn watch_mailserver() -> anyhow::Result<()> {
    info!("mail: watcher started");

    loop {
        let redis_and_emails = tokio::task::spawn_blocking(|| {
            let mut server = match MailServer::new() {
                Some(server) => server,
                None => {
                    error!("mail: server connection failed");
                    return None;
                }
            };

            let emails = match server.check_emails() {
                Some(emails) => emails,
                None => {
                    error!("mail: check failed");
                    return None;
                }
            };

            if emails.is_empty() {
                return None;
            }

            Some((server.redis_cfg, emails))
        })
        .await;

        match redis_and_emails {
            Ok(Some((redis_cfg, emails))) => {
                for mail in emails {
                    match mail.process_email(&redis_cfg).await {
                        Ok(_) => info!("mail: processed {}", mail.sender),
                        Err(e) => error!("mail: process failed for {}: {}", mail.sender, e),
                    }
                }
            }
            Ok(None) => {
                // no need to log when no emails found
            }
            Err(e) => {
                error!("mail: watcher task failed: {}", e);
            }
        }

        // check emails at regular intervals
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}
