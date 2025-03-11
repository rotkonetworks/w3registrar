use anyhow::anyhow;
use std::net::TcpStream;
use std::str::FromStr;
use std::time::Duration;

use crate::{
    adapter::Adapter,
    api::{Account, RedisConnection},
    config::RedisConfig,
};
use imap::Session;
use native_tls::{TlsConnector, TlsStream};
use subxt::utils::AccountId32;

use tracing::{error, info, instrument, Level};

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

struct MailListener {
    session: Session<TlsStream<TcpStream>>,
    redis_cfg: RedisConfig,
    mailbox: String,
}

impl MailListener {
    fn connect() -> Option<(Session<TlsStream<TcpStream>>, RedisConfig, String)> {
        let cfg = match GLOBAL_CONFIG.get() {
            Some(cfg) => cfg,
            None => {
                error!("Global config not initialized");
                return None;
            }
        };

        let email_cfg = cfg.adapter.email.clone();
        info!("connecting to {}", email_cfg.server);

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

    // TODO: care about only first line
    async fn get_mail(&mut self, id: u32) -> anyhow::Result<Mail> {
        let mail = self.session.uid_fetch(format!("{}", id), "RFC822")?;
        for msg in mail.iter() {
            let parsed = mail_parser::MessageParser::default()
                .parse(msg.body().unwrap_or_default())
                .unwrap_or_default();
            let address = parsed.return_address().unwrap().to_string();
            let x = parsed.body_text(0).map(|body| body.to_string());
            return Ok(Mail::new(address, x));
        }
        return Err(anyhow!("No message found"));
    }

    async fn flag_mail_as_seen(&mut self, id: u32) -> anyhow::Result<()> {
        self.session
            .uid_store(format!("{}", id), "+FLAGS (\\SEEN)")?;
        self.session.expunge()?;
        Ok(())
    }

    async fn check_mailbox(&mut self) -> anyhow::Result<()> {
        info!("Selecting mailbox {}", self.mailbox);
        self.session.select(&self.mailbox).map_err(|e| {
            anyhow!(
                "{}:{} Unable to select mail box {} {}",
                file!(),
                line!(),
                &self.mailbox,
                e
            )
        })?;

        loop {
            info!("Starting idle session");
            let mut idle_handle = self.session.idle().map_err(|e| {
                anyhow!(
                    "{}:{} Unable to start idle IMAP session {}",
                    file!(),
                    line!(),
                    e
                )
            })?;

            let keep_alive_duration = Duration::from_secs(60);
            idle_handle.set_keepalive(keep_alive_duration);

            info!("Waiting for a mail");
            idle_handle
                .wait_keepalive()
                .map_err(|e| anyhow!("{}:{} Unable to wait for mail, {}", file!(), line!(), e))?;
            info!("Received a new mail");

            info!("Searching for unseen mails...");
            let mail_id = self.session.search("UNSEEN").map_err(|e| {
                anyhow!(
                    "{}:{} Unable search for `NEW` mails {}",
                    file!(),
                    line!(),
                    e
                )
            })?;

            for id in mail_id {
                info!("Flagging mail with ID {id} as `SEEN`");
                self.flag_mail_as_seen(id).await.map_err(|e| {
                    anyhow!(
                        "{}:{} Unable to flag mail with ID {id} as seen, Reason: {}",
                        file!(),
                        line!(),
                        e
                    )
                })?;

                let mail = match self.get_mail(id).await {
                    Ok(mail) => mail,
                    Err(e) => {
                        error!(
                            "{}:{} Unable get mail from ID {id}, Reason: {}",
                            file!(),
                            line!(),
                            e
                        );
                        continue;
                    }
                };
                info!("Mail: {:#?}", mail);

                mail.process_email(&self.redis_cfg).await.map_err(|e| {
                    anyhow!(
                        "{}:{} Unable to process mail with ID {id}, Reason: {}",
                        file!(),
                        line!(),
                        e
                    )
                })?;
            }
        }
    }
}

#[instrument(name = "mail_watcher")]
pub async fn watch_mailserver() -> anyhow::Result<()> {
    // NOTE: this duplicate exist since the guard is dropped after the end of watch_mailserver and
    // since we spawn a task that will out live this function which should inherit this context (span)
    info!("watcher started");

    let mut server = match MailListener::new() {
        Some(server) => server,
        None => {
            return Err(anyhow!("Failed to create a MailListener instance"));
        }
    };

    tokio::task::spawn(async move {
        let span = tracing::span!(Level::INFO, "mail_watcher");
        let _guard = span.enter();
        if let Err(e) = server.check_mailbox().await {
            error!(error = %e, "Error occurred while checking mailbox");
        }
    });

    Ok(())
}
