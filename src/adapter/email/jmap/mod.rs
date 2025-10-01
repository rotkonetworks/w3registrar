use anyhow::anyhow;
use jmap_client::client::{Client, Credentials};
use jmap_client::mailbox::{query::Filter as MailboxFilter, Role};
use jmap_client::email::{self, Property, query::Filter as EmailFilter};
use jmap_client::email_submission::Address;
use jmap_client::core::query::Filter;
use std::time::Duration;
use tracing::{error, info, instrument};

use crate::{
    adapter::Adapter,
    api::{Account, Network},
    config::{EmailConfig, EmailProtocol, EmailMode, GLOBAL_CONFIG},
    redis::RedisConnection,
};
use subxt::utils::AccountId32;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct JmapMail {
    pub body: Option<String>,
    pub sender: String,
}

impl Adapter for JmapMail {}

impl JmapMail {
    fn new(sender: String, body: Option<String>) -> Self {
        Self { body, sender }
    }

    async fn process_email(&self) -> anyhow::Result<()> {
        let account = Account::Email(self.sender.clone());
        let mut redis_connection = RedisConnection::get_connection().await?;

        let search_query = format!("{account}|*");
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

            let network = Network::from_str(info[2])?;
            let id = info[3];
            if let Ok(wallet_id) = AccountId32::from_str(id) {
                if let Some(text) = self
                    .body
                    .as_ref()
                    .and_then(|b| b.lines().next())
                    .map(|l| l.trim().to_owned())
                {
                    match <JmapMail as Adapter>::handle_content(
                        &text,
                        &mut redis_connection,
                        &network,
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

pub struct JmapClient {
    client: Client,
    config: EmailConfig,
    mailbox_id: Option<String>,
    identity_id: Option<String>,
    sent_mailbox_id: Option<String>,
}

impl JmapClient {
    pub async fn new(config: &EmailConfig) -> anyhow::Result<Self> {
        if !matches!(config.protocol, EmailProtocol::Jmap) {
            return Err(anyhow!("Invalid protocol for JMAP client"));
        }

        let credentials = Credentials::basic(&config.username, &config.password);
        let client = Client::new()
            .credentials(credentials)
            .connect(&config.server)
            .await?;

        let mut jmap_client = Self {
            client,
            config: config.clone(),
            mailbox_id: None,
            identity_id: None,
            sent_mailbox_id: None,
        };

        // Initialize based on mode
        match config.mode {
            EmailMode::Receive | EmailMode::Bidirectional => {
                jmap_client.init_receive().await?;
            }
            _ => {}
        }

        match config.mode {
            EmailMode::Send | EmailMode::Bidirectional => {
                jmap_client.init_send().await?;
            }
            _ => {}
        }

        Ok(jmap_client)
    }

    async fn init_receive(&mut self) -> anyhow::Result<()> {
        // Find the inbox mailbox
        let mut mailbox_response = self.client
            .mailbox_query(
                MailboxFilter::name(&self.config.mailbox).into(),
                None::<Vec<_>>,
            )
            .await?;

        self.mailbox_id = if let Some(id) = mailbox_response.take_ids().pop() {
            Some(id)
        } else {
            // Try INBOX if the configured mailbox wasn't found
            let mut inbox_response = self.client
                .mailbox_query(
                    MailboxFilter::name("INBOX").into(),
                    None::<Vec<_>>,
                )
                .await?;

            inbox_response
                .take_ids()
                .pop()
                .map(|id| Some(id))
                .ok_or_else(|| anyhow!("Neither '{}' nor INBOX found", self.config.mailbox))?
        };

        Ok(())
    }

    async fn init_send(&mut self) -> anyhow::Result<()> {
        // For JMAP, we'll use a simple identity ID
        // Most JMAP servers use "1" as the default identity
        // In production, you'd enumerate identities properly
        self.identity_id = Some("1".to_string());

        // Find the Sent mailbox
        let mut sent_response = self.client
            .mailbox_query(
                MailboxFilter::role(Role::Sent).into(),
                None::<Vec<_>>,
            )
            .await?;

        self.sent_mailbox_id = sent_response.take_ids().pop();

        Ok(())
    }

    pub async fn send_challenge_email(
        &self,
        to_email: &str,
        challenge_token: &str,
        network: &Network,
        account_id: &AccountId32,
    ) -> anyhow::Result<()> {
        if !matches!(self.config.mode, EmailMode::Send | EmailMode::Bidirectional) {
            return Err(anyhow!("Email mode does not support sending"));
        }

        let identity_id = self.identity_id.as_ref()
            .ok_or_else(|| anyhow!("No identity configured for sending"))?;

        // Create email body
        let subject = format!("W3Registrar Verification for {}", network);
        let body = format!(
            "Your verification token for {} network (account {})\n\n{}\n\n\
            Please reply to this email with the token above as the first line of your response.\n\n\
            This token will expire in 24 hours.",
            network, account_id, challenge_token
        );

        // Create the email with proper headers
        let email_content = format!(
            "From: {} <{}>
To: {}
Subject: {}

{}",
            self.config.name, self.config.email, to_email, subject, body
        );

        let create_response = self.client
            .email_import(
                email_content.as_bytes().to_vec(),
                [self.sent_mailbox_id.as_ref().unwrap_or(identity_id)],
                ["$draft"].into(),
                None,
            )
            .await?;

        let email_id = create_response
            .id()
            .ok_or_else(|| anyhow!("Failed to create draft email"))?;

        // Submit the email using email_submission_create_envelope
        self.client
            .email_submission_create_envelope(
                email_id,
                identity_id,
                Address::new(&self.config.email),
                vec![Address::new(to_email)],
            )
            .await?;

        info!("Sent challenge email to {} for {}/{}", to_email, network, account_id);

        Ok(())
    }

    async fn fetch_email(&self, email_id: &str) -> anyhow::Result<JmapMail> {
        let email = self.client.email_get(
            email_id,
            [Property::From, Property::Preview].into(),
        ).await?
        .ok_or_else(|| anyhow!("Email {} not found", email_id))?;

        let sender = email
            .from()
            .and_then(|addrs| addrs.first())
            .and_then(|addr| Some(addr.email()))
            .ok_or_else(|| anyhow!("No sender found for email"))?
            .to_string();

        let body = email.preview().map(|s| s.to_string());

        Ok(JmapMail::new(sender, body))
    }

    async fn mark_as_seen(&self, email_id: &str) -> anyhow::Result<()> {
        self.client
            .email_set_keyword(email_id, "$seen", true)
            .await?;

        Ok(())
    }

    pub async fn check_mailbox(&self) -> anyhow::Result<()> {
        if !matches!(self.config.mode, EmailMode::Receive | EmailMode::Bidirectional) {
            return Err(anyhow!("Email mode does not support receiving"));
        }

        let mailbox_id = self.mailbox_id.as_ref()
            .ok_or_else(|| anyhow!("No mailbox configured for receiving"))?;

        info!("JMAP: Starting to monitor mailbox {}", mailbox_id);

        loop {
            // Query for unseen emails in the mailbox
            let mut query_response = self.client
                .email_query(
                    Filter::and([
                        EmailFilter::in_mailbox(mailbox_id),
                        EmailFilter::not_keyword("$seen"),
                    ]).into(),
                    [email::query::Comparator::from()].into(),
                )
                .await?;

            let email_ids = query_response.take_ids();

            if !email_ids.is_empty() {
                info!("JMAP: Found {} unseen emails", email_ids.len());

                for email_id in email_ids {
                    info!("JMAP: Processing email {}", email_id);

                    // Mark as seen first to avoid reprocessing
                    if let Err(e) = self.mark_as_seen(&email_id).await {
                        error!("JMAP: Failed to mark email {} as seen: {}", email_id, e);
                        continue;
                    }

                    match self.fetch_email(&email_id).await {
                        Ok(mail) => {
                            info!("JMAP: Mail from {}", mail.sender);
                            if let Err(e) = mail.process_email().await {
                                error!("JMAP: Failed to process email {}: {}", email_id, e);
                            }
                        }
                        Err(e) => {
                            error!("JMAP: Failed to fetch email {}: {}", email_id, e);
                        }
                    }
                }
            }

            // Wait before next check
            let checking_frequency = self.config.checking_frequency.unwrap_or(500);
            tokio::time::sleep(Duration::from_secs(checking_frequency)).await;
        }
    }
}

// Global JMAP client for sending emails
static JMAP_SENDER: tokio::sync::OnceCell<JmapClient> = tokio::sync::OnceCell::const_new();

pub async fn initialize_jmap_sender() -> anyhow::Result<()> {
    let config = GLOBAL_CONFIG
        .get()
        .ok_or_else(|| anyhow!("Global config not initialized"))?;

    if matches!(config.adapter.email.protocol, EmailProtocol::Jmap) &&
       matches!(config.adapter.email.mode, EmailMode::Send | EmailMode::Bidirectional) {
        let client = JmapClient::new(&config.adapter.email).await?;
        JMAP_SENDER.set(client)
            .map_err(|_| anyhow!("Failed to set JMAP sender"))?;
        info!("JMAP sender initialized");
    }

    Ok(())
}

pub async fn send_email_challenge(
    to_email: &str,
    challenge_token: &str,
    network: &Network,
    account_id: &AccountId32,
) -> anyhow::Result<()> {
    let sender = JMAP_SENDER
        .get()
        .ok_or_else(|| anyhow!("JMAP sender not initialized"))?;

    sender.send_challenge_email(to_email, challenge_token, network, account_id).await
}

#[instrument(name = "jmap_watcher")]
pub async fn watch_jmap_server() -> anyhow::Result<()> {
    info!("JMAP watcher started");

    let config = GLOBAL_CONFIG
        .get()
        .ok_or_else(|| anyhow!("Global config not initialized"))?;

    if !matches!(config.adapter.email.protocol, EmailProtocol::Jmap) {
        return Err(anyhow!("Email protocol is not JMAP"));
    }

    if !matches!(config.adapter.email.mode, EmailMode::Receive | EmailMode::Bidirectional) {
        info!("JMAP configured for send-only mode, skipping receiver");
        return Ok(());
    }

    let client = JmapClient::new(&config.adapter.email).await?;

    tokio::task::spawn(async move {
        let span = tracing::span!(tracing::Level::INFO, "jmap_watcher");
        let _guard = span.enter();
        if let Err(e) = client.check_mailbox().await {
            error!(error = %e, "Error occurred while checking JMAP mailbox");
        }
    });

    Ok(())
}