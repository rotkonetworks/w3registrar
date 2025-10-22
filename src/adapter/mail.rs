// TODO: remove unused things
#![allow(dead_code)]

use anyhow::anyhow;
use jmap_client::client::{Client, Credentials};
use jmap_client::email::{EmailAddress, EmailBodyPart, Property};
use jmap_client::email_submission::Address;
use jmap_client::event_source::Changes;
use jmap_client::push_subscription::PushSubscription;
use jmap_client::TypeState;
use tokio_stream::StreamExt;
use tracing::{error, info, instrument};
use uuid::Uuid;

use crate::{
    adapter::Adapter,
    api::{Account, Network},
    config::{EmailConfig, GLOBAL_CONFIG},
    redis::RedisConnection,
};
use std::str::FromStr;
use subxt::utils::AccountId32;

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
    id: Uuid,
    config: EmailConfig,
    mailbox_id: Option<String>,
    identity_id: Option<String>,
    sent_mailbox_id: Option<String>,
}

impl Default for JmapClient {
    fn default() -> Self {
        todo!()
    }
}

impl JmapClient {
    pub async fn push_subscription_verify(
        &self,
        id: &str,
        verification_code: impl Into<String>,
    ) -> jmap_client::Result<Option<PushSubscription>> {
        self.client
            .push_subscription_verify(id, verification_code)
            .await
    }

    pub async fn new(config: &EmailConfig) -> anyhow::Result<Self> {
        let credentials = Credentials::basic(&config.username, &config.password);

        let client = Client::new()
            .credentials(credentials)
            .follow_redirects(&config.redirects)
            .connect(&config.server)
            .await?;

        let id = uuid::Uuid::new_v4();

        let jmap_client = Self {
            client,
            id,
            config: config.clone(),
            mailbox_id: None,
            identity_id: None,
            sent_mailbox_id: None,
        };

        Ok(jmap_client)
    }

    pub async fn send_challenge_email(
        &self,
        to_email: &str,
        challenge_token: &str,
        network: &Network,
        account_id: &AccountId32,
    ) -> anyhow::Result<()> {
        let identity_id = self
            .identity_id
            .as_ref()
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

        let create_response = self
            .client
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

        info!(
            "Sent challenge email to {} for {}/{}",
            to_email, network, account_id
        );

        Ok(())
    }

    async fn fetch_email(&self, email_id: &str) -> anyhow::Result<JmapMail> {
        let email = self
            .client
            .email_get(email_id, [Property::From, Property::Preview].into())
            .await?
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

    pub async fn handle_mail_body(
        &mut self,
        body: &EmailBodyPart,
        sender: &EmailAddress,
    ) -> anyhow::Result<()> {
        let text = body.charset().unwrap_or_default();
        let account = Account::Email(sender.email().to_string());
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
                    Err(e) => {
                        error!("verification: failed for {}/{}: {}", account, network, e)
                    }
                }
            }
        }

        Ok(())
    }

    pub async fn handle_account_changes<'a, I>(&mut self, changes: I) -> anyhow::Result<()>
    where
        I: Iterator<Item = (&'a TypeState, &'a String)>,
    {
        for (_, state_id) in changes {
            if let Some(mail) = self
                .client
                .email_get(&state_id, Some([Property::TextBody]))
                .await
                .unwrap()
            {
                // body text
                let bodys = mail.text_body().unwrap_or_default();
                // sender address
                if let Some(sender) = mail.sender().unwrap_or_default().first() {
                    for body in bodys {
                        self.handle_mail_body(body, sender).await?;
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn handle_event(
        &mut self,
        event: Result<Changes, jmap_client::Error>,
    ) -> anyhow::Result<()> {
        let changes = event.map_err(|e| anyhow::Error::msg(format!("{e:?}")))?;
        info!(id=?changes.id(),"Change id");
        for account_id in changes.changed_accounts() {
            info!(account=?account_id, "Account has changes");

            if let Some(account_changes) = changes.changes(account_id) {
                self.handle_account_changes(account_changes).await?;
            }
        }
        Ok(())
    }

    pub async fn check_mailbox(&mut self) -> anyhow::Result<()> {
        let mut stream = self
            .client
            .event_source(
                [TypeState::Email, TypeState::EmailDelivery].into(),
                false,
                60.into(),
                None,
            )
            .await
            .unwrap();
        info!("Subscribing on jmap EventSource");

        while let Some(event) = stream.next().await {
            self.handle_event(event).await?;
        }

        Ok(())
    }
}

// Global JMAP client for sending emails
static JMAP_SENDER: tokio::sync::OnceCell<JmapClient> = tokio::sync::OnceCell::const_new();

#[instrument(name = "jmap_watcher")]
pub async fn watch_jmap_server() -> anyhow::Result<()> {
    info!("JMAP watcher started");

    let config = GLOBAL_CONFIG
        .get()
        .ok_or_else(|| anyhow!("Global config not initialized"))?;

    let mut client = JmapClient::new(&config.adapter.email).await?;
    info!("New jmap client was created");

    if let Err(e) = client.check_mailbox().await {
        error!(error = %e, "Error occurred while checking JMAP mailbox");
    }

    Ok(())
}
