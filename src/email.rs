#![allow(unused)]

use std::net::TcpStream;
use std::str::FromStr;

use crate::{
    api::{Account, AccountType, RedisConnection},
    config::RedisConfig,
    node::register_identity,
};
use imap::Session;
use native_tls::{TlsConnector, TlsStream};
use subxt::utils::AccountId32;
use tracing::info;

use crate::config::GLOBAL_CONFIG;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Mail {
    pub body: Option<String>,
    pub sender: String,
}

impl Mail {
    fn new(sender: String, body: Option<String>) -> Self {
        Self { body, sender }
    }

    // TOOO: refactor this, there is a similar func in the `Matrix` module with similar logic
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

        if self.body.ne(&Some(token.to_owned())) {
            info!("Wrong token, got {:?} but expected {:?}", self.body, token);
            return Ok(());
        }

        redis_connection
            .update_challenge_status(network, account_id, &account_type)
            .await?;

        if state.all_done {
            info!("All challenges are done!");
            let cfg = GLOBAL_CONFIG.get().expect("Unable to get config");
            let network = &cfg
                .registrar
                .get_network(network)
                .expect(&format!("unable to get network from {}", network));

            register_identity(account_id, network.registrar_index, &network.endpoint).await?;
        }
        return Ok(());
    }

    async fn handle_content(&self, redis_cfg: &RedisConfig) -> anyhow::Result<()> {
        let account = Account::Email(self.sender.clone());

        let account_type = AccountType::Email;
        let mut redis_connection = RedisConnection::create_conn(redis_cfg)?;
        // <<type>:<name>>:<network>:<wallet_id>
        let search_querry = format!("{}:*", account);
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
            // let account = Account::from_str(&format!("{}:{}", info[0], info[1]))?;
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
    async fn new() -> anyhow::Result<Self> {
        let cfg = GLOBAL_CONFIG
            .get()
            .expect("GLOBAL_CONFIG is not initialized");

        let email_cfg = cfg.adapter.email.clone();
        info!("trying to connect..");
        let tls_connector = TlsConnector::builder().build().unwrap();
        let mut client = imap::connect_starttls(
            (email_cfg.name.clone(), email_cfg.port),
            email_cfg.name.clone(),
            &tls_connector,
        )
        .unwrap();
        info!("connected!");
        client.debug = false;
        info!(
            "trying to login as {:?}:{:?}",
            email_cfg.username.clone(),
            email_cfg.password.clone()
        );
        let session = client
            .login(email_cfg.username.clone(), email_cfg.password.clone())
            .expect("Unable to login!");

        Ok(Self {
            redis_cfg: cfg.redis.clone(),
            mailbox: email_cfg.mailbox.clone(),
            session,
        })
    }

    async fn listen(mut self) -> anyhow::Result<()> {
        self.session
            .select(self.mailbox.clone())
            .expect("Unable to select mailbox");

        tokio::spawn(async move {
            loop {
                self.check_mailbox().await.unwrap();
            }
        });
        Ok(())
    }

    async fn flag_seen(&mut self, id: u32) -> anyhow::Result<()> {
        self.session
            .uid_store(format!("{}", id), "+FLAGS (\\SEEN)")?;
        self.session.expunge()?;
        Ok(())
    }

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

    async fn check_mailbox(&mut self) -> anyhow::Result<()> {
        let idle_handle = self.session.idle()?;
        idle_handle.wait()?;
        let mail_id = self.session.search("UNSEEN")?;
        for id in mail_id {
            let mail = self.get_mail(id).await?;
            self.flag_seen(id).await?;
            info!("Mail: {:#?}", mail);
            mail.handle_content(&self.redis_cfg).await?;
        }
        Ok(())
    }
}

pub async fn watch_mailserver() -> anyhow::Result<()> {
    MailServer::new().await?.listen().await
}
