use super::types::Network;
use crate::config::{Config, RedisConfig};
use crate::redis::RedisConnection;

use futures::StreamExt;
use redis::Msg;
use std::str::FromStr;
use subxt::utils::AccountId32;
use tracing::{error, info, info_span, instrument, Span};

struct RedisSubscriber {
    redis_cfg: RedisConfig,
    span: Span,
}

impl RedisSubscriber {
    fn new(redis_cfg: RedisConfig) -> Self {
        let span = info_span!("redis_subscriber");
        Self { redis_cfg, span }
    }

    #[instrument(skip_all, parent = &self.span)]
    pub async fn listen(&mut self) -> anyhow::Result<()> {
        let mut pubsub = RedisConnection::new_pubsub().await?;
        pubsub.psubscribe("__keyspace@0__:*").await?;
        let mut stream = pubsub.on_message();
        while let Some(msg) = stream.next().await {
            info!("Redis event occured");
            if let Err(e) = self.handle_redis_message(msg).await {
                error!(error = %e, "Failed to handle Redis message");
                continue;
            }
        }
        info!("Redis subscription ended");
        Ok(())
    }

    #[instrument(skip_all, parent = &self.span)]
    pub async fn process_state_change(
        &self,
        msg: &Msg,
    ) -> anyhow::Result<Option<(AccountId32, serde_json::Value)>> {
        let mut conn = RedisConnection::get_connection().await?;
        let payload: String = msg.get_payload()?;
        let channel = msg.get_channel_name();

        info!(payload = ?payload, channel = ?channel, "Processing Redis message");

        if !matches!(payload.as_str(), "set" | "del") {
            info!("Ignoring Redis operation: {}", payload);
            return Ok(None);
        }

        let key = match channel.strip_prefix("__keyspace@0__:") {
            Some(k) => k,
            None => return Ok(None),
        };

        let (account_id, network) = match key.split_once('|') {
            Some(parts) => parts,
            None => return Ok(None),
        };

        let id = AccountId32::from_str(account_id)?;
        let network = Network::from_str(network)?;

        let account_state = conn.build_account_state_message(&network, &id, None).await?;

        Ok(Some((id, account_state)))
    }

    #[instrument(skip_all, parent = &self.span)]
    async fn handle_redis_message(&self, msg: Msg) -> anyhow::Result<()> {
        if let Ok(Some((id, value))) = self.process_state_change(&msg).await {
            info!(
                account_id = %id.to_string(),
                new_state = %value.to_string(),
                "Processed new state"
            );
        }
        Ok(())
    }
}

pub async fn spawn_redis_subscriber() -> anyhow::Result<()> {
    let redis_cfg = Config::load_static().redis.clone();
    RedisSubscriber::new(redis_cfg).listen().await
}
