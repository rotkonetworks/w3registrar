mod api;

pub use pallet_identity::pallet::Event as IdentityEvent;
pub use people_rococo_runtime::people::IdentityInfo;
pub use subxt::utils::AccountId32 as AccountId;

use anyhow::{anyhow, Result};
use async_stream::try_stream;
use tokio_stream::Stream;

pub type Client = subxt::OnlineClient<subxt::SubstrateConfig>;

pub type Registration = pallet_identity::types::Registration<u128, IdentityInfo>;

pub type Judgement = pallet_identity::types::Judgement<u128>;

pub type ProxyType = people_rococo_runtime::ProxyType;

pub struct RegistrationInfo {
    pub registration: Registration,
    pub has_paid_fee: bool,
    pub filled_fields: Vec<String>,
}

pub async fn subscribe_to_identity_events(
    client: &Client,
) -> Result<impl Stream<Item = Result<IdentityEvent>>> {
    let mut block_stream = client.blocks().subscribe_finalized().await?;

    Ok(try_stream! {
        while let Some(block_res) = block_stream.next().await {
            let block = block_res?;
            for event_res in block.events().await?.iter() {
                let event_details = event_res?;
                if let Ok(event) = event_details.as_root_event::<api::Event>() {
                    match event {
                        api::Event::Identity(e) => {
                            yield e;
                        }
                        _ => {}
                    };
                }
            }
        }
    })
}

pub async fn get_registration(client: &Client, who: &AccountId) -> Result<Registration> {
    let storage = client.storage().at_latest().await?;
    let address = api::storage().identity().identity_of(who);
    match storage.fetch(&address).await? {
        None => Err(anyhow!("No registration found for {}", who)),
        Some((reg, _)) => Ok(reg),
    }
}

pub async fn get_registration_info(client: &Client, who: &AccountId) -> Result<RegistrationInfo> {
    let storage = client.storage().at_latest().await?;
    let address = api::storage().identity().identity_of(who);
    
    match storage.fetch(&address).await? {
        None => Err(anyhow!("No registration found for {}", who)),
        Some((reg, _)) => {
            let has_paid_fee = reg.judgements.0.iter().any(|(_, j)| matches!(j, Judgement::FeePaid(_)));
            let filled_fields = get_filled_fields(&reg.info);
            
            Ok(RegistrationInfo {
                registration: reg,
                has_paid_fee,
                filled_fields,
            })
        }
    }
}

pub fn get_filled_fields(info: &IdentityInfo) -> Vec<String> {
    let mut fields = vec![];
    let check = |v: &Data, n: &str| if !v.0.is_empty() { fields.push(n.to_string()) };
    
    check(&info.display, "display");
    check(&info.legal, "legal");
    check(&info.web, "web");
    check(&info.email, "email");
    check(&info.twitter, "twitter");
    check(&info.discord, "discord");
    check(&info.matrix, "matrix");

    if info.image.is_some() { fields.push("image".into()); }
    if info.additional.iter().any(|(_, v)| !v.0.is_empty()) { fields.push("additional".into()); }

    fields
}
