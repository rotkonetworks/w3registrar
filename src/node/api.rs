#![allow(dead_code)]
#![allow(unused_imports)]

pub use subxt::utils::AccountId32 as AccountId;

pub type RegistrarIndex = u32;

pub type Deposit = u128;

#[derive(
    ::subxt::ext::subxt_core::ext::codec::Decode,
    ::subxt::ext::subxt_core::ext::codec::Encode,
    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
    Debug,
)]
#[codec(crate = :: subxt :: ext :: subxt_core :: ext :: codec)]
#[decode_as_type(
    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
)]
#[encode_as_type(
    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
)]
pub struct BoundedVec<T>(pub Vec<T>);

#[derive(
    ::subxt::ext::subxt_core::ext::codec::Decode,
    ::subxt::ext::subxt_core::ext::codec::Encode,
    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
    Debug,
)]
#[codec(crate = :: subxt :: ext :: subxt_core :: ext :: codec)]
#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
pub enum RuntimeEvent {
    #[codec(index = 50)]
    Identity(IdentityEvent),
}

#[derive(
    ::subxt::ext::subxt_core::ext::codec::Decode,
    ::subxt::ext::subxt_core::ext::codec::Encode,
    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
    Debug,
)]
#[codec(crate = :: subxt :: ext :: subxt_core :: ext :: codec)]
#[decode_as_type(
    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
)]
#[encode_as_type(
    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
)]
pub enum IdentityEvent {
    #[codec(index = 0)]
    IdentitySet {
        who: AccountId,
    },
    #[codec(index = 1)]
    IdentityCleared {
        who: AccountId,
        deposit: Deposit,
    },
    #[codec(index = 2)]
    IdentityKilled {
        who: AccountId,
        deposit: Deposit,
    },
    #[codec(index = 3)]
    JudgementRequested {
        who: AccountId,
        registrar_index: RegistrarIndex,
    },
    #[codec(index = 4)]
    JudgementUnrequested {
        who: AccountId,
        registrar_index: RegistrarIndex,
    },
    #[codec(index = 5)]
    JudgementGiven {
        target: AccountId,
        registrar_index: RegistrarIndex,
    },
}

#[derive(
    ::subxt::ext::subxt_core::ext::codec::Decode,
    ::subxt::ext::subxt_core::ext::codec::Encode,
    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
    Debug,
)]
#[codec(crate = :: subxt :: ext :: subxt_core :: ext :: codec)]
#[decode_as_type(
    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
)]
#[encode_as_type(
    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
)]
pub struct Registration {
    pub judgements: BoundedVec<(u32, Judgement)>,
    pub deposit: Deposit,
    pub info: IdentityInfo,
}

#[derive(
    ::subxt::ext::subxt_core::ext::codec::Decode,
    ::subxt::ext::subxt_core::ext::codec::Encode,
    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
    Debug,
)]
#[codec(crate = :: subxt :: ext :: subxt_core :: ext :: codec)]
#[decode_as_type(
    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
)]
#[encode_as_type(
    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
)]
pub enum Judgement {
    #[codec(index = 0)]
    Unknown,
    #[codec(index = 1)]
    FeePaid(u128),
    #[codec(index = 2)]
    Reasonable,
    #[codec(index = 3)]
    KnownGood,
    #[codec(index = 4)]
    OutOfDate,
    #[codec(index = 5)]
    LowQuality,
    #[codec(index = 6)]
    Erroneous,
}

#[derive(
    ::subxt::ext::subxt_core::ext::codec::Decode,
    ::subxt::ext::subxt_core::ext::codec::Encode,
    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
    Debug,
)]
#[codec(crate = :: subxt :: ext :: subxt_core :: ext :: codec)]
#[decode_as_type(
    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
)]
#[encode_as_type(
    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
)]
pub struct IdentityInfo {
    pub display: IdentityData,
    pub legal: IdentityData,
    pub web: IdentityData,
    pub matrix: IdentityData,
    pub email: IdentityData,
    pub pgp_fingerprint: Option<[u8; 20usize]>,
    pub image: IdentityData,
    pub twitter: IdentityData,
    pub github: IdentityData,
    pub discord: IdentityData,
}

#[derive(
    ::subxt::ext::subxt_core::ext::codec::Decode,
    ::subxt::ext::subxt_core::ext::codec::Encode,
    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
    Debug,
)]
#[codec(crate = :: subxt :: ext :: subxt_core :: ext :: codec)]
#[decode_as_type(
    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
)]
#[encode_as_type(
    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
)]
pub enum IdentityData {
    #[codec(index = 0)]
    None,
    #[codec(index = 1)]
    Raw0([u8; 0usize]),
    #[codec(index = 2)]
    Raw1([u8; 1usize]),
    #[codec(index = 3)]
    Raw2([u8; 2usize]),
    #[codec(index = 4)]
    Raw3([u8; 3usize]),
    #[codec(index = 5)]
    Raw4([u8; 4usize]),
    #[codec(index = 6)]
    Raw5([u8; 5usize]),
    #[codec(index = 7)]
    Raw6([u8; 6usize]),
    #[codec(index = 8)]
    Raw7([u8; 7usize]),
    #[codec(index = 9)]
    Raw8([u8; 8usize]),
    #[codec(index = 10)]
    Raw9([u8; 9usize]),
    #[codec(index = 11)]
    Raw10([u8; 10usize]),
    #[codec(index = 12)]
    Raw11([u8; 11usize]),
    #[codec(index = 13)]
    Raw12([u8; 12usize]),
    #[codec(index = 14)]
    Raw13([u8; 13usize]),
    #[codec(index = 15)]
    Raw14([u8; 14usize]),
    #[codec(index = 16)]
    Raw15([u8; 15usize]),
    #[codec(index = 17)]
    Raw16([u8; 16usize]),
    #[codec(index = 18)]
    Raw17([u8; 17usize]),
    #[codec(index = 19)]
    Raw18([u8; 18usize]),
    #[codec(index = 20)]
    Raw19([u8; 19usize]),
    #[codec(index = 21)]
    Raw20([u8; 20usize]),
    #[codec(index = 22)]
    Raw21([u8; 21usize]),
    #[codec(index = 23)]
    Raw22([u8; 22usize]),
    #[codec(index = 24)]
    Raw23([u8; 23usize]),
    #[codec(index = 25)]
    Raw24([u8; 24usize]),
    #[codec(index = 26)]
    Raw25([u8; 25usize]),
    #[codec(index = 27)]
    Raw26([u8; 26usize]),
    #[codec(index = 28)]
    Raw27([u8; 27usize]),
    #[codec(index = 29)]
    Raw28([u8; 28usize]),
    #[codec(index = 30)]
    Raw29([u8; 29usize]),
    #[codec(index = 31)]
    Raw30([u8; 30usize]),
    #[codec(index = 32)]
    Raw31([u8; 31usize]),
    #[codec(index = 33)]
    Raw32([u8; 32usize]),
    #[codec(index = 34)]
    BlakeTwo256([u8; 32usize]),
    #[codec(index = 35)]
    Sha256([u8; 32usize]),
    #[codec(index = 36)]
    Keccak256([u8; 32usize]),
    #[codec(index = 37)]
    ShaThree256([u8; 32usize]),
}

//------------------------------------------------------------------------------

pub type IdentityOf = (Registration, Option<BoundedVec<u8>>);

use subxt::utils::Yes;
use subxt::storage::{StaticAddress, StaticStorageKey};

use std::borrow::Borrow;

pub fn identity_of(
    _0: impl Borrow<AccountId>,
) -> StaticAddress<StaticStorageKey<AccountId>,
    IdentityOf,
    Yes,
    (),
    (),
> {
    StaticAddress::new_static(
        "Identity",
        "IdentityOf",
        StaticStorageKey::new(_0.borrow()),
        [
            150u8, 8u8, 52u8, 88u8, 246u8, 82u8, 229u8, 62u8, 172u8, 30u8, 102u8,
            182u8, 49u8, 76u8, 106u8, 226u8, 159u8, 217u8, 16u8, 1u8, 8u8, 216u8,
            84u8, 165u8, 172u8, 100u8, 113u8, 137u8, 181u8, 6u8, 201u8, 245u8,
        ],
    )
}

//------------------------------------------------------------------------------

pub type Target = subxt::utils::MultiAddress<AccountId, ()>;

pub type Identity = subxt::ext::subxt_core::utils::H256;

use subxt::ext::subxt_core::tx::payload::StaticPayload;

#[derive(
    ::subxt::ext::subxt_core::ext::codec::Decode,
    ::subxt::ext::subxt_core::ext::codec::Encode,
    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
    Debug,
)]
#[codec(crate = :: subxt :: ext :: subxt_core :: ext :: codec)]
#[decode_as_type(
    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
)]
#[encode_as_type(
    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
)]
pub struct ProvideJudgement {
    #[codec(compact)]
    pub reg_index: RegistrarIndex,
    pub target: Target,
    pub judgement: Judgement,
    pub identity: Identity,
}

pub fn provide_judgement(
    reg_index: RegistrarIndex,
    target: Target,
    judgement: Judgement,
    identity: Identity,
) -> StaticPayload<ProvideJudgement>
{
    StaticPayload::new_static(
        "Identity",
        "provide_judgement",
        ProvideJudgement {
            reg_index,
            target,
            judgement,
            identity,
        },
        [
            145u8, 188u8, 61u8, 236u8, 183u8, 49u8, 49u8, 149u8, 240u8, 184u8,
            202u8, 75u8, 69u8, 0u8, 95u8, 103u8, 132u8, 24u8, 107u8, 221u8, 236u8,
            75u8, 231u8, 125u8, 39u8, 189u8, 45u8, 202u8, 116u8, 123u8, 236u8,
            96u8,
        ],
    )
}



