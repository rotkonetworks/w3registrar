#![allow(dead_code, unused_imports, non_camel_case_types)]
#![allow(clippy::all)]
#![allow(rustdoc::broken_intra_doc_links)]

#[allow(unused_imports)]
mod root_mod {
    pub use super::*;
}
pub static PALLETS: [&str; 19usize] = ["System", "ParachainSystem", "Timestamp", "ParachainInfo", "Balances", "TransactionPayment", "Authorship", "CollatorSelection", "Session", "Aura", "AuraExt", "XcmpQueue", "PolkadotXcm", "CumulusXcm", "MessageQueue", "Utility", "Multisig", "Identity", "IdentityMigrator", ];
pub static RUNTIME_APIS: [&str; 15usize] = ["AuraApi", "AuraUnincludedSegmentApi", "Core", "Metadata", "BlockBuilder", "TaggedTransactionQueue", "OffchainWorkerApi", "SessionKeys", "AccountNonceApi", "TransactionPaymentApi", "TransactionPaymentCallApi", "XcmPaymentApi", "DryRunApi", "CollectCollationInfo", "GenesisBuilder", ];
#[doc = r" The error type returned when there is a runtime issue."]
pub type DispatchError = runtime_types::sp_runtime::DispatchError;
#[doc = r" The outer event enum."]
pub type Event = runtime_types::people_rococo_runtime::RuntimeEvent;
#[doc = r" The outer extrinsic enum."]
pub type Call = runtime_types::people_rococo_runtime::RuntimeCall;
#[doc = r" The outer error enum representing the DispatchError's Module variant."]
pub type Error = runtime_types::people_rococo_runtime::RuntimeError;
pub fn constants() -> ConstantsApi { ConstantsApi }
pub fn storage() -> StorageApi { StorageApi }
pub fn tx() -> TransactionApi { TransactionApi }
pub fn apis() -> runtime_apis::RuntimeApi { runtime_apis::RuntimeApi }
pub mod runtime_apis {
    use super::root_mod;
    use super::runtime_types;
    use ::subxt::ext::subxt_core::ext::codec::Encode;
    pub struct RuntimeApi;
    impl RuntimeApi {
        pub fn aura_api(&self) -> aura_api::AuraApi { aura_api::AuraApi }
        pub fn aura_unincluded_segment_api(&self) -> aura_unincluded_segment_api::AuraUnincludedSegmentApi { aura_unincluded_segment_api::AuraUnincludedSegmentApi }
        pub fn core(&self) -> core::Core { core::Core }
        pub fn metadata(&self) -> metadata::Metadata { metadata::Metadata }
        pub fn block_builder(&self) -> block_builder::BlockBuilder { block_builder::BlockBuilder }
        pub fn tagged_transaction_queue(&self) -> tagged_transaction_queue::TaggedTransactionQueue { tagged_transaction_queue::TaggedTransactionQueue }
        pub fn offchain_worker_api(&self) -> offchain_worker_api::OffchainWorkerApi { offchain_worker_api::OffchainWorkerApi }
        pub fn session_keys(&self) -> session_keys::SessionKeys { session_keys::SessionKeys }
        pub fn account_nonce_api(&self) -> account_nonce_api::AccountNonceApi { account_nonce_api::AccountNonceApi }
        pub fn transaction_payment_api(&self) -> transaction_payment_api::TransactionPaymentApi { transaction_payment_api::TransactionPaymentApi }
        pub fn transaction_payment_call_api(&self) -> transaction_payment_call_api::TransactionPaymentCallApi { transaction_payment_call_api::TransactionPaymentCallApi }
        pub fn xcm_payment_api(&self) -> xcm_payment_api::XcmPaymentApi { xcm_payment_api::XcmPaymentApi }
        pub fn dry_run_api(&self) -> dry_run_api::DryRunApi { dry_run_api::DryRunApi }
        pub fn collect_collation_info(&self) -> collect_collation_info::CollectCollationInfo { collect_collation_info::CollectCollationInfo }
        pub fn genesis_builder(&self) -> genesis_builder::GenesisBuilder { genesis_builder::GenesisBuilder }
    }
    pub mod aura_api {
        use super::root_mod;
        use super::runtime_types;
        pub struct AuraApi;
        impl AuraApi {
            pub fn slot_duration(&self) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<types::SlotDuration, types::slot_duration::output::Output> { ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static("AuraApi", "slot_duration", types::SlotDuration {}, [233u8, 210u8, 132u8, 172u8, 100u8, 125u8, 239u8, 92u8, 114u8, 82u8, 7u8, 110u8, 179u8, 196u8, 10u8, 19u8, 211u8, 15u8, 174u8, 2u8, 91u8, 73u8, 133u8, 100u8, 205u8, 201u8, 191u8, 60u8, 163u8, 122u8, 215u8, 10u8, ]) }
            pub fn authorities(&self) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<types::Authorities, types::authorities::output::Output> { ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static("AuraApi", "authorities", types::Authorities {}, [35u8, 244u8, 24u8, 155u8, 95u8, 1u8, 221u8, 159u8, 33u8, 144u8, 213u8, 26u8, 13u8, 21u8, 136u8, 72u8, 45u8, 47u8, 15u8, 51u8, 235u8, 10u8, 6u8, 219u8, 9u8, 246u8, 50u8, 252u8, 49u8, 77u8, 64u8, 182u8, ]) }
        }
        pub mod types {
            use super::runtime_types;
            pub mod slot_duration {
                use super::runtime_types;
                pub mod output {
                    use super::runtime_types;
                    pub type Output = runtime_types::sp_consensus_slots::SlotDuration;
                }
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct SlotDuration {}
            pub mod authorities {
                use super::runtime_types;
                pub mod output {
                    use super::runtime_types;
                    pub type Output = ::subxt::ext::subxt_core::alloc::vec::Vec<runtime_types::sp_consensus_aura::sr25519::app_sr25519::Public>;
                }
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct Authorities {}
        }
    }
    pub mod aura_unincluded_segment_api {
        use super::root_mod;
        use super::runtime_types;
        pub struct AuraUnincludedSegmentApi;
        impl AuraUnincludedSegmentApi {
            pub fn can_build_upon(&self, included_hash: types::can_build_upon::IncludedHash, slot: types::can_build_upon::Slot) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<types::CanBuildUpon, types::can_build_upon::output::Output> { ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static("AuraUnincludedSegmentApi", "can_build_upon", types::CanBuildUpon { included_hash, slot }, [255u8, 59u8, 225u8, 229u8, 189u8, 250u8, 48u8, 150u8, 92u8, 226u8, 221u8, 202u8, 143u8, 145u8, 107u8, 112u8, 151u8, 146u8, 136u8, 155u8, 118u8, 174u8, 52u8, 178u8, 14u8, 89u8, 194u8, 157u8, 110u8, 103u8, 92u8, 72u8, ]) }
        }
        pub mod types {
            use super::runtime_types;
            pub mod can_build_upon {
                use super::runtime_types;
                pub type IncludedHash = ::subxt::ext::subxt_core::utils::H256;
                pub type Slot = runtime_types::sp_consensus_slots::Slot;
                pub mod output {
                    use super::runtime_types;
                    pub type Output = ::core::primitive::bool;
                }
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct CanBuildUpon {
                pub included_hash: can_build_upon::IncludedHash,
                pub slot: can_build_upon::Slot,
            }
        }
    }
    pub mod core {
        use super::root_mod;
        use super::runtime_types;
        pub struct Core;
        impl Core {
            pub fn version(&self) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<types::Version, types::version::output::Output> { ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static("Core", "version", types::Version {}, [76u8, 202u8, 17u8, 117u8, 189u8, 237u8, 239u8, 237u8, 151u8, 17u8, 125u8, 159u8, 218u8, 92u8, 57u8, 238u8, 64u8, 147u8, 40u8, 72u8, 157u8, 116u8, 37u8, 195u8, 156u8, 27u8, 123u8, 173u8, 178u8, 102u8, 136u8, 6u8, ]) }
            pub fn execute_block(&self, block: types::execute_block::Block) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<types::ExecuteBlock, types::execute_block::output::Output> { ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static("Core", "execute_block", types::ExecuteBlock { block }, [133u8, 135u8, 228u8, 65u8, 106u8, 27u8, 85u8, 158u8, 112u8, 254u8, 93u8, 26u8, 102u8, 201u8, 118u8, 216u8, 249u8, 247u8, 91u8, 74u8, 56u8, 208u8, 231u8, 115u8, 131u8, 29u8, 209u8, 6u8, 65u8, 57u8, 214u8, 125u8, ]) }
            pub fn initialize_block(&self, header: types::initialize_block::Header) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<types::InitializeBlock, types::initialize_block::output::Output> { ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static("Core", "initialize_block", types::InitializeBlock { header }, [132u8, 169u8, 113u8, 112u8, 80u8, 139u8, 113u8, 35u8, 41u8, 81u8, 36u8, 35u8, 37u8, 202u8, 29u8, 207u8, 205u8, 229u8, 145u8, 7u8, 133u8, 94u8, 25u8, 108u8, 233u8, 86u8, 234u8, 29u8, 236u8, 57u8, 56u8, 186u8, ]) }
        }
        pub mod types {
            use super::runtime_types;
            pub mod version {
                use super::runtime_types;
                pub mod output {
                    use super::runtime_types;
                    pub type Output = runtime_types::sp_version::RuntimeVersion;
                }
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct Version {}
            pub mod execute_block {
                use super::runtime_types;
                pub type Block = runtime_types::sp_runtime::generic::block::Block<runtime_types::sp_runtime::generic::header::Header<::core::primitive::u32>, ::subxt::ext::subxt_core::utils::UncheckedExtrinsic<::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()>, runtime_types::people_rococo_runtime::RuntimeCall, runtime_types::sp_runtime::MultiSignature, (runtime_types::frame_system::extensions::check_non_zero_sender::CheckNonZeroSender, runtime_types::frame_system::extensions::check_spec_version::CheckSpecVersion, runtime_types::frame_system::extensions::check_tx_version::CheckTxVersion, runtime_types::frame_system::extensions::check_genesis::CheckGenesis, runtime_types::frame_system::extensions::check_mortality::CheckMortality, runtime_types::frame_system::extensions::check_nonce::CheckNonce, runtime_types::frame_system::extensions::check_weight::CheckWeight, runtime_types::pallet_transaction_payment::ChargeTransactionPayment, runtime_types::cumulus_primitives_storage_weight_reclaim::StorageWeightReclaim,)>>;
                pub mod output {
                    use super::runtime_types;
                    pub type Output = ();
                }
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct ExecuteBlock {
                pub block: execute_block::Block,
            }
            pub mod initialize_block {
                use super::runtime_types;
                pub type Header = runtime_types::sp_runtime::generic::header::Header<::core::primitive::u32>;
                pub mod output {
                    use super::runtime_types;
                    pub type Output = runtime_types::sp_runtime::ExtrinsicInclusionMode;
                }
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct InitializeBlock {
                pub header: initialize_block::Header,
            }
        }
    }
    pub mod metadata {
        use super::root_mod;
        use super::runtime_types;
        pub struct Metadata;
        impl Metadata {
            pub fn metadata(&self) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<types::Metadata, types::metadata::output::Output> { ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static("Metadata", "metadata", types::Metadata {}, [231u8, 24u8, 67u8, 152u8, 23u8, 26u8, 188u8, 82u8, 229u8, 6u8, 185u8, 27u8, 175u8, 68u8, 83u8, 122u8, 69u8, 89u8, 185u8, 74u8, 248u8, 87u8, 217u8, 124u8, 193u8, 252u8, 199u8, 186u8, 196u8, 179u8, 179u8, 96u8, ]) }
            pub fn metadata_at_version(&self, version: types::metadata_at_version::Version) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<types::MetadataAtVersion, types::metadata_at_version::output::Output> { ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static("Metadata", "metadata_at_version", types::MetadataAtVersion { version }, [131u8, 53u8, 212u8, 234u8, 16u8, 25u8, 120u8, 252u8, 153u8, 153u8, 216u8, 28u8, 54u8, 113u8, 52u8, 236u8, 146u8, 68u8, 142u8, 8u8, 10u8, 169u8, 131u8, 142u8, 204u8, 38u8, 48u8, 108u8, 134u8, 86u8, 226u8, 61u8, ]) }
            pub fn metadata_versions(&self) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<types::MetadataVersions, types::metadata_versions::output::Output> { ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static("Metadata", "metadata_versions", types::MetadataVersions {}, [23u8, 144u8, 137u8, 91u8, 188u8, 39u8, 231u8, 208u8, 252u8, 218u8, 224u8, 176u8, 77u8, 32u8, 130u8, 212u8, 223u8, 76u8, 100u8, 190u8, 82u8, 94u8, 190u8, 8u8, 82u8, 244u8, 225u8, 179u8, 85u8, 176u8, 56u8, 16u8, ]) }
        }
        pub mod types {
            use super::runtime_types;
            pub mod metadata {
                use super::runtime_types;
                pub mod output {
                    use super::runtime_types;
                    pub type Output = runtime_types::sp_core::OpaqueMetadata;
                }
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct Metadata {}
            pub mod metadata_at_version {
                use super::runtime_types;
                pub type Version = ::core::primitive::u32;
                pub mod output {
                    use super::runtime_types;
                    pub type Output = ::core::option::Option<runtime_types::sp_core::OpaqueMetadata>;
                }
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct MetadataAtVersion {
                pub version: metadata_at_version::Version,
            }
            pub mod metadata_versions {
                use super::runtime_types;
                pub mod output {
                    use super::runtime_types;
                    pub type Output = ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u32>;
                }
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct MetadataVersions {}
        }
    }
    pub mod block_builder {
        use super::root_mod;
        use super::runtime_types;
        pub struct BlockBuilder;
        impl BlockBuilder {
            pub fn apply_extrinsic(&self, extrinsic: types::apply_extrinsic::Extrinsic) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<types::ApplyExtrinsic, types::apply_extrinsic::output::Output> { ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static("BlockBuilder", "apply_extrinsic", types::ApplyExtrinsic { extrinsic }, [72u8, 54u8, 139u8, 3u8, 118u8, 136u8, 65u8, 47u8, 6u8, 105u8, 125u8, 223u8, 160u8, 29u8, 103u8, 74u8, 79u8, 149u8, 48u8, 90u8, 237u8, 2u8, 97u8, 201u8, 123u8, 34u8, 167u8, 37u8, 187u8, 35u8, 176u8, 97u8, ]) }
            pub fn finalize_block(&self) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<types::FinalizeBlock, types::finalize_block::output::Output> { ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static("BlockBuilder", "finalize_block", types::FinalizeBlock {}, [244u8, 207u8, 24u8, 33u8, 13u8, 69u8, 9u8, 249u8, 145u8, 143u8, 122u8, 96u8, 197u8, 55u8, 64u8, 111u8, 238u8, 224u8, 34u8, 201u8, 27u8, 146u8, 232u8, 99u8, 191u8, 30u8, 114u8, 16u8, 32u8, 220u8, 58u8, 62u8, ]) }
            pub fn inherent_extrinsics(&self, inherent: types::inherent_extrinsics::Inherent) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<types::InherentExtrinsics, types::inherent_extrinsics::output::Output> { ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static("BlockBuilder", "inherent_extrinsics", types::InherentExtrinsics { inherent }, [254u8, 110u8, 245u8, 201u8, 250u8, 192u8, 27u8, 228u8, 151u8, 213u8, 166u8, 89u8, 94u8, 81u8, 189u8, 234u8, 64u8, 18u8, 245u8, 80u8, 29u8, 18u8, 140u8, 129u8, 113u8, 236u8, 135u8, 55u8, 79u8, 159u8, 175u8, 183u8, ]) }
            pub fn check_inherents(&self, block: types::check_inherents::Block, data: types::check_inherents::Data) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<types::CheckInherents, types::check_inherents::output::Output> { ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static("BlockBuilder", "check_inherents", types::CheckInherents { block, data }, [153u8, 134u8, 1u8, 215u8, 139u8, 11u8, 53u8, 51u8, 210u8, 175u8, 197u8, 28u8, 38u8, 209u8, 175u8, 247u8, 142u8, 157u8, 50u8, 151u8, 164u8, 191u8, 181u8, 118u8, 80u8, 97u8, 160u8, 248u8, 110u8, 217u8, 181u8, 234u8, ]) }
        }
        pub mod types {
            use super::runtime_types;
            pub mod apply_extrinsic {
                use super::runtime_types;
                pub type Extrinsic = ::subxt::ext::subxt_core::utils::UncheckedExtrinsic<::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()>, runtime_types::people_rococo_runtime::RuntimeCall, runtime_types::sp_runtime::MultiSignature, (runtime_types::frame_system::extensions::check_non_zero_sender::CheckNonZeroSender, runtime_types::frame_system::extensions::check_spec_version::CheckSpecVersion, runtime_types::frame_system::extensions::check_tx_version::CheckTxVersion, runtime_types::frame_system::extensions::check_genesis::CheckGenesis, runtime_types::frame_system::extensions::check_mortality::CheckMortality, runtime_types::frame_system::extensions::check_nonce::CheckNonce, runtime_types::frame_system::extensions::check_weight::CheckWeight, runtime_types::pallet_transaction_payment::ChargeTransactionPayment, runtime_types::cumulus_primitives_storage_weight_reclaim::StorageWeightReclaim,)>;
                pub mod output {
                    use super::runtime_types;
                    pub type Output = ::core::result::Result<::core::result::Result<(), runtime_types::sp_runtime::DispatchError>, runtime_types::sp_runtime::transaction_validity::TransactionValidityError>;
                }
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct ApplyExtrinsic {
                pub extrinsic: apply_extrinsic::Extrinsic,
            }
            pub mod finalize_block {
                use super::runtime_types;
                pub mod output {
                    use super::runtime_types;
                    pub type Output = runtime_types::sp_runtime::generic::header::Header<::core::primitive::u32>;
                }
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct FinalizeBlock {}
            pub mod inherent_extrinsics {
                use super::runtime_types;
                pub type Inherent = runtime_types::sp_inherents::InherentData;
                pub mod output {
                    use super::runtime_types;
                    pub type Output = ::subxt::ext::subxt_core::alloc::vec::Vec<::subxt::ext::subxt_core::utils::UncheckedExtrinsic<::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()>, runtime_types::people_rococo_runtime::RuntimeCall, runtime_types::sp_runtime::MultiSignature, (runtime_types::frame_system::extensions::check_non_zero_sender::CheckNonZeroSender, runtime_types::frame_system::extensions::check_spec_version::CheckSpecVersion, runtime_types::frame_system::extensions::check_tx_version::CheckTxVersion, runtime_types::frame_system::extensions::check_genesis::CheckGenesis, runtime_types::frame_system::extensions::check_mortality::CheckMortality, runtime_types::frame_system::extensions::check_nonce::CheckNonce, runtime_types::frame_system::extensions::check_weight::CheckWeight, runtime_types::pallet_transaction_payment::ChargeTransactionPayment, runtime_types::cumulus_primitives_storage_weight_reclaim::StorageWeightReclaim,)>>;
                }
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct InherentExtrinsics {
                pub inherent: inherent_extrinsics::Inherent,
            }
            pub mod check_inherents {
                use super::runtime_types;
                pub type Block = runtime_types::sp_runtime::generic::block::Block<runtime_types::sp_runtime::generic::header::Header<::core::primitive::u32>, ::subxt::ext::subxt_core::utils::UncheckedExtrinsic<::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()>, runtime_types::people_rococo_runtime::RuntimeCall, runtime_types::sp_runtime::MultiSignature, (runtime_types::frame_system::extensions::check_non_zero_sender::CheckNonZeroSender, runtime_types::frame_system::extensions::check_spec_version::CheckSpecVersion, runtime_types::frame_system::extensions::check_tx_version::CheckTxVersion, runtime_types::frame_system::extensions::check_genesis::CheckGenesis, runtime_types::frame_system::extensions::check_mortality::CheckMortality, runtime_types::frame_system::extensions::check_nonce::CheckNonce, runtime_types::frame_system::extensions::check_weight::CheckWeight, runtime_types::pallet_transaction_payment::ChargeTransactionPayment, runtime_types::cumulus_primitives_storage_weight_reclaim::StorageWeightReclaim,)>>;
                pub type Data = runtime_types::sp_inherents::InherentData;
                pub mod output {
                    use super::runtime_types;
                    pub type Output = runtime_types::sp_inherents::CheckInherentsResult;
                }
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct CheckInherents {
                pub block: check_inherents::Block,
                pub data: check_inherents::Data,
            }
        }
    }
    pub mod tagged_transaction_queue {
        use super::root_mod;
        use super::runtime_types;
        pub struct TaggedTransactionQueue;
        impl TaggedTransactionQueue {
            pub fn validate_transaction(&self, source: types::validate_transaction::Source, tx: types::validate_transaction::Tx, block_hash: types::validate_transaction::BlockHash) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<types::ValidateTransaction, types::validate_transaction::output::Output> { ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static("TaggedTransactionQueue", "validate_transaction", types::ValidateTransaction { source, tx, block_hash }, [196u8, 50u8, 90u8, 49u8, 109u8, 251u8, 200u8, 35u8, 23u8, 150u8, 140u8, 143u8, 232u8, 164u8, 133u8, 89u8, 32u8, 240u8, 115u8, 39u8, 95u8, 70u8, 162u8, 76u8, 122u8, 73u8, 151u8, 144u8, 234u8, 120u8, 100u8, 29u8, ]) }
        }
        pub mod types {
            use super::runtime_types;
            pub mod validate_transaction {
                use super::runtime_types;
                pub type Source = runtime_types::sp_runtime::transaction_validity::TransactionSource;
                pub type Tx = ::subxt::ext::subxt_core::utils::UncheckedExtrinsic<::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()>, runtime_types::people_rococo_runtime::RuntimeCall, runtime_types::sp_runtime::MultiSignature, (runtime_types::frame_system::extensions::check_non_zero_sender::CheckNonZeroSender, runtime_types::frame_system::extensions::check_spec_version::CheckSpecVersion, runtime_types::frame_system::extensions::check_tx_version::CheckTxVersion, runtime_types::frame_system::extensions::check_genesis::CheckGenesis, runtime_types::frame_system::extensions::check_mortality::CheckMortality, runtime_types::frame_system::extensions::check_nonce::CheckNonce, runtime_types::frame_system::extensions::check_weight::CheckWeight, runtime_types::pallet_transaction_payment::ChargeTransactionPayment, runtime_types::cumulus_primitives_storage_weight_reclaim::StorageWeightReclaim,)>;
                pub type BlockHash = ::subxt::ext::subxt_core::utils::H256;
                pub mod output {
                    use super::runtime_types;
                    pub type Output = ::core::result::Result<runtime_types::sp_runtime::transaction_validity::ValidTransaction, runtime_types::sp_runtime::transaction_validity::TransactionValidityError>;
                }
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct ValidateTransaction {
                pub source: validate_transaction::Source,
                pub tx: validate_transaction::Tx,
                pub block_hash: validate_transaction::BlockHash,
            }
        }
    }
    pub mod offchain_worker_api {
        use super::root_mod;
        use super::runtime_types;
        pub struct OffchainWorkerApi;
        impl OffchainWorkerApi { pub fn offchain_worker(&self, header: types::offchain_worker::Header) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<types::OffchainWorker, types::offchain_worker::output::Output> { ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static("OffchainWorkerApi", "offchain_worker", types::OffchainWorker { header }, [10u8, 135u8, 19u8, 153u8, 33u8, 216u8, 18u8, 242u8, 33u8, 140u8, 4u8, 223u8, 200u8, 130u8, 103u8, 118u8, 137u8, 24u8, 19u8, 127u8, 161u8, 29u8, 184u8, 111u8, 222u8, 111u8, 253u8, 73u8, 45u8, 31u8, 79u8, 60u8, ]) } }
        pub mod types {
            use super::runtime_types;
            pub mod offchain_worker {
                use super::runtime_types;
                pub type Header = runtime_types::sp_runtime::generic::header::Header<::core::primitive::u32>;
                pub mod output {
                    use super::runtime_types;
                    pub type Output = ();
                }
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct OffchainWorker {
                pub header: offchain_worker::Header,
            }
        }
    }
    pub mod session_keys {
        use super::root_mod;
        use super::runtime_types;
        pub struct SessionKeys;
        impl SessionKeys {
            pub fn generate_session_keys(&self, seed: types::generate_session_keys::Seed) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<types::GenerateSessionKeys, types::generate_session_keys::output::Output> { ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static("SessionKeys", "generate_session_keys", types::GenerateSessionKeys { seed }, [96u8, 171u8, 164u8, 166u8, 175u8, 102u8, 101u8, 47u8, 133u8, 95u8, 102u8, 202u8, 83u8, 26u8, 238u8, 47u8, 126u8, 132u8, 22u8, 11u8, 33u8, 190u8, 175u8, 94u8, 58u8, 245u8, 46u8, 80u8, 195u8, 184u8, 107u8, 65u8, ]) }
            pub fn decode_session_keys(&self, encoded: types::decode_session_keys::Encoded) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<types::DecodeSessionKeys, types::decode_session_keys::output::Output> { ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static("SessionKeys", "decode_session_keys", types::DecodeSessionKeys { encoded }, [57u8, 242u8, 18u8, 51u8, 132u8, 110u8, 238u8, 255u8, 39u8, 194u8, 8u8, 54u8, 198u8, 178u8, 75u8, 151u8, 148u8, 176u8, 144u8, 197u8, 87u8, 29u8, 179u8, 235u8, 176u8, 78u8, 252u8, 103u8, 72u8, 203u8, 151u8, 248u8, ]) }
        }
        pub mod types {
            use super::runtime_types;
            pub mod generate_session_keys {
                use super::runtime_types;
                pub type Seed = ::core::option::Option<::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>>;
                pub mod output {
                    use super::runtime_types;
                    pub type Output = ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>;
                }
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct GenerateSessionKeys {
                pub seed: generate_session_keys::Seed,
            }
            pub mod decode_session_keys {
                use super::runtime_types;
                pub type Encoded = ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>;
                pub mod output {
                    use super::runtime_types;
                    pub type Output = ::core::option::Option<::subxt::ext::subxt_core::alloc::vec::Vec<(::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>, runtime_types::sp_core::crypto::KeyTypeId,)>>;
                }
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct DecodeSessionKeys {
                pub encoded: decode_session_keys::Encoded,
            }
        }
    }
    pub mod account_nonce_api {
        use super::root_mod;
        use super::runtime_types;
        pub struct AccountNonceApi;
        impl AccountNonceApi { pub fn account_nonce(&self, account: types::account_nonce::Account) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<types::AccountNonce, types::account_nonce::output::Output> { ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static("AccountNonceApi", "account_nonce", types::AccountNonce { account }, [231u8, 82u8, 7u8, 227u8, 131u8, 2u8, 215u8, 252u8, 173u8, 82u8, 11u8, 103u8, 200u8, 25u8, 114u8, 116u8, 79u8, 229u8, 152u8, 150u8, 236u8, 37u8, 101u8, 26u8, 220u8, 146u8, 182u8, 101u8, 73u8, 55u8, 191u8, 171u8, ]) } }
        pub mod types {
            use super::runtime_types;
            pub mod account_nonce {
                use super::runtime_types;
                pub type Account = ::subxt::ext::subxt_core::utils::AccountId32;
                pub mod output {
                    use super::runtime_types;
                    pub type Output = ::core::primitive::u32;
                }
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct AccountNonce {
                pub account: account_nonce::Account,
            }
        }
    }
    pub mod transaction_payment_api {
        use super::root_mod;
        use super::runtime_types;
        pub struct TransactionPaymentApi;
        impl TransactionPaymentApi {
            pub fn query_info(&self, uxt: types::query_info::Uxt, len: types::query_info::Len) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<types::QueryInfo, types::query_info::output::Output> { ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static("TransactionPaymentApi", "query_info", types::QueryInfo { uxt, len }, [56u8, 30u8, 174u8, 34u8, 202u8, 24u8, 177u8, 189u8, 145u8, 36u8, 1u8, 156u8, 98u8, 209u8, 178u8, 49u8, 198u8, 23u8, 150u8, 173u8, 35u8, 205u8, 147u8, 129u8, 42u8, 22u8, 69u8, 3u8, 129u8, 8u8, 196u8, 139u8, ]) }
            pub fn query_fee_details(&self, uxt: types::query_fee_details::Uxt, len: types::query_fee_details::Len) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<types::QueryFeeDetails, types::query_fee_details::output::Output> { ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static("TransactionPaymentApi", "query_fee_details", types::QueryFeeDetails { uxt, len }, [117u8, 60u8, 137u8, 159u8, 237u8, 252u8, 216u8, 238u8, 232u8, 1u8, 100u8, 152u8, 26u8, 185u8, 145u8, 125u8, 68u8, 189u8, 4u8, 30u8, 125u8, 7u8, 196u8, 153u8, 235u8, 51u8, 219u8, 108u8, 185u8, 254u8, 100u8, 201u8, ]) }
            pub fn query_weight_to_fee(&self, weight: types::query_weight_to_fee::Weight) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<types::QueryWeightToFee, types::query_weight_to_fee::output::Output> { ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static("TransactionPaymentApi", "query_weight_to_fee", types::QueryWeightToFee { weight }, [206u8, 243u8, 189u8, 83u8, 231u8, 244u8, 247u8, 52u8, 126u8, 208u8, 224u8, 5u8, 163u8, 108u8, 254u8, 114u8, 214u8, 156u8, 227u8, 217u8, 211u8, 198u8, 121u8, 164u8, 110u8, 54u8, 181u8, 146u8, 50u8, 146u8, 146u8, 23u8, ]) }
            pub fn query_length_to_fee(&self, length: types::query_length_to_fee::Length) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<types::QueryLengthToFee, types::query_length_to_fee::output::Output> { ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static("TransactionPaymentApi", "query_length_to_fee", types::QueryLengthToFee { length }, [92u8, 132u8, 29u8, 119u8, 66u8, 11u8, 196u8, 224u8, 129u8, 23u8, 249u8, 12u8, 32u8, 28u8, 92u8, 50u8, 188u8, 101u8, 203u8, 229u8, 248u8, 216u8, 130u8, 150u8, 212u8, 161u8, 81u8, 254u8, 116u8, 89u8, 162u8, 48u8, ]) }
        }
        pub mod types {
            use super::runtime_types;
            pub mod query_info {
                use super::runtime_types;
                pub type Uxt = ::subxt::ext::subxt_core::utils::UncheckedExtrinsic<::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()>, runtime_types::people_rococo_runtime::RuntimeCall, runtime_types::sp_runtime::MultiSignature, (runtime_types::frame_system::extensions::check_non_zero_sender::CheckNonZeroSender, runtime_types::frame_system::extensions::check_spec_version::CheckSpecVersion, runtime_types::frame_system::extensions::check_tx_version::CheckTxVersion, runtime_types::frame_system::extensions::check_genesis::CheckGenesis, runtime_types::frame_system::extensions::check_mortality::CheckMortality, runtime_types::frame_system::extensions::check_nonce::CheckNonce, runtime_types::frame_system::extensions::check_weight::CheckWeight, runtime_types::pallet_transaction_payment::ChargeTransactionPayment, runtime_types::cumulus_primitives_storage_weight_reclaim::StorageWeightReclaim,)>;
                pub type Len = ::core::primitive::u32;
                pub mod output {
                    use super::runtime_types;
                    pub type Output = runtime_types::pallet_transaction_payment::types::RuntimeDispatchInfo<::core::primitive::u128, runtime_types::sp_weights::weight_v2::Weight>;
                }
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct QueryInfo {
                pub uxt: query_info::Uxt,
                pub len: query_info::Len,
            }
            pub mod query_fee_details {
                use super::runtime_types;
                pub type Uxt = ::subxt::ext::subxt_core::utils::UncheckedExtrinsic<::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()>, runtime_types::people_rococo_runtime::RuntimeCall, runtime_types::sp_runtime::MultiSignature, (runtime_types::frame_system::extensions::check_non_zero_sender::CheckNonZeroSender, runtime_types::frame_system::extensions::check_spec_version::CheckSpecVersion, runtime_types::frame_system::extensions::check_tx_version::CheckTxVersion, runtime_types::frame_system::extensions::check_genesis::CheckGenesis, runtime_types::frame_system::extensions::check_mortality::CheckMortality, runtime_types::frame_system::extensions::check_nonce::CheckNonce, runtime_types::frame_system::extensions::check_weight::CheckWeight, runtime_types::pallet_transaction_payment::ChargeTransactionPayment, runtime_types::cumulus_primitives_storage_weight_reclaim::StorageWeightReclaim,)>;
                pub type Len = ::core::primitive::u32;
                pub mod output {
                    use super::runtime_types;
                    pub type Output = runtime_types::pallet_transaction_payment::types::FeeDetails<::core::primitive::u128>;
                }
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct QueryFeeDetails {
                pub uxt: query_fee_details::Uxt,
                pub len: query_fee_details::Len,
            }
            pub mod query_weight_to_fee {
                use super::runtime_types;
                pub type Weight = runtime_types::sp_weights::weight_v2::Weight;
                pub mod output {
                    use super::runtime_types;
                    pub type Output = ::core::primitive::u128;
                }
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct QueryWeightToFee {
                pub weight: query_weight_to_fee::Weight,
            }
            pub mod query_length_to_fee {
                use super::runtime_types;
                pub type Length = ::core::primitive::u32;
                pub mod output {
                    use super::runtime_types;
                    pub type Output = ::core::primitive::u128;
                }
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct QueryLengthToFee {
                pub length: query_length_to_fee::Length,
            }
        }
    }
    pub mod transaction_payment_call_api {
        use super::root_mod;
        use super::runtime_types;
        pub struct TransactionPaymentCallApi;
        impl TransactionPaymentCallApi {
            pub fn query_call_info(&self, call: types::query_call_info::Call, len: types::query_call_info::Len) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<types::QueryCallInfo, types::query_call_info::output::Output> { ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static("TransactionPaymentCallApi", "query_call_info", types::QueryCallInfo { call, len }, [37u8, 247u8, 100u8, 215u8, 174u8, 24u8, 3u8, 77u8, 31u8, 57u8, 65u8, 191u8, 242u8, 169u8, 21u8, 86u8, 199u8, 81u8, 174u8, 196u8, 201u8, 246u8, 241u8, 148u8, 250u8, 2u8, 220u8, 141u8, 45u8, 42u8, 159u8, 216u8, ]) }
            pub fn query_call_fee_details(&self, call: types::query_call_fee_details::Call, len: types::query_call_fee_details::Len) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<types::QueryCallFeeDetails, types::query_call_fee_details::output::Output> { ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static("TransactionPaymentCallApi", "query_call_fee_details", types::QueryCallFeeDetails { call, len }, [230u8, 0u8, 118u8, 61u8, 233u8, 47u8, 219u8, 47u8, 4u8, 97u8, 166u8, 120u8, 39u8, 106u8, 139u8, 59u8, 209u8, 246u8, 251u8, 176u8, 66u8, 63u8, 91u8, 138u8, 201u8, 152u8, 97u8, 70u8, 130u8, 100u8, 55u8, 202u8, ]) }
            pub fn query_weight_to_fee(&self, weight: types::query_weight_to_fee::Weight) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<types::QueryWeightToFee, types::query_weight_to_fee::output::Output> { ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static("TransactionPaymentCallApi", "query_weight_to_fee", types::QueryWeightToFee { weight }, [117u8, 91u8, 94u8, 22u8, 248u8, 212u8, 15u8, 23u8, 97u8, 116u8, 64u8, 228u8, 83u8, 123u8, 87u8, 77u8, 97u8, 7u8, 98u8, 181u8, 6u8, 165u8, 114u8, 141u8, 164u8, 113u8, 126u8, 88u8, 174u8, 171u8, 224u8, 35u8, ]) }
            pub fn query_length_to_fee(&self, length: types::query_length_to_fee::Length) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<types::QueryLengthToFee, types::query_length_to_fee::output::Output> { ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static("TransactionPaymentCallApi", "query_length_to_fee", types::QueryLengthToFee { length }, [246u8, 40u8, 4u8, 160u8, 152u8, 94u8, 170u8, 53u8, 205u8, 122u8, 5u8, 69u8, 70u8, 25u8, 128u8, 156u8, 119u8, 134u8, 116u8, 147u8, 14u8, 164u8, 65u8, 140u8, 86u8, 13u8, 250u8, 218u8, 89u8, 95u8, 234u8, 228u8, ]) }
        }
        pub mod types {
            use super::runtime_types;
            pub mod query_call_info {
                use super::runtime_types;
                pub type Call = runtime_types::people_rococo_runtime::RuntimeCall;
                pub type Len = ::core::primitive::u32;
                pub mod output {
                    use super::runtime_types;
                    pub type Output = runtime_types::pallet_transaction_payment::types::RuntimeDispatchInfo<::core::primitive::u128, runtime_types::sp_weights::weight_v2::Weight>;
                }
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct QueryCallInfo {
                pub call: query_call_info::Call,
                pub len: query_call_info::Len,
            }
            pub mod query_call_fee_details {
                use super::runtime_types;
                pub type Call = runtime_types::people_rococo_runtime::RuntimeCall;
                pub type Len = ::core::primitive::u32;
                pub mod output {
                    use super::runtime_types;
                    pub type Output = runtime_types::pallet_transaction_payment::types::FeeDetails<::core::primitive::u128>;
                }
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct QueryCallFeeDetails {
                pub call: query_call_fee_details::Call,
                pub len: query_call_fee_details::Len,
            }
            pub mod query_weight_to_fee {
                use super::runtime_types;
                pub type Weight = runtime_types::sp_weights::weight_v2::Weight;
                pub mod output {
                    use super::runtime_types;
                    pub type Output = ::core::primitive::u128;
                }
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct QueryWeightToFee {
                pub weight: query_weight_to_fee::Weight,
            }
            pub mod query_length_to_fee {
                use super::runtime_types;
                pub type Length = ::core::primitive::u32;
                pub mod output {
                    use super::runtime_types;
                    pub type Output = ::core::primitive::u128;
                }
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct QueryLengthToFee {
                pub length: query_length_to_fee::Length,
            }
        }
    }
    pub mod xcm_payment_api {
        use super::root_mod;
        use super::runtime_types;
        pub struct XcmPaymentApi;
        impl XcmPaymentApi {
            pub fn query_acceptable_payment_assets(&self, xcm_version: types::query_acceptable_payment_assets::XcmVersion) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<types::QueryAcceptablePaymentAssets, types::query_acceptable_payment_assets::output::Output> { ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static("XcmPaymentApi", "query_acceptable_payment_assets", types::QueryAcceptablePaymentAssets { xcm_version }, [232u8, 67u8, 173u8, 246u8, 152u8, 193u8, 90u8, 68u8, 49u8, 200u8, 118u8, 68u8, 139u8, 225u8, 161u8, 38u8, 177u8, 158u8, 83u8, 135u8, 180u8, 97u8, 4u8, 94u8, 0u8, 232u8, 114u8, 119u8, 77u8, 5u8, 8u8, 236u8, ]) }
            pub fn query_xcm_weight(&self, message: types::query_xcm_weight::Message) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<types::QueryXcmWeight, types::query_xcm_weight::output::Output> { ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static("XcmPaymentApi", "query_xcm_weight", types::QueryXcmWeight { message }, [58u8, 118u8, 149u8, 47u8, 144u8, 85u8, 10u8, 89u8, 29u8, 123u8, 249u8, 209u8, 165u8, 160u8, 43u8, 246u8, 12u8, 106u8, 89u8, 20u8, 219u8, 133u8, 189u8, 58u8, 14u8, 136u8, 189u8, 142u8, 123u8, 145u8, 77u8, 68u8, ]) }
            pub fn query_weight_to_asset_fee(&self, weight: types::query_weight_to_asset_fee::Weight, asset: types::query_weight_to_asset_fee::Asset) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<types::QueryWeightToAssetFee, types::query_weight_to_asset_fee::output::Output> { ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static("XcmPaymentApi", "query_weight_to_asset_fee", types::QueryWeightToAssetFee { weight, asset }, [86u8, 75u8, 169u8, 75u8, 0u8, 231u8, 241u8, 122u8, 197u8, 232u8, 188u8, 66u8, 247u8, 240u8, 170u8, 39u8, 199u8, 82u8, 104u8, 16u8, 28u8, 40u8, 214u8, 232u8, 177u8, 212u8, 117u8, 16u8, 181u8, 240u8, 33u8, 126u8, ]) }
            pub fn query_delivery_fees(&self, destination: types::query_delivery_fees::Destination, message: types::query_delivery_fees::Message) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<types::QueryDeliveryFees, types::query_delivery_fees::output::Output> { ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static("XcmPaymentApi", "query_delivery_fees", types::QueryDeliveryFees { destination, message }, [248u8, 169u8, 153u8, 16u8, 58u8, 94u8, 83u8, 239u8, 80u8, 12u8, 183u8, 141u8, 169u8, 8u8, 137u8, 178u8, 241u8, 228u8, 241u8, 66u8, 89u8, 202u8, 78u8, 125u8, 240u8, 248u8, 109u8, 41u8, 189u8, 119u8, 20u8, 149u8, ]) }
        }
        pub mod types {
            use super::runtime_types;
            pub mod query_acceptable_payment_assets {
                use super::runtime_types;
                pub type XcmVersion = ::core::primitive::u32;
                pub mod output {
                    use super::runtime_types;
                    pub type Output = ::core::result::Result<::subxt::ext::subxt_core::alloc::vec::Vec<runtime_types::xcm::VersionedAssetId>, runtime_types::xcm_fee_payment_runtime_api::fees::Error>;
                }
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct QueryAcceptablePaymentAssets {
                pub xcm_version: query_acceptable_payment_assets::XcmVersion,
            }
            pub mod query_xcm_weight {
                use super::runtime_types;
                pub type Message = runtime_types::xcm::VersionedXcm;
                pub mod output {
                    use super::runtime_types;
                    pub type Output = ::core::result::Result<runtime_types::sp_weights::weight_v2::Weight, runtime_types::xcm_fee_payment_runtime_api::fees::Error>;
                }
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct QueryXcmWeight {
                pub message: query_xcm_weight::Message,
            }
            pub mod query_weight_to_asset_fee {
                use super::runtime_types;
                pub type Weight = runtime_types::sp_weights::weight_v2::Weight;
                pub type Asset = runtime_types::xcm::VersionedAssetId;
                pub mod output {
                    use super::runtime_types;
                    pub type Output = ::core::result::Result<::core::primitive::u128, runtime_types::xcm_fee_payment_runtime_api::fees::Error>;
                }
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct QueryWeightToAssetFee {
                pub weight: query_weight_to_asset_fee::Weight,
                pub asset: query_weight_to_asset_fee::Asset,
            }
            pub mod query_delivery_fees {
                use super::runtime_types;
                pub type Destination = runtime_types::xcm::VersionedLocation;
                pub type Message = runtime_types::xcm::VersionedXcm;
                pub mod output {
                    use super::runtime_types;
                    pub type Output = ::core::result::Result<runtime_types::xcm::VersionedAssets, runtime_types::xcm_fee_payment_runtime_api::fees::Error>;
                }
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct QueryDeliveryFees {
                pub destination: query_delivery_fees::Destination,
                pub message: query_delivery_fees::Message,
            }
        }
    }
    pub mod dry_run_api {
        use super::root_mod;
        use super::runtime_types;
        pub struct DryRunApi;
        impl DryRunApi {
            pub fn dry_run_call(&self, origin: types::dry_run_call::Origin, call: types::dry_run_call::Call) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<types::DryRunCall, types::dry_run_call::output::Output> { ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static("DryRunApi", "dry_run_call", types::DryRunCall { origin, call }, [107u8, 59u8, 169u8, 21u8, 191u8, 83u8, 238u8, 183u8, 51u8, 195u8, 158u8, 169u8, 93u8, 71u8, 37u8, 167u8, 105u8, 38u8, 28u8, 16u8, 17u8, 76u8, 167u8, 155u8, 213u8, 187u8, 15u8, 25u8, 17u8, 113u8, 33u8, 165u8, ]) }
            pub fn dry_run_xcm(&self, origin_location: types::dry_run_xcm::OriginLocation, xcm: types::dry_run_xcm::Xcm) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<types::DryRunXcm, types::dry_run_xcm::output::Output> { ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static("DryRunApi", "dry_run_xcm", types::DryRunXcm { origin_location, xcm }, [191u8, 18u8, 57u8, 131u8, 174u8, 242u8, 156u8, 11u8, 100u8, 25u8, 248u8, 63u8, 224u8, 197u8, 252u8, 241u8, 220u8, 227u8, 238u8, 97u8, 64u8, 243u8, 32u8, 14u8, 209u8, 249u8, 19u8, 77u8, 84u8, 82u8, 60u8, 113u8, ]) }
        }
        pub mod types {
            use super::runtime_types;
            pub mod dry_run_call {
                use super::runtime_types;
                pub type Origin = runtime_types::people_rococo_runtime::OriginCaller;
                pub type Call = runtime_types::people_rococo_runtime::RuntimeCall;
                pub mod output {
                    use super::runtime_types;
                    pub type Output = ::core::result::Result<runtime_types::xcm_fee_payment_runtime_api::dry_run::CallDryRunEffects<runtime_types::people_rococo_runtime::RuntimeEvent>, runtime_types::xcm_fee_payment_runtime_api::dry_run::Error>;
                }
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct DryRunCall {
                pub origin: dry_run_call::Origin,
                pub call: dry_run_call::Call,
            }
            pub mod dry_run_xcm {
                use super::runtime_types;
                pub type OriginLocation = runtime_types::xcm::VersionedLocation;
                pub type Xcm = runtime_types::xcm::VersionedXcm;
                pub mod output {
                    use super::runtime_types;
                    pub type Output = ::core::result::Result<runtime_types::xcm_fee_payment_runtime_api::dry_run::XcmDryRunEffects<runtime_types::people_rococo_runtime::RuntimeEvent>, runtime_types::xcm_fee_payment_runtime_api::dry_run::Error>;
                }
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct DryRunXcm {
                pub origin_location: dry_run_xcm::OriginLocation,
                pub xcm: dry_run_xcm::Xcm,
            }
        }
    }
    pub mod collect_collation_info {
        use super::root_mod;
        use super::runtime_types;
        pub struct CollectCollationInfo;
        impl CollectCollationInfo { pub fn collect_collation_info(&self, header: types::collect_collation_info::Header) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<types::CollectCollationInfo, types::collect_collation_info::output::Output> { ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static("CollectCollationInfo", "collect_collation_info", types::CollectCollationInfo { header }, [56u8, 138u8, 105u8, 91u8, 216u8, 40u8, 255u8, 98u8, 86u8, 138u8, 185u8, 155u8, 80u8, 141u8, 85u8, 48u8, 252u8, 235u8, 178u8, 231u8, 111u8, 216u8, 71u8, 20u8, 33u8, 202u8, 24u8, 215u8, 214u8, 132u8, 51u8, 166u8, ]) } }
        pub mod types {
            use super::runtime_types;
            pub mod collect_collation_info {
                use super::runtime_types;
                pub type Header = runtime_types::sp_runtime::generic::header::Header<::core::primitive::u32>;
                pub mod output {
                    use super::runtime_types;
                    pub type Output = runtime_types::cumulus_primitives_core::CollationInfo;
                }
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct CollectCollationInfo {
                pub header: collect_collation_info::Header,
            }
        }
    }
    pub mod genesis_builder {
        use super::root_mod;
        use super::runtime_types;
        pub struct GenesisBuilder;
        impl GenesisBuilder {
            pub fn build_state(&self, json: types::build_state::Json) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<types::BuildState, types::build_state::output::Output> { ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static("GenesisBuilder", "build_state", types::BuildState { json }, [203u8, 233u8, 104u8, 116u8, 111u8, 131u8, 201u8, 235u8, 117u8, 116u8, 140u8, 185u8, 93u8, 25u8, 155u8, 210u8, 56u8, 49u8, 23u8, 32u8, 253u8, 92u8, 149u8, 241u8, 85u8, 245u8, 137u8, 45u8, 209u8, 189u8, 81u8, 2u8, ]) }
            pub fn get_preset(&self, id: types::get_preset::Id) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<types::GetPreset, types::get_preset::output::Output> { ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static("GenesisBuilder", "get_preset", types::GetPreset { id }, [43u8, 153u8, 23u8, 52u8, 113u8, 161u8, 227u8, 122u8, 169u8, 135u8, 119u8, 8u8, 128u8, 33u8, 143u8, 235u8, 13u8, 173u8, 58u8, 121u8, 178u8, 223u8, 66u8, 217u8, 22u8, 244u8, 168u8, 113u8, 202u8, 186u8, 241u8, 124u8, ]) }
            pub fn preset_names(&self) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<types::PresetNames, types::preset_names::output::Output> { ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static("GenesisBuilder", "preset_names", types::PresetNames {}, [150u8, 117u8, 54u8, 129u8, 221u8, 130u8, 186u8, 71u8, 13u8, 140u8, 77u8, 180u8, 141u8, 37u8, 22u8, 219u8, 149u8, 218u8, 186u8, 206u8, 80u8, 42u8, 165u8, 41u8, 99u8, 184u8, 73u8, 37u8, 125u8, 188u8, 167u8, 122u8, ]) }
        }
        pub mod types {
            use super::runtime_types;
            pub mod build_state {
                use super::runtime_types;
                pub type Json = ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>;
                pub mod output {
                    use super::runtime_types;
                    pub type Output = ::core::result::Result<(), ::subxt::ext::subxt_core::alloc::string::String>;
                }
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct BuildState {
                pub json: build_state::Json,
            }
            pub mod get_preset {
                use super::runtime_types;
                pub type Id = ::core::option::Option<::subxt::ext::subxt_core::alloc::string::String>;
                pub mod output {
                    use super::runtime_types;
                    pub type Output = ::core::option::Option<::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>>;
                }
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct GetPreset {
                pub id: get_preset::Id,
            }
            pub mod preset_names {
                use super::runtime_types;
                pub mod output {
                    use super::runtime_types;
                    pub type Output = ::subxt::ext::subxt_core::alloc::vec::Vec<::subxt::ext::subxt_core::alloc::string::String>;
                }
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct PresetNames {}
        }
    }
}
pub fn custom() -> CustomValuesApi { CustomValuesApi }
pub struct CustomValuesApi;
impl CustomValuesApi {}
pub struct ConstantsApi;
impl ConstantsApi {
    pub fn system(&self) -> system::constants::ConstantsApi { system::constants::ConstantsApi }
    pub fn parachain_system(&self) -> parachain_system::constants::ConstantsApi { parachain_system::constants::ConstantsApi }
    pub fn timestamp(&self) -> timestamp::constants::ConstantsApi { timestamp::constants::ConstantsApi }
    pub fn balances(&self) -> balances::constants::ConstantsApi { balances::constants::ConstantsApi }
    pub fn transaction_payment(&self) -> transaction_payment::constants::ConstantsApi { transaction_payment::constants::ConstantsApi }
    pub fn aura(&self) -> aura::constants::ConstantsApi { aura::constants::ConstantsApi }
    pub fn xcmp_queue(&self) -> xcmp_queue::constants::ConstantsApi { xcmp_queue::constants::ConstantsApi }
    pub fn message_queue(&self) -> message_queue::constants::ConstantsApi { message_queue::constants::ConstantsApi }
    pub fn utility(&self) -> utility::constants::ConstantsApi { utility::constants::ConstantsApi }
    pub fn multisig(&self) -> multisig::constants::ConstantsApi { multisig::constants::ConstantsApi }
    pub fn identity(&self) -> identity::constants::ConstantsApi { identity::constants::ConstantsApi }
}
pub struct StorageApi;
impl StorageApi {
    pub fn system(&self) -> system::storage::StorageApi { system::storage::StorageApi }
    pub fn parachain_system(&self) -> parachain_system::storage::StorageApi { parachain_system::storage::StorageApi }
    pub fn timestamp(&self) -> timestamp::storage::StorageApi { timestamp::storage::StorageApi }
    pub fn parachain_info(&self) -> parachain_info::storage::StorageApi { parachain_info::storage::StorageApi }
    pub fn balances(&self) -> balances::storage::StorageApi { balances::storage::StorageApi }
    pub fn transaction_payment(&self) -> transaction_payment::storage::StorageApi { transaction_payment::storage::StorageApi }
    pub fn authorship(&self) -> authorship::storage::StorageApi { authorship::storage::StorageApi }
    pub fn collator_selection(&self) -> collator_selection::storage::StorageApi { collator_selection::storage::StorageApi }
    pub fn session(&self) -> session::storage::StorageApi { session::storage::StorageApi }
    pub fn aura(&self) -> aura::storage::StorageApi { aura::storage::StorageApi }
    pub fn aura_ext(&self) -> aura_ext::storage::StorageApi { aura_ext::storage::StorageApi }
    pub fn xcmp_queue(&self) -> xcmp_queue::storage::StorageApi { xcmp_queue::storage::StorageApi }
    pub fn polkadot_xcm(&self) -> polkadot_xcm::storage::StorageApi { polkadot_xcm::storage::StorageApi }
    pub fn message_queue(&self) -> message_queue::storage::StorageApi { message_queue::storage::StorageApi }
    pub fn multisig(&self) -> multisig::storage::StorageApi { multisig::storage::StorageApi }
    pub fn identity(&self) -> identity::storage::StorageApi { identity::storage::StorageApi }
}
pub struct TransactionApi;
impl TransactionApi {
    pub fn system(&self) -> system::calls::TransactionApi { system::calls::TransactionApi }
    pub fn parachain_system(&self) -> parachain_system::calls::TransactionApi { parachain_system::calls::TransactionApi }
    pub fn timestamp(&self) -> timestamp::calls::TransactionApi { timestamp::calls::TransactionApi }
    pub fn parachain_info(&self) -> parachain_info::calls::TransactionApi { parachain_info::calls::TransactionApi }
    pub fn balances(&self) -> balances::calls::TransactionApi { balances::calls::TransactionApi }
    pub fn collator_selection(&self) -> collator_selection::calls::TransactionApi { collator_selection::calls::TransactionApi }
    pub fn session(&self) -> session::calls::TransactionApi { session::calls::TransactionApi }
    pub fn xcmp_queue(&self) -> xcmp_queue::calls::TransactionApi { xcmp_queue::calls::TransactionApi }
    pub fn polkadot_xcm(&self) -> polkadot_xcm::calls::TransactionApi { polkadot_xcm::calls::TransactionApi }
    pub fn cumulus_xcm(&self) -> cumulus_xcm::calls::TransactionApi { cumulus_xcm::calls::TransactionApi }
    pub fn message_queue(&self) -> message_queue::calls::TransactionApi { message_queue::calls::TransactionApi }
    pub fn utility(&self) -> utility::calls::TransactionApi { utility::calls::TransactionApi }
    pub fn multisig(&self) -> multisig::calls::TransactionApi { multisig::calls::TransactionApi }
    pub fn identity(&self) -> identity::calls::TransactionApi { identity::calls::TransactionApi }
    pub fn identity_migrator(&self) -> identity_migrator::calls::TransactionApi { identity_migrator::calls::TransactionApi }
}
#[doc = r" check whether the metadata provided is aligned with this statically generated code."]
pub fn is_codegen_valid_for(metadata: &::subxt::ext::subxt_core::Metadata) -> bool {
    let runtime_metadata_hash = metadata.hasher().only_these_pallets(&PALLETS).only_these_runtime_apis(&RUNTIME_APIS).hash();
    runtime_metadata_hash == [126u8, 56u8, 216u8, 138u8, 124u8, 212u8, 55u8, 202u8, 124u8, 233u8, 192u8, 84u8, 188u8, 66u8, 22u8, 174u8, 171u8, 205u8, 214u8, 195u8, 157u8, 71u8, 16u8, 141u8, 74u8, 12u8, 129u8, 226u8, 85u8, 83u8, 106u8, 8u8, ]
}
pub mod system {
    use super::root_mod;
    use super::runtime_types;
    pub type Error = runtime_types::frame_system::pallet::Error;
    pub type Call = runtime_types::frame_system::pallet::Call;
    pub mod calls {
        use super::root_mod;
        use super::runtime_types;
        type DispatchError = runtime_types::sp_runtime::DispatchError;
        pub mod types {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct Remark {
                pub remark: remark::Remark,
            }
            pub mod remark {
                use super::runtime_types;
                pub type Remark = ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for Remark {
                const PALLET: &'static str = "System";
                const CALL: &'static str = "remark";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct SetHeapPages {
                pub pages: set_heap_pages::Pages,
            }
            pub mod set_heap_pages {
                use super::runtime_types;
                pub type Pages = ::core::primitive::u64;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for SetHeapPages {
                const PALLET: &'static str = "System";
                const CALL: &'static str = "set_heap_pages";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct SetCode {
                pub code: set_code::Code,
            }
            pub mod set_code {
                use super::runtime_types;
                pub type Code = ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for SetCode {
                const PALLET: &'static str = "System";
                const CALL: &'static str = "set_code";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct SetCodeWithoutChecks {
                pub code: set_code_without_checks::Code,
            }
            pub mod set_code_without_checks {
                use super::runtime_types;
                pub type Code = ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for SetCodeWithoutChecks {
                const PALLET: &'static str = "System";
                const CALL: &'static str = "set_code_without_checks";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct SetStorage {
                pub items: set_storage::Items,
            }
            pub mod set_storage {
                use super::runtime_types;
                pub type Items = ::subxt::ext::subxt_core::alloc::vec::Vec<(::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>, ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>,)>;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for SetStorage {
                const PALLET: &'static str = "System";
                const CALL: &'static str = "set_storage";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct KillStorage {
                pub keys: kill_storage::Keys,
            }
            pub mod kill_storage {
                use super::runtime_types;
                pub type Keys = ::subxt::ext::subxt_core::alloc::vec::Vec<::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>>;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for KillStorage {
                const PALLET: &'static str = "System";
                const CALL: &'static str = "kill_storage";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct KillPrefix {
                pub prefix: kill_prefix::Prefix,
                pub subkeys: kill_prefix::Subkeys,
            }
            pub mod kill_prefix {
                use super::runtime_types;
                pub type Prefix = ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>;
                pub type Subkeys = ::core::primitive::u32;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for KillPrefix {
                const PALLET: &'static str = "System";
                const CALL: &'static str = "kill_prefix";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct RemarkWithEvent {
                pub remark: remark_with_event::Remark,
            }
            pub mod remark_with_event {
                use super::runtime_types;
                pub type Remark = ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for RemarkWithEvent {
                const PALLET: &'static str = "System";
                const CALL: &'static str = "remark_with_event";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct AuthorizeUpgrade {
                pub code_hash: authorize_upgrade::CodeHash,
            }
            pub mod authorize_upgrade {
                use super::runtime_types;
                pub type CodeHash = ::subxt::ext::subxt_core::utils::H256;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for AuthorizeUpgrade {
                const PALLET: &'static str = "System";
                const CALL: &'static str = "authorize_upgrade";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct AuthorizeUpgradeWithoutChecks {
                pub code_hash: authorize_upgrade_without_checks::CodeHash,
            }
            pub mod authorize_upgrade_without_checks {
                use super::runtime_types;
                pub type CodeHash = ::subxt::ext::subxt_core::utils::H256;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for AuthorizeUpgradeWithoutChecks {
                const PALLET: &'static str = "System";
                const CALL: &'static str = "authorize_upgrade_without_checks";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct ApplyAuthorizedUpgrade {
                pub code: apply_authorized_upgrade::Code,
            }
            pub mod apply_authorized_upgrade {
                use super::runtime_types;
                pub type Code = ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for ApplyAuthorizedUpgrade {
                const PALLET: &'static str = "System";
                const CALL: &'static str = "apply_authorized_upgrade";
            }
        }
        pub struct TransactionApi;
        impl TransactionApi {
            pub fn remark(&self, remark: types::remark::Remark) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::Remark> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("System", "remark", types::Remark { remark }, [43u8, 126u8, 180u8, 174u8, 141u8, 48u8, 52u8, 125u8, 166u8, 212u8, 216u8, 98u8, 100u8, 24u8, 132u8, 71u8, 101u8, 64u8, 246u8, 169u8, 33u8, 250u8, 147u8, 208u8, 2u8, 40u8, 129u8, 209u8, 232u8, 207u8, 207u8, 13u8, ]) }
            pub fn set_heap_pages(&self, pages: types::set_heap_pages::Pages) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::SetHeapPages> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("System", "set_heap_pages", types::SetHeapPages { pages }, [188u8, 191u8, 99u8, 216u8, 219u8, 109u8, 141u8, 50u8, 78u8, 235u8, 215u8, 242u8, 195u8, 24u8, 111u8, 76u8, 229u8, 64u8, 99u8, 225u8, 134u8, 121u8, 81u8, 209u8, 127u8, 223u8, 98u8, 215u8, 150u8, 70u8, 57u8, 147u8, ]) }
            pub fn set_code(&self, code: types::set_code::Code) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::SetCode> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("System", "set_code", types::SetCode { code }, [233u8, 248u8, 88u8, 245u8, 28u8, 65u8, 25u8, 169u8, 35u8, 237u8, 19u8, 203u8, 136u8, 160u8, 18u8, 3u8, 20u8, 197u8, 81u8, 169u8, 244u8, 188u8, 27u8, 147u8, 147u8, 236u8, 65u8, 25u8, 3u8, 143u8, 182u8, 22u8, ]) }
            pub fn set_code_without_checks(&self, code: types::set_code_without_checks::Code) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::SetCodeWithoutChecks> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("System", "set_code_without_checks", types::SetCodeWithoutChecks { code }, [82u8, 212u8, 157u8, 44u8, 70u8, 0u8, 143u8, 15u8, 109u8, 109u8, 107u8, 157u8, 141u8, 42u8, 169u8, 11u8, 15u8, 186u8, 252u8, 138u8, 10u8, 147u8, 15u8, 178u8, 247u8, 229u8, 213u8, 98u8, 207u8, 231u8, 119u8, 115u8, ]) }
            pub fn set_storage(&self, items: types::set_storage::Items) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::SetStorage> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("System", "set_storage", types::SetStorage { items }, [141u8, 216u8, 52u8, 222u8, 223u8, 136u8, 123u8, 181u8, 19u8, 75u8, 163u8, 102u8, 229u8, 189u8, 158u8, 142u8, 95u8, 235u8, 240u8, 49u8, 150u8, 76u8, 78u8, 137u8, 126u8, 88u8, 183u8, 88u8, 231u8, 146u8, 234u8, 43u8, ]) }
            pub fn kill_storage(&self, keys: types::kill_storage::Keys) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::KillStorage> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("System", "kill_storage", types::KillStorage { keys }, [73u8, 63u8, 196u8, 36u8, 144u8, 114u8, 34u8, 213u8, 108u8, 93u8, 209u8, 234u8, 153u8, 185u8, 33u8, 91u8, 187u8, 195u8, 223u8, 130u8, 58u8, 156u8, 63u8, 47u8, 228u8, 249u8, 216u8, 139u8, 143u8, 177u8, 41u8, 35u8, ]) }
            pub fn kill_prefix(&self, prefix: types::kill_prefix::Prefix, subkeys: types::kill_prefix::Subkeys) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::KillPrefix> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("System", "kill_prefix", types::KillPrefix { prefix, subkeys }, [184u8, 57u8, 139u8, 24u8, 208u8, 87u8, 108u8, 215u8, 198u8, 189u8, 175u8, 242u8, 167u8, 215u8, 97u8, 63u8, 110u8, 166u8, 238u8, 98u8, 67u8, 236u8, 111u8, 110u8, 234u8, 81u8, 102u8, 5u8, 182u8, 5u8, 214u8, 85u8, ]) }
            pub fn remark_with_event(&self, remark: types::remark_with_event::Remark) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::RemarkWithEvent> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("System", "remark_with_event", types::RemarkWithEvent { remark }, [120u8, 120u8, 153u8, 92u8, 184u8, 85u8, 34u8, 2u8, 174u8, 206u8, 105u8, 228u8, 233u8, 130u8, 80u8, 246u8, 228u8, 59u8, 234u8, 240u8, 4u8, 49u8, 147u8, 170u8, 115u8, 91u8, 149u8, 200u8, 228u8, 181u8, 8u8, 154u8, ]) }
            pub fn authorize_upgrade(&self, code_hash: types::authorize_upgrade::CodeHash) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::AuthorizeUpgrade> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("System", "authorize_upgrade", types::AuthorizeUpgrade { code_hash }, [4u8, 14u8, 76u8, 107u8, 209u8, 129u8, 9u8, 39u8, 193u8, 17u8, 84u8, 254u8, 170u8, 214u8, 24u8, 155u8, 29u8, 184u8, 249u8, 241u8, 109u8, 58u8, 145u8, 131u8, 109u8, 63u8, 38u8, 165u8, 107u8, 215u8, 217u8, 172u8, ]) }
            pub fn authorize_upgrade_without_checks(&self, code_hash: types::authorize_upgrade_without_checks::CodeHash) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::AuthorizeUpgradeWithoutChecks> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("System", "authorize_upgrade_without_checks", types::AuthorizeUpgradeWithoutChecks { code_hash }, [126u8, 126u8, 55u8, 26u8, 47u8, 55u8, 66u8, 8u8, 167u8, 18u8, 29u8, 136u8, 146u8, 14u8, 189u8, 117u8, 16u8, 227u8, 162u8, 61u8, 149u8, 197u8, 104u8, 184u8, 185u8, 161u8, 99u8, 154u8, 80u8, 125u8, 181u8, 233u8, ]) }
            pub fn apply_authorized_upgrade(&self, code: types::apply_authorized_upgrade::Code) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::ApplyAuthorizedUpgrade> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("System", "apply_authorized_upgrade", types::ApplyAuthorizedUpgrade { code }, [232u8, 107u8, 127u8, 38u8, 230u8, 29u8, 97u8, 4u8, 160u8, 191u8, 222u8, 156u8, 245u8, 102u8, 196u8, 141u8, 44u8, 163u8, 98u8, 68u8, 125u8, 32u8, 124u8, 101u8, 108u8, 93u8, 211u8, 52u8, 0u8, 231u8, 33u8, 227u8, ]) }
        }
    }
    pub type Event = runtime_types::frame_system::pallet::Event;
    pub mod events {
        use super::runtime_types;
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct ExtrinsicSuccess {
            pub dispatch_info: extrinsic_success::DispatchInfo,
        }
        pub mod extrinsic_success {
            use super::runtime_types;
            pub type DispatchInfo = runtime_types::frame_support::dispatch::DispatchInfo;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for ExtrinsicSuccess {
            const PALLET: &'static str = "System";
            const EVENT: &'static str = "ExtrinsicSuccess";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct ExtrinsicFailed {
            pub dispatch_error: extrinsic_failed::DispatchError,
            pub dispatch_info: extrinsic_failed::DispatchInfo,
        }
        pub mod extrinsic_failed {
            use super::runtime_types;
            pub type DispatchError = runtime_types::sp_runtime::DispatchError;
            pub type DispatchInfo = runtime_types::frame_support::dispatch::DispatchInfo;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for ExtrinsicFailed {
            const PALLET: &'static str = "System";
            const EVENT: &'static str = "ExtrinsicFailed";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct CodeUpdated;
        impl ::subxt::ext::subxt_core::events::StaticEvent for CodeUpdated {
            const PALLET: &'static str = "System";
            const EVENT: &'static str = "CodeUpdated";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct NewAccount {
            pub account: new_account::Account,
        }
        pub mod new_account {
            use super::runtime_types;
            pub type Account = ::subxt::ext::subxt_core::utils::AccountId32;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for NewAccount {
            const PALLET: &'static str = "System";
            const EVENT: &'static str = "NewAccount";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct KilledAccount {
            pub account: killed_account::Account,
        }
        pub mod killed_account {
            use super::runtime_types;
            pub type Account = ::subxt::ext::subxt_core::utils::AccountId32;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for KilledAccount {
            const PALLET: &'static str = "System";
            const EVENT: &'static str = "KilledAccount";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct Remarked {
            pub sender: remarked::Sender,
            pub hash: remarked::Hash,
        }
        pub mod remarked {
            use super::runtime_types;
            pub type Sender = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type Hash = ::subxt::ext::subxt_core::utils::H256;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for Remarked {
            const PALLET: &'static str = "System";
            const EVENT: &'static str = "Remarked";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct UpgradeAuthorized {
            pub code_hash: upgrade_authorized::CodeHash,
            pub check_version: upgrade_authorized::CheckVersion,
        }
        pub mod upgrade_authorized {
            use super::runtime_types;
            pub type CodeHash = ::subxt::ext::subxt_core::utils::H256;
            pub type CheckVersion = ::core::primitive::bool;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for UpgradeAuthorized {
            const PALLET: &'static str = "System";
            const EVENT: &'static str = "UpgradeAuthorized";
        }
    }
    pub mod storage {
        use super::runtime_types;
        pub mod types {
            use super::runtime_types;
            pub mod account {
                use super::runtime_types;
                pub type Account = runtime_types::frame_system::AccountInfo<::core::primitive::u32, runtime_types::pallet_balances::types::AccountData<::core::primitive::u128>>;
                pub type Param0 = ::subxt::ext::subxt_core::utils::AccountId32;
            }
            pub mod extrinsic_count {
                use super::runtime_types;
                pub type ExtrinsicCount = ::core::primitive::u32;
            }
            pub mod inherents_applied {
                use super::runtime_types;
                pub type InherentsApplied = ::core::primitive::bool;
            }
            pub mod block_weight {
                use super::runtime_types;
                pub type BlockWeight = runtime_types::frame_support::dispatch::PerDispatchClass<runtime_types::sp_weights::weight_v2::Weight>;
            }
            pub mod all_extrinsics_len {
                use super::runtime_types;
                pub type AllExtrinsicsLen = ::core::primitive::u32;
            }
            pub mod block_hash {
                use super::runtime_types;
                pub type BlockHash = ::subxt::ext::subxt_core::utils::H256;
                pub type Param0 = ::core::primitive::u32;
            }
            pub mod extrinsic_data {
                use super::runtime_types;
                pub type ExtrinsicData = ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>;
                pub type Param0 = ::core::primitive::u32;
            }
            pub mod number {
                use super::runtime_types;
                pub type Number = ::core::primitive::u32;
            }
            pub mod parent_hash {
                use super::runtime_types;
                pub type ParentHash = ::subxt::ext::subxt_core::utils::H256;
            }
            pub mod digest {
                use super::runtime_types;
                pub type Digest = runtime_types::sp_runtime::generic::digest::Digest;
            }
            pub mod events {
                use super::runtime_types;
                pub type Events = ::subxt::ext::subxt_core::alloc::vec::Vec<runtime_types::frame_system::EventRecord<runtime_types::people_rococo_runtime::RuntimeEvent, ::subxt::ext::subxt_core::utils::H256>>;
            }
            pub mod event_count {
                use super::runtime_types;
                pub type EventCount = ::core::primitive::u32;
            }
            pub mod event_topics {
                use super::runtime_types;
                pub type EventTopics = ::subxt::ext::subxt_core::alloc::vec::Vec<(::core::primitive::u32, ::core::primitive::u32,)>;
                pub type Param0 = ::subxt::ext::subxt_core::utils::H256;
            }
            pub mod last_runtime_upgrade {
                use super::runtime_types;
                pub type LastRuntimeUpgrade = runtime_types::frame_system::LastRuntimeUpgradeInfo;
            }
            pub mod upgraded_to_u32_ref_count {
                use super::runtime_types;
                pub type UpgradedToU32RefCount = ::core::primitive::bool;
            }
            pub mod upgraded_to_triple_ref_count {
                use super::runtime_types;
                pub type UpgradedToTripleRefCount = ::core::primitive::bool;
            }
            pub mod execution_phase {
                use super::runtime_types;
                pub type ExecutionPhase = runtime_types::frame_system::Phase;
            }
            pub mod authorized_upgrade {
                use super::runtime_types;
                pub type AuthorizedUpgrade = runtime_types::frame_system::CodeUpgradeAuthorization;
            }
        }
        pub struct StorageApi;
        impl StorageApi {
            pub fn account_iter(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::account::Account, (), ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("System", "Account", (), [14u8, 233u8, 115u8, 214u8, 0u8, 109u8, 222u8, 121u8, 162u8, 65u8, 60u8, 175u8, 209u8, 79u8, 222u8, 124u8, 22u8, 235u8, 138u8, 176u8, 133u8, 124u8, 90u8, 158u8, 85u8, 45u8, 37u8, 174u8, 47u8, 79u8, 47u8, 166u8, ]) }
            pub fn account(&self, _0: impl ::core::borrow::Borrow<types::account::Param0>) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::account::Param0>, types::account::Account, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("System", "Account", ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0.borrow()), [14u8, 233u8, 115u8, 214u8, 0u8, 109u8, 222u8, 121u8, 162u8, 65u8, 60u8, 175u8, 209u8, 79u8, 222u8, 124u8, 22u8, 235u8, 138u8, 176u8, 133u8, 124u8, 90u8, 158u8, 85u8, 45u8, 37u8, 174u8, 47u8, 79u8, 47u8, 166u8, ]) }
            pub fn extrinsic_count(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::extrinsic_count::ExtrinsicCount, ::subxt::ext::subxt_core::utils::Yes, (), ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("System", "ExtrinsicCount", (), [102u8, 76u8, 236u8, 42u8, 40u8, 231u8, 33u8, 222u8, 123u8, 147u8, 153u8, 148u8, 234u8, 203u8, 181u8, 119u8, 6u8, 187u8, 177u8, 199u8, 120u8, 47u8, 137u8, 254u8, 96u8, 100u8, 165u8, 182u8, 249u8, 230u8, 159u8, 79u8, ]) }
            pub fn inherents_applied(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::inherents_applied::InherentsApplied, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("System", "InherentsApplied", (), [132u8, 249u8, 142u8, 252u8, 8u8, 103u8, 80u8, 120u8, 50u8, 6u8, 188u8, 223u8, 101u8, 55u8, 165u8, 189u8, 172u8, 249u8, 165u8, 230u8, 183u8, 109u8, 34u8, 65u8, 185u8, 150u8, 29u8, 8u8, 186u8, 129u8, 135u8, 239u8, ]) }
            pub fn block_weight(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::block_weight::BlockWeight, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("System", "BlockWeight", (), [158u8, 46u8, 228u8, 89u8, 210u8, 214u8, 84u8, 154u8, 50u8, 68u8, 63u8, 62u8, 43u8, 42u8, 99u8, 27u8, 54u8, 42u8, 146u8, 44u8, 241u8, 216u8, 229u8, 30u8, 216u8, 255u8, 165u8, 238u8, 181u8, 130u8, 36u8, 102u8, ]) }
            pub fn all_extrinsics_len(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::all_extrinsics_len::AllExtrinsicsLen, ::subxt::ext::subxt_core::utils::Yes, (), ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("System", "AllExtrinsicsLen", (), [117u8, 86u8, 61u8, 243u8, 41u8, 51u8, 102u8, 214u8, 137u8, 100u8, 243u8, 185u8, 122u8, 174u8, 187u8, 117u8, 86u8, 189u8, 63u8, 135u8, 101u8, 218u8, 203u8, 201u8, 237u8, 254u8, 128u8, 183u8, 169u8, 221u8, 242u8, 65u8, ]) }
            pub fn block_hash_iter(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::block_hash::BlockHash, (), ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("System", "BlockHash", (), [217u8, 32u8, 215u8, 253u8, 24u8, 182u8, 207u8, 178u8, 157u8, 24u8, 103u8, 100u8, 195u8, 165u8, 69u8, 152u8, 112u8, 181u8, 56u8, 192u8, 164u8, 16u8, 20u8, 222u8, 28u8, 214u8, 144u8, 142u8, 146u8, 69u8, 202u8, 118u8, ]) }
            pub fn block_hash(&self, _0: impl ::core::borrow::Borrow<types::block_hash::Param0>) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::block_hash::Param0>, types::block_hash::BlockHash, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("System", "BlockHash", ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0.borrow()), [217u8, 32u8, 215u8, 253u8, 24u8, 182u8, 207u8, 178u8, 157u8, 24u8, 103u8, 100u8, 195u8, 165u8, 69u8, 152u8, 112u8, 181u8, 56u8, 192u8, 164u8, 16u8, 20u8, 222u8, 28u8, 214u8, 144u8, 142u8, 146u8, 69u8, 202u8, 118u8, ]) }
            pub fn extrinsic_data_iter(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::extrinsic_data::ExtrinsicData, (), ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("System", "ExtrinsicData", (), [160u8, 180u8, 122u8, 18u8, 196u8, 26u8, 2u8, 37u8, 115u8, 232u8, 133u8, 220u8, 106u8, 245u8, 4u8, 129u8, 42u8, 84u8, 241u8, 45u8, 199u8, 179u8, 128u8, 61u8, 170u8, 137u8, 231u8, 156u8, 247u8, 57u8, 47u8, 38u8, ]) }
            pub fn extrinsic_data(&self, _0: impl ::core::borrow::Borrow<types::extrinsic_data::Param0>) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::extrinsic_data::Param0>, types::extrinsic_data::ExtrinsicData, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("System", "ExtrinsicData", ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0.borrow()), [160u8, 180u8, 122u8, 18u8, 196u8, 26u8, 2u8, 37u8, 115u8, 232u8, 133u8, 220u8, 106u8, 245u8, 4u8, 129u8, 42u8, 84u8, 241u8, 45u8, 199u8, 179u8, 128u8, 61u8, 170u8, 137u8, 231u8, 156u8, 247u8, 57u8, 47u8, 38u8, ]) }
            pub fn number(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::number::Number, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("System", "Number", (), [30u8, 194u8, 177u8, 90u8, 194u8, 232u8, 46u8, 180u8, 85u8, 129u8, 14u8, 9u8, 8u8, 8u8, 23u8, 95u8, 230u8, 5u8, 13u8, 105u8, 125u8, 2u8, 22u8, 200u8, 78u8, 93u8, 115u8, 28u8, 150u8, 113u8, 48u8, 53u8, ]) }
            pub fn parent_hash(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::parent_hash::ParentHash, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("System", "ParentHash", (), [26u8, 130u8, 11u8, 216u8, 155u8, 71u8, 128u8, 170u8, 30u8, 153u8, 21u8, 192u8, 62u8, 93u8, 137u8, 80u8, 120u8, 81u8, 202u8, 94u8, 248u8, 125u8, 71u8, 82u8, 141u8, 229u8, 32u8, 56u8, 73u8, 50u8, 101u8, 78u8, ]) }
            pub fn digest(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::digest::Digest, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("System", "Digest", (), [61u8, 64u8, 237u8, 91u8, 145u8, 232u8, 17u8, 254u8, 181u8, 16u8, 234u8, 91u8, 51u8, 140u8, 254u8, 131u8, 98u8, 135u8, 21u8, 37u8, 251u8, 20u8, 58u8, 92u8, 123u8, 141u8, 14u8, 227u8, 146u8, 46u8, 222u8, 117u8, ]) }
            pub fn events(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::events::Events, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("System", "Events", (), [155u8, 78u8, 68u8, 114u8, 18u8, 64u8, 51u8, 173u8, 93u8, 250u8, 177u8, 24u8, 60u8, 238u8, 88u8, 207u8, 83u8, 73u8, 122u8, 37u8, 108u8, 228u8, 38u8, 63u8, 112u8, 241u8, 116u8, 88u8, 38u8, 14u8, 218u8, 181u8, ]) }
            pub fn event_count(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::event_count::EventCount, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("System", "EventCount", (), [175u8, 24u8, 252u8, 184u8, 210u8, 167u8, 146u8, 143u8, 164u8, 80u8, 151u8, 205u8, 189u8, 189u8, 55u8, 220u8, 47u8, 101u8, 181u8, 33u8, 254u8, 131u8, 13u8, 143u8, 3u8, 244u8, 245u8, 45u8, 2u8, 210u8, 79u8, 133u8, ]) }
            pub fn event_topics_iter(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::event_topics::EventTopics, (), ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("System", "EventTopics", (), [40u8, 225u8, 14u8, 75u8, 44u8, 176u8, 76u8, 34u8, 143u8, 107u8, 69u8, 133u8, 114u8, 13u8, 172u8, 250u8, 141u8, 73u8, 12u8, 65u8, 217u8, 63u8, 120u8, 241u8, 48u8, 106u8, 143u8, 161u8, 128u8, 100u8, 166u8, 59u8, ]) }
            pub fn event_topics(&self, _0: impl ::core::borrow::Borrow<types::event_topics::Param0>) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::event_topics::Param0>, types::event_topics::EventTopics, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("System", "EventTopics", ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0.borrow()), [40u8, 225u8, 14u8, 75u8, 44u8, 176u8, 76u8, 34u8, 143u8, 107u8, 69u8, 133u8, 114u8, 13u8, 172u8, 250u8, 141u8, 73u8, 12u8, 65u8, 217u8, 63u8, 120u8, 241u8, 48u8, 106u8, 143u8, 161u8, 128u8, 100u8, 166u8, 59u8, ]) }
            pub fn last_runtime_upgrade(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::last_runtime_upgrade::LastRuntimeUpgrade, ::subxt::ext::subxt_core::utils::Yes, (), ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("System", "LastRuntimeUpgrade", (), [137u8, 29u8, 175u8, 75u8, 197u8, 208u8, 91u8, 207u8, 156u8, 87u8, 148u8, 68u8, 91u8, 140u8, 22u8, 233u8, 1u8, 229u8, 56u8, 34u8, 40u8, 194u8, 253u8, 30u8, 163u8, 39u8, 54u8, 209u8, 13u8, 27u8, 139u8, 184u8, ]) }
            pub fn upgraded_to_u32_ref_count(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::upgraded_to_u32_ref_count::UpgradedToU32RefCount, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("System", "UpgradedToU32RefCount", (), [229u8, 73u8, 9u8, 132u8, 186u8, 116u8, 151u8, 171u8, 145u8, 29u8, 34u8, 130u8, 52u8, 146u8, 124u8, 175u8, 79u8, 189u8, 147u8, 230u8, 234u8, 107u8, 124u8, 31u8, 2u8, 22u8, 86u8, 190u8, 4u8, 147u8, 50u8, 245u8, ]) }
            pub fn upgraded_to_triple_ref_count(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::upgraded_to_triple_ref_count::UpgradedToTripleRefCount, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("System", "UpgradedToTripleRefCount", (), [97u8, 66u8, 124u8, 243u8, 27u8, 167u8, 147u8, 81u8, 254u8, 201u8, 101u8, 24u8, 40u8, 231u8, 14u8, 179u8, 154u8, 163u8, 71u8, 81u8, 185u8, 167u8, 82u8, 254u8, 189u8, 3u8, 101u8, 207u8, 206u8, 194u8, 155u8, 151u8, ]) }
            pub fn execution_phase(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::execution_phase::ExecutionPhase, ::subxt::ext::subxt_core::utils::Yes, (), ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("System", "ExecutionPhase", (), [191u8, 129u8, 100u8, 134u8, 126u8, 116u8, 154u8, 203u8, 220u8, 200u8, 0u8, 26u8, 161u8, 250u8, 133u8, 205u8, 146u8, 24u8, 5u8, 156u8, 158u8, 35u8, 36u8, 253u8, 52u8, 235u8, 86u8, 167u8, 35u8, 100u8, 119u8, 27u8, ]) }
            pub fn authorized_upgrade(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::authorized_upgrade::AuthorizedUpgrade, ::subxt::ext::subxt_core::utils::Yes, (), ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("System", "AuthorizedUpgrade", (), [165u8, 97u8, 27u8, 138u8, 2u8, 28u8, 55u8, 92u8, 96u8, 96u8, 168u8, 169u8, 55u8, 178u8, 44u8, 127u8, 58u8, 140u8, 206u8, 178u8, 1u8, 37u8, 214u8, 213u8, 251u8, 123u8, 5u8, 111u8, 90u8, 148u8, 217u8, 135u8, ]) }
        }
    }
    pub mod constants {
        use super::runtime_types;
        pub struct ConstantsApi;
        impl ConstantsApi {
            pub fn block_weights(&self) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<runtime_types::frame_system::limits::BlockWeights> { ::subxt::ext::subxt_core::constants::address::StaticAddress::new_static("System", "BlockWeights", [176u8, 124u8, 225u8, 136u8, 25u8, 73u8, 247u8, 33u8, 82u8, 206u8, 85u8, 190u8, 127u8, 102u8, 71u8, 11u8, 185u8, 8u8, 58u8, 0u8, 94u8, 55u8, 163u8, 177u8, 104u8, 59u8, 60u8, 136u8, 246u8, 116u8, 0u8, 239u8, ]) }
            pub fn block_length(&self) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<runtime_types::frame_system::limits::BlockLength> { ::subxt::ext::subxt_core::constants::address::StaticAddress::new_static("System", "BlockLength", [23u8, 242u8, 225u8, 39u8, 225u8, 67u8, 152u8, 41u8, 155u8, 104u8, 68u8, 229u8, 185u8, 133u8, 10u8, 143u8, 184u8, 152u8, 234u8, 44u8, 140u8, 96u8, 166u8, 235u8, 162u8, 160u8, 72u8, 7u8, 35u8, 194u8, 3u8, 37u8, ]) }
            pub fn block_hash_count(&self) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<::core::primitive::u32> { ::subxt::ext::subxt_core::constants::address::StaticAddress::new_static("System", "BlockHashCount", [98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8, 125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8, 178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8, 145u8, ]) }
            pub fn db_weight(&self) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<runtime_types::sp_weights::RuntimeDbWeight> { ::subxt::ext::subxt_core::constants::address::StaticAddress::new_static("System", "DbWeight", [42u8, 43u8, 178u8, 142u8, 243u8, 203u8, 60u8, 173u8, 118u8, 111u8, 200u8, 170u8, 102u8, 70u8, 237u8, 187u8, 198u8, 120u8, 153u8, 232u8, 183u8, 76u8, 74u8, 10u8, 70u8, 243u8, 14u8, 218u8, 213u8, 126u8, 29u8, 177u8, ]) }
            pub fn version(&self) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<runtime_types::sp_version::RuntimeVersion> { ::subxt::ext::subxt_core::constants::address::StaticAddress::new_static("System", "Version", [219u8, 45u8, 162u8, 245u8, 177u8, 246u8, 48u8, 126u8, 191u8, 157u8, 228u8, 83u8, 111u8, 133u8, 183u8, 13u8, 148u8, 108u8, 92u8, 102u8, 72u8, 205u8, 74u8, 242u8, 233u8, 79u8, 20u8, 170u8, 72u8, 202u8, 158u8, 165u8, ]) }
            pub fn ss58_prefix(&self) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<::core::primitive::u16> { ::subxt::ext::subxt_core::constants::address::StaticAddress::new_static("System", "SS58Prefix", [116u8, 33u8, 2u8, 170u8, 181u8, 147u8, 171u8, 169u8, 167u8, 227u8, 41u8, 144u8, 11u8, 236u8, 82u8, 100u8, 74u8, 60u8, 184u8, 72u8, 169u8, 90u8, 208u8, 135u8, 15u8, 117u8, 10u8, 123u8, 128u8, 193u8, 29u8, 70u8, ]) }
        }
    }
}
pub mod parachain_system {
    use super::root_mod;
    use super::runtime_types;
    pub type Error = runtime_types::cumulus_pallet_parachain_system::pallet::Error;
    pub type Call = runtime_types::cumulus_pallet_parachain_system::pallet::Call;
    pub mod calls {
        use super::root_mod;
        use super::runtime_types;
        type DispatchError = runtime_types::sp_runtime::DispatchError;
        pub mod types {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct SetValidationData {
                pub data: set_validation_data::Data,
            }
            pub mod set_validation_data {
                use super::runtime_types;
                pub type Data = runtime_types::cumulus_primitives_parachain_inherent::ParachainInherentData;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for SetValidationData {
                const PALLET: &'static str = "ParachainSystem";
                const CALL: &'static str = "set_validation_data";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct SudoSendUpwardMessage {
                pub message: sudo_send_upward_message::Message,
            }
            pub mod sudo_send_upward_message {
                use super::runtime_types;
                pub type Message = ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for SudoSendUpwardMessage {
                const PALLET: &'static str = "ParachainSystem";
                const CALL: &'static str = "sudo_send_upward_message";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct AuthorizeUpgrade {
                pub code_hash: authorize_upgrade::CodeHash,
                pub check_version: authorize_upgrade::CheckVersion,
            }
            pub mod authorize_upgrade {
                use super::runtime_types;
                pub type CodeHash = ::subxt::ext::subxt_core::utils::H256;
                pub type CheckVersion = ::core::primitive::bool;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for AuthorizeUpgrade {
                const PALLET: &'static str = "ParachainSystem";
                const CALL: &'static str = "authorize_upgrade";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct EnactAuthorizedUpgrade {
                pub code: enact_authorized_upgrade::Code,
            }
            pub mod enact_authorized_upgrade {
                use super::runtime_types;
                pub type Code = ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for EnactAuthorizedUpgrade {
                const PALLET: &'static str = "ParachainSystem";
                const CALL: &'static str = "enact_authorized_upgrade";
            }
        }
        pub struct TransactionApi;
        impl TransactionApi {
            pub fn set_validation_data(&self, data: types::set_validation_data::Data) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::SetValidationData> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("ParachainSystem", "set_validation_data", types::SetValidationData { data }, [167u8, 126u8, 75u8, 137u8, 220u8, 60u8, 106u8, 214u8, 92u8, 170u8, 136u8, 176u8, 98u8, 0u8, 234u8, 217u8, 146u8, 113u8, 149u8, 88u8, 114u8, 141u8, 228u8, 105u8, 136u8, 71u8, 233u8, 18u8, 70u8, 36u8, 24u8, 249u8, ]) }
            pub fn sudo_send_upward_message(&self, message: types::sudo_send_upward_message::Message) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::SudoSendUpwardMessage> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("ParachainSystem", "sudo_send_upward_message", types::SudoSendUpwardMessage { message }, [1u8, 231u8, 11u8, 78u8, 127u8, 117u8, 248u8, 67u8, 230u8, 199u8, 126u8, 47u8, 20u8, 62u8, 252u8, 138u8, 199u8, 48u8, 41u8, 21u8, 28u8, 157u8, 218u8, 143u8, 4u8, 253u8, 62u8, 192u8, 94u8, 252u8, 92u8, 180u8, ]) }
            pub fn authorize_upgrade(&self, code_hash: types::authorize_upgrade::CodeHash, check_version: types::authorize_upgrade::CheckVersion) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::AuthorizeUpgrade> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("ParachainSystem", "authorize_upgrade", types::AuthorizeUpgrade { code_hash, check_version }, [213u8, 114u8, 107u8, 169u8, 223u8, 147u8, 205u8, 204u8, 3u8, 81u8, 228u8, 0u8, 82u8, 57u8, 43u8, 95u8, 12u8, 59u8, 241u8, 176u8, 143u8, 131u8, 253u8, 166u8, 98u8, 187u8, 94u8, 235u8, 177u8, 110u8, 162u8, 218u8, ]) }
            pub fn enact_authorized_upgrade(&self, code: types::enact_authorized_upgrade::Code) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::EnactAuthorizedUpgrade> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("ParachainSystem", "enact_authorized_upgrade", types::EnactAuthorizedUpgrade { code }, [232u8, 135u8, 114u8, 87u8, 196u8, 146u8, 244u8, 19u8, 106u8, 73u8, 88u8, 193u8, 48u8, 14u8, 72u8, 133u8, 247u8, 147u8, 50u8, 95u8, 252u8, 213u8, 192u8, 47u8, 244u8, 102u8, 195u8, 120u8, 179u8, 87u8, 94u8, 8u8, ]) }
        }
    }
    pub type Event = runtime_types::cumulus_pallet_parachain_system::pallet::Event;
    pub mod events {
        use super::runtime_types;
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct ValidationFunctionStored;
        impl ::subxt::ext::subxt_core::events::StaticEvent for ValidationFunctionStored {
            const PALLET: &'static str = "ParachainSystem";
            const EVENT: &'static str = "ValidationFunctionStored";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct ValidationFunctionApplied {
            pub relay_chain_block_num: validation_function_applied::RelayChainBlockNum,
        }
        pub mod validation_function_applied {
            use super::runtime_types;
            pub type RelayChainBlockNum = ::core::primitive::u32;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for ValidationFunctionApplied {
            const PALLET: &'static str = "ParachainSystem";
            const EVENT: &'static str = "ValidationFunctionApplied";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct ValidationFunctionDiscarded;
        impl ::subxt::ext::subxt_core::events::StaticEvent for ValidationFunctionDiscarded {
            const PALLET: &'static str = "ParachainSystem";
            const EVENT: &'static str = "ValidationFunctionDiscarded";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct DownwardMessagesReceived {
            pub count: downward_messages_received::Count,
        }
        pub mod downward_messages_received {
            use super::runtime_types;
            pub type Count = ::core::primitive::u32;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for DownwardMessagesReceived {
            const PALLET: &'static str = "ParachainSystem";
            const EVENT: &'static str = "DownwardMessagesReceived";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct DownwardMessagesProcessed {
            pub weight_used: downward_messages_processed::WeightUsed,
            pub dmq_head: downward_messages_processed::DmqHead,
        }
        pub mod downward_messages_processed {
            use super::runtime_types;
            pub type WeightUsed = runtime_types::sp_weights::weight_v2::Weight;
            pub type DmqHead = ::subxt::ext::subxt_core::utils::H256;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for DownwardMessagesProcessed {
            const PALLET: &'static str = "ParachainSystem";
            const EVENT: &'static str = "DownwardMessagesProcessed";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct UpwardMessageSent {
            pub message_hash: upward_message_sent::MessageHash,
        }
        pub mod upward_message_sent {
            use super::runtime_types;
            pub type MessageHash = ::core::option::Option<[::core::primitive::u8; 32usize]>;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for UpwardMessageSent {
            const PALLET: &'static str = "ParachainSystem";
            const EVENT: &'static str = "UpwardMessageSent";
        }
    }
    pub mod storage {
        use super::runtime_types;
        pub mod types {
            use super::runtime_types;
            pub mod unincluded_segment {
                use super::runtime_types;
                pub type UnincludedSegment = ::subxt::ext::subxt_core::alloc::vec::Vec<runtime_types::cumulus_pallet_parachain_system::unincluded_segment::Ancestor<::subxt::ext::subxt_core::utils::H256>>;
            }
            pub mod aggregated_unincluded_segment {
                use super::runtime_types;
                pub type AggregatedUnincludedSegment = runtime_types::cumulus_pallet_parachain_system::unincluded_segment::SegmentTracker<::subxt::ext::subxt_core::utils::H256>;
            }
            pub mod pending_validation_code {
                use super::runtime_types;
                pub type PendingValidationCode = ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>;
            }
            pub mod new_validation_code {
                use super::runtime_types;
                pub type NewValidationCode = ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>;
            }
            pub mod validation_data {
                use super::runtime_types;
                pub type ValidationData = runtime_types::polkadot_primitives::v7::PersistedValidationData<::subxt::ext::subxt_core::utils::H256, ::core::primitive::u32>;
            }
            pub mod did_set_validation_code {
                use super::runtime_types;
                pub type DidSetValidationCode = ::core::primitive::bool;
            }
            pub mod last_relay_chain_block_number {
                use super::runtime_types;
                pub type LastRelayChainBlockNumber = ::core::primitive::u32;
            }
            pub mod upgrade_restriction_signal {
                use super::runtime_types;
                pub type UpgradeRestrictionSignal = ::core::option::Option<runtime_types::polkadot_primitives::v7::UpgradeRestriction>;
            }
            pub mod upgrade_go_ahead {
                use super::runtime_types;
                pub type UpgradeGoAhead = ::core::option::Option<runtime_types::polkadot_primitives::v7::UpgradeGoAhead>;
            }
            pub mod relay_state_proof {
                use super::runtime_types;
                pub type RelayStateProof = runtime_types::sp_trie::storage_proof::StorageProof;
            }
            pub mod relevant_messaging_state {
                use super::runtime_types;
                pub type RelevantMessagingState = runtime_types::cumulus_pallet_parachain_system::relay_state_snapshot::MessagingStateSnapshot;
            }
            pub mod host_configuration {
                use super::runtime_types;
                pub type HostConfiguration = runtime_types::polkadot_primitives::v7::AbridgedHostConfiguration;
            }
            pub mod last_dmq_mqc_head {
                use super::runtime_types;
                pub type LastDmqMqcHead = runtime_types::cumulus_primitives_parachain_inherent::MessageQueueChain;
            }
            pub mod last_hrmp_mqc_heads {
                use super::runtime_types;
                pub type LastHrmpMqcHeads = ::subxt::ext::subxt_core::utils::KeyedVec<runtime_types::polkadot_parachain_primitives::primitives::Id, runtime_types::cumulus_primitives_parachain_inherent::MessageQueueChain>;
            }
            pub mod processed_downward_messages {
                use super::runtime_types;
                pub type ProcessedDownwardMessages = ::core::primitive::u32;
            }
            pub mod hrmp_watermark {
                use super::runtime_types;
                pub type HrmpWatermark = ::core::primitive::u32;
            }
            pub mod hrmp_outbound_messages {
                use super::runtime_types;
                pub type HrmpOutboundMessages = ::subxt::ext::subxt_core::alloc::vec::Vec<runtime_types::polkadot_core_primitives::OutboundHrmpMessage<runtime_types::polkadot_parachain_primitives::primitives::Id>>;
            }
            pub mod upward_messages {
                use super::runtime_types;
                pub type UpwardMessages = ::subxt::ext::subxt_core::alloc::vec::Vec<::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>>;
            }
            pub mod pending_upward_messages {
                use super::runtime_types;
                pub type PendingUpwardMessages = ::subxt::ext::subxt_core::alloc::vec::Vec<::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>>;
            }
            pub mod upward_delivery_fee_factor {
                use super::runtime_types;
                pub type UpwardDeliveryFeeFactor = runtime_types::sp_arithmetic::fixed_point::FixedU128;
            }
            pub mod announced_hrmp_messages_per_candidate {
                use super::runtime_types;
                pub type AnnouncedHrmpMessagesPerCandidate = ::core::primitive::u32;
            }
            pub mod reserved_xcmp_weight_override {
                use super::runtime_types;
                pub type ReservedXcmpWeightOverride = runtime_types::sp_weights::weight_v2::Weight;
            }
            pub mod reserved_dmp_weight_override {
                use super::runtime_types;
                pub type ReservedDmpWeightOverride = runtime_types::sp_weights::weight_v2::Weight;
            }
            pub mod custom_validation_head_data {
                use super::runtime_types;
                pub type CustomValidationHeadData = ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>;
            }
        }
        pub struct StorageApi;
        impl StorageApi {
            pub fn unincluded_segment(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::unincluded_segment::UnincludedSegment, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("ParachainSystem", "UnincludedSegment", (), [73u8, 83u8, 226u8, 16u8, 203u8, 233u8, 221u8, 109u8, 23u8, 114u8, 56u8, 154u8, 100u8, 116u8, 253u8, 10u8, 164u8, 22u8, 110u8, 73u8, 245u8, 226u8, 54u8, 146u8, 67u8, 109u8, 149u8, 142u8, 154u8, 218u8, 55u8, 178u8, ]) }
            pub fn aggregated_unincluded_segment(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::aggregated_unincluded_segment::AggregatedUnincludedSegment, ::subxt::ext::subxt_core::utils::Yes, (), ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("ParachainSystem", "AggregatedUnincludedSegment", (), [165u8, 51u8, 182u8, 156u8, 65u8, 114u8, 167u8, 133u8, 245u8, 52u8, 32u8, 119u8, 159u8, 65u8, 201u8, 108u8, 99u8, 43u8, 84u8, 63u8, 95u8, 182u8, 134u8, 163u8, 51u8, 202u8, 243u8, 82u8, 225u8, 192u8, 186u8, 2u8, ]) }
            pub fn pending_validation_code(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::pending_validation_code::PendingValidationCode, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("ParachainSystem", "PendingValidationCode", (), [78u8, 159u8, 219u8, 211u8, 177u8, 80u8, 102u8, 93u8, 83u8, 146u8, 90u8, 233u8, 232u8, 11u8, 104u8, 172u8, 93u8, 68u8, 44u8, 228u8, 99u8, 197u8, 254u8, 28u8, 181u8, 215u8, 247u8, 238u8, 49u8, 49u8, 195u8, 249u8, ]) }
            pub fn new_validation_code(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::new_validation_code::NewValidationCode, ::subxt::ext::subxt_core::utils::Yes, (), ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("ParachainSystem", "NewValidationCode", (), [185u8, 123u8, 152u8, 122u8, 230u8, 136u8, 79u8, 73u8, 206u8, 19u8, 59u8, 57u8, 75u8, 250u8, 83u8, 185u8, 29u8, 76u8, 89u8, 137u8, 77u8, 163u8, 25u8, 125u8, 182u8, 67u8, 2u8, 180u8, 48u8, 237u8, 49u8, 171u8, ]) }
            pub fn validation_data(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::validation_data::ValidationData, ::subxt::ext::subxt_core::utils::Yes, (), ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("ParachainSystem", "ValidationData", (), [193u8, 240u8, 25u8, 56u8, 103u8, 173u8, 56u8, 56u8, 229u8, 243u8, 91u8, 25u8, 249u8, 95u8, 122u8, 93u8, 37u8, 181u8, 54u8, 244u8, 217u8, 200u8, 62u8, 136u8, 80u8, 148u8, 16u8, 177u8, 124u8, 211u8, 95u8, 24u8, ]) }
            pub fn did_set_validation_code(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::did_set_validation_code::DidSetValidationCode, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("ParachainSystem", "DidSetValidationCode", (), [233u8, 228u8, 48u8, 111u8, 200u8, 35u8, 30u8, 139u8, 251u8, 77u8, 196u8, 252u8, 35u8, 222u8, 129u8, 235u8, 7u8, 19u8, 156u8, 82u8, 126u8, 173u8, 29u8, 62u8, 20u8, 67u8, 166u8, 116u8, 108u8, 182u8, 57u8, 246u8, ]) }
            pub fn last_relay_chain_block_number(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::last_relay_chain_block_number::LastRelayChainBlockNumber, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("ParachainSystem", "LastRelayChainBlockNumber", (), [17u8, 65u8, 131u8, 169u8, 195u8, 243u8, 195u8, 93u8, 220u8, 174u8, 75u8, 216u8, 214u8, 227u8, 96u8, 40u8, 8u8, 153u8, 116u8, 160u8, 79u8, 255u8, 35u8, 232u8, 242u8, 42u8, 100u8, 150u8, 208u8, 210u8, 142u8, 186u8, ]) }
            pub fn upgrade_restriction_signal(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::upgrade_restriction_signal::UpgradeRestrictionSignal, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("ParachainSystem", "UpgradeRestrictionSignal", (), [235u8, 240u8, 37u8, 44u8, 181u8, 52u8, 7u8, 216u8, 20u8, 139u8, 69u8, 124u8, 21u8, 173u8, 237u8, 64u8, 105u8, 88u8, 49u8, 69u8, 123u8, 55u8, 181u8, 167u8, 112u8, 183u8, 190u8, 231u8, 231u8, 127u8, 77u8, 148u8, ]) }
            pub fn upgrade_go_ahead(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::upgrade_go_ahead::UpgradeGoAhead, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("ParachainSystem", "UpgradeGoAhead", (), [149u8, 144u8, 186u8, 88u8, 180u8, 34u8, 82u8, 226u8, 100u8, 148u8, 246u8, 55u8, 233u8, 97u8, 43u8, 0u8, 48u8, 31u8, 69u8, 154u8, 29u8, 147u8, 241u8, 91u8, 81u8, 126u8, 206u8, 117u8, 14u8, 149u8, 87u8, 88u8, ]) }
            pub fn relay_state_proof(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::relay_state_proof::RelayStateProof, ::subxt::ext::subxt_core::utils::Yes, (), ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("ParachainSystem", "RelayStateProof", (), [46u8, 115u8, 163u8, 190u8, 246u8, 47u8, 200u8, 159u8, 206u8, 204u8, 94u8, 250u8, 127u8, 112u8, 109u8, 111u8, 210u8, 195u8, 244u8, 41u8, 36u8, 187u8, 71u8, 150u8, 149u8, 253u8, 143u8, 33u8, 83u8, 189u8, 182u8, 238u8, ]) }
            pub fn relevant_messaging_state(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::relevant_messaging_state::RelevantMessagingState, ::subxt::ext::subxt_core::utils::Yes, (), ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("ParachainSystem", "RelevantMessagingState", (), [117u8, 166u8, 186u8, 126u8, 21u8, 174u8, 86u8, 253u8, 163u8, 90u8, 54u8, 226u8, 186u8, 253u8, 126u8, 168u8, 145u8, 45u8, 155u8, 32u8, 97u8, 110u8, 208u8, 125u8, 47u8, 113u8, 165u8, 199u8, 210u8, 118u8, 217u8, 73u8, ]) }
            pub fn host_configuration(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::host_configuration::HostConfiguration, ::subxt::ext::subxt_core::utils::Yes, (), ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("ParachainSystem", "HostConfiguration", (), [252u8, 23u8, 111u8, 189u8, 120u8, 204u8, 129u8, 223u8, 248u8, 179u8, 239u8, 173u8, 133u8, 61u8, 140u8, 2u8, 75u8, 32u8, 204u8, 178u8, 69u8, 21u8, 44u8, 227u8, 178u8, 179u8, 33u8, 26u8, 131u8, 156u8, 78u8, 85u8, ]) }
            pub fn last_dmq_mqc_head(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::last_dmq_mqc_head::LastDmqMqcHead, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("ParachainSystem", "LastDmqMqcHead", (), [1u8, 70u8, 140u8, 40u8, 51u8, 127u8, 75u8, 80u8, 5u8, 49u8, 196u8, 31u8, 30u8, 61u8, 54u8, 252u8, 0u8, 0u8, 100u8, 115u8, 177u8, 250u8, 138u8, 48u8, 107u8, 41u8, 93u8, 87u8, 195u8, 107u8, 206u8, 227u8, ]) }
            pub fn last_hrmp_mqc_heads(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::last_hrmp_mqc_heads::LastHrmpMqcHeads, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("ParachainSystem", "LastHrmpMqcHeads", (), [131u8, 170u8, 142u8, 30u8, 101u8, 113u8, 131u8, 81u8, 38u8, 168u8, 98u8, 3u8, 9u8, 109u8, 96u8, 179u8, 115u8, 177u8, 128u8, 11u8, 238u8, 54u8, 81u8, 60u8, 97u8, 112u8, 224u8, 175u8, 86u8, 133u8, 182u8, 76u8, ]) }
            pub fn processed_downward_messages(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::processed_downward_messages::ProcessedDownwardMessages, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("ParachainSystem", "ProcessedDownwardMessages", (), [151u8, 234u8, 196u8, 87u8, 130u8, 79u8, 4u8, 102u8, 47u8, 10u8, 33u8, 132u8, 149u8, 118u8, 61u8, 141u8, 5u8, 1u8, 30u8, 120u8, 220u8, 156u8, 16u8, 11u8, 14u8, 52u8, 126u8, 151u8, 244u8, 149u8, 197u8, 51u8, ]) }
            pub fn hrmp_watermark(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::hrmp_watermark::HrmpWatermark, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("ParachainSystem", "HrmpWatermark", (), [77u8, 62u8, 59u8, 220u8, 7u8, 125u8, 98u8, 249u8, 108u8, 212u8, 223u8, 99u8, 152u8, 13u8, 29u8, 80u8, 166u8, 65u8, 232u8, 113u8, 145u8, 128u8, 123u8, 35u8, 238u8, 31u8, 113u8, 156u8, 220u8, 104u8, 217u8, 165u8, ]) }
            pub fn hrmp_outbound_messages(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::hrmp_outbound_messages::HrmpOutboundMessages, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("ParachainSystem", "HrmpOutboundMessages", (), [42u8, 9u8, 96u8, 217u8, 25u8, 101u8, 129u8, 147u8, 150u8, 20u8, 164u8, 186u8, 217u8, 178u8, 15u8, 201u8, 233u8, 104u8, 92u8, 120u8, 29u8, 245u8, 196u8, 13u8, 141u8, 210u8, 102u8, 62u8, 216u8, 80u8, 246u8, 145u8, ]) }
            pub fn upward_messages(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::upward_messages::UpwardMessages, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("ParachainSystem", "UpwardMessages", (), [179u8, 127u8, 8u8, 94u8, 194u8, 246u8, 53u8, 79u8, 80u8, 22u8, 18u8, 75u8, 116u8, 163u8, 90u8, 161u8, 30u8, 140u8, 57u8, 126u8, 60u8, 91u8, 23u8, 30u8, 120u8, 245u8, 125u8, 96u8, 152u8, 25u8, 248u8, 85u8, ]) }
            pub fn pending_upward_messages(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::pending_upward_messages::PendingUpwardMessages, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("ParachainSystem", "PendingUpwardMessages", (), [239u8, 45u8, 18u8, 173u8, 148u8, 150u8, 55u8, 176u8, 173u8, 156u8, 246u8, 226u8, 198u8, 214u8, 104u8, 187u8, 186u8, 13u8, 83u8, 194u8, 153u8, 29u8, 228u8, 109u8, 26u8, 18u8, 212u8, 151u8, 246u8, 24u8, 133u8, 216u8, ]) }
            pub fn upward_delivery_fee_factor(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::upward_delivery_fee_factor::UpwardDeliveryFeeFactor, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("ParachainSystem", "UpwardDeliveryFeeFactor", (), [40u8, 217u8, 164u8, 111u8, 151u8, 132u8, 69u8, 226u8, 163u8, 175u8, 43u8, 239u8, 179u8, 217u8, 136u8, 161u8, 13u8, 251u8, 163u8, 102u8, 24u8, 27u8, 168u8, 89u8, 221u8, 83u8, 93u8, 64u8, 96u8, 117u8, 146u8, 71u8, ]) }
            pub fn announced_hrmp_messages_per_candidate(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::announced_hrmp_messages_per_candidate::AnnouncedHrmpMessagesPerCandidate, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("ParachainSystem", "AnnouncedHrmpMessagesPerCandidate", (), [93u8, 11u8, 229u8, 172u8, 73u8, 87u8, 13u8, 149u8, 15u8, 94u8, 163u8, 107u8, 156u8, 22u8, 131u8, 177u8, 96u8, 247u8, 213u8, 224u8, 41u8, 126u8, 157u8, 33u8, 154u8, 194u8, 95u8, 234u8, 65u8, 19u8, 58u8, 161u8, ]) }
            pub fn reserved_xcmp_weight_override(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::reserved_xcmp_weight_override::ReservedXcmpWeightOverride, ::subxt::ext::subxt_core::utils::Yes, (), ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("ParachainSystem", "ReservedXcmpWeightOverride", (), [176u8, 93u8, 203u8, 74u8, 18u8, 170u8, 246u8, 203u8, 109u8, 89u8, 86u8, 77u8, 96u8, 66u8, 189u8, 79u8, 184u8, 253u8, 11u8, 230u8, 87u8, 120u8, 1u8, 254u8, 215u8, 41u8, 210u8, 86u8, 239u8, 206u8, 60u8, 2u8, ]) }
            pub fn reserved_dmp_weight_override(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::reserved_dmp_weight_override::ReservedDmpWeightOverride, ::subxt::ext::subxt_core::utils::Yes, (), ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("ParachainSystem", "ReservedDmpWeightOverride", (), [205u8, 124u8, 9u8, 156u8, 255u8, 207u8, 208u8, 23u8, 179u8, 132u8, 254u8, 157u8, 237u8, 240u8, 167u8, 203u8, 253u8, 111u8, 136u8, 32u8, 100u8, 152u8, 16u8, 19u8, 175u8, 14u8, 108u8, 61u8, 59u8, 231u8, 70u8, 112u8, ]) }
            pub fn custom_validation_head_data(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::custom_validation_head_data::CustomValidationHeadData, ::subxt::ext::subxt_core::utils::Yes, (), ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("ParachainSystem", "CustomValidationHeadData", (), [52u8, 186u8, 187u8, 57u8, 245u8, 171u8, 202u8, 23u8, 92u8, 80u8, 118u8, 66u8, 251u8, 156u8, 175u8, 254u8, 141u8, 185u8, 115u8, 209u8, 170u8, 165u8, 1u8, 242u8, 120u8, 234u8, 162u8, 24u8, 135u8, 105u8, 8u8, 177u8, ]) }
        }
    }
    pub mod constants {
        use super::runtime_types;
        pub struct ConstantsApi;
        impl ConstantsApi { pub fn self_para_id(&self) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<runtime_types::polkadot_parachain_primitives::primitives::Id> { ::subxt::ext::subxt_core::constants::address::StaticAddress::new_static("ParachainSystem", "SelfParaId", [65u8, 93u8, 120u8, 165u8, 204u8, 81u8, 159u8, 163u8, 93u8, 135u8, 114u8, 121u8, 147u8, 35u8, 215u8, 213u8, 4u8, 223u8, 83u8, 37u8, 225u8, 200u8, 189u8, 156u8, 140u8, 36u8, 58u8, 46u8, 42u8, 232u8, 155u8, 0u8, ]) } }
    }
}
pub mod timestamp {
    use super::root_mod;
    use super::runtime_types;
    pub type Call = runtime_types::pallet_timestamp::pallet::Call;
    pub mod calls {
        use super::root_mod;
        use super::runtime_types;
        type DispatchError = runtime_types::sp_runtime::DispatchError;
        pub mod types {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct Set {
                #[codec(compact)] pub now: set::Now,
            }
            pub mod set {
                use super::runtime_types;
                pub type Now = ::core::primitive::u64;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for Set {
                const PALLET: &'static str = "Timestamp";
                const CALL: &'static str = "set";
            }
        }
        pub struct TransactionApi;
        impl TransactionApi { pub fn set(&self, now: types::set::Now) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::Set> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Timestamp", "set", types::Set { now }, [37u8, 95u8, 49u8, 218u8, 24u8, 22u8, 0u8, 95u8, 72u8, 35u8, 155u8, 199u8, 213u8, 54u8, 207u8, 22u8, 185u8, 193u8, 221u8, 70u8, 18u8, 200u8, 4u8, 231u8, 195u8, 173u8, 6u8, 122u8, 11u8, 203u8, 231u8, 227u8, ]) } }
    }
    pub mod storage {
        use super::runtime_types;
        pub mod types {
            use super::runtime_types;
            pub mod now {
                use super::runtime_types;
                pub type Now = ::core::primitive::u64;
            }
            pub mod did_update {
                use super::runtime_types;
                pub type DidUpdate = ::core::primitive::bool;
            }
        }
        pub struct StorageApi;
        impl StorageApi {
            pub fn now(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::now::Now, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Timestamp", "Now", (), [44u8, 50u8, 80u8, 30u8, 195u8, 146u8, 123u8, 238u8, 8u8, 163u8, 187u8, 92u8, 61u8, 39u8, 51u8, 29u8, 173u8, 169u8, 217u8, 158u8, 85u8, 187u8, 141u8, 26u8, 12u8, 115u8, 51u8, 11u8, 200u8, 244u8, 138u8, 152u8, ]) }
            pub fn did_update(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::did_update::DidUpdate, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Timestamp", "DidUpdate", (), [229u8, 175u8, 246u8, 102u8, 237u8, 158u8, 212u8, 229u8, 238u8, 214u8, 205u8, 160u8, 164u8, 252u8, 195u8, 75u8, 139u8, 110u8, 22u8, 34u8, 248u8, 204u8, 107u8, 46u8, 20u8, 200u8, 238u8, 167u8, 71u8, 41u8, 214u8, 140u8, ]) }
        }
    }
    pub mod constants {
        use super::runtime_types;
        pub struct ConstantsApi;
        impl ConstantsApi { pub fn minimum_period(&self) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<::core::primitive::u64> { ::subxt::ext::subxt_core::constants::address::StaticAddress::new_static("Timestamp", "MinimumPeriod", [128u8, 214u8, 205u8, 242u8, 181u8, 142u8, 124u8, 231u8, 190u8, 146u8, 59u8, 226u8, 157u8, 101u8, 103u8, 117u8, 249u8, 65u8, 18u8, 191u8, 103u8, 119u8, 53u8, 85u8, 81u8, 96u8, 220u8, 42u8, 184u8, 239u8, 42u8, 246u8, ]) } }
    }
}
pub mod parachain_info {
    use super::root_mod;
    use super::runtime_types;
    pub type Call = runtime_types::staging_parachain_info::pallet::Call;
    pub mod calls {
        use super::root_mod;
        use super::runtime_types;
        type DispatchError = runtime_types::sp_runtime::DispatchError;
        pub mod types { use super::runtime_types; }
        pub struct TransactionApi;
        impl TransactionApi {}
    }
    pub mod storage {
        use super::runtime_types;
        pub mod types {
            use super::runtime_types;
            pub mod parachain_id {
                use super::runtime_types;
                pub type ParachainId = runtime_types::polkadot_parachain_primitives::primitives::Id;
            }
        }
        pub struct StorageApi;
        impl StorageApi { pub fn parachain_id(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::parachain_id::ParachainId, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("ParachainInfo", "ParachainId", (), [160u8, 130u8, 74u8, 181u8, 231u8, 180u8, 246u8, 152u8, 204u8, 44u8, 245u8, 91u8, 113u8, 246u8, 218u8, 50u8, 254u8, 248u8, 35u8, 219u8, 83u8, 144u8, 228u8, 245u8, 122u8, 53u8, 194u8, 172u8, 222u8, 118u8, 202u8, 91u8, ]) } }
    }
}
pub mod balances {
    use super::root_mod;
    use super::runtime_types;
    pub type Error = runtime_types::pallet_balances::pallet::Error;
    pub type Call = runtime_types::pallet_balances::pallet::Call;
    pub mod calls {
        use super::root_mod;
        use super::runtime_types;
        type DispatchError = runtime_types::sp_runtime::DispatchError;
        pub mod types {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct TransferAllowDeath {
                pub dest: transfer_allow_death::Dest,
                #[codec(compact)] pub value: transfer_allow_death::Value,
            }
            pub mod transfer_allow_death {
                use super::runtime_types;
                pub type Dest = ::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()>;
                pub type Value = ::core::primitive::u128;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for TransferAllowDeath {
                const PALLET: &'static str = "Balances";
                const CALL: &'static str = "transfer_allow_death";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct ForceTransfer {
                pub source: force_transfer::Source,
                pub dest: force_transfer::Dest,
                #[codec(compact)] pub value: force_transfer::Value,
            }
            pub mod force_transfer {
                use super::runtime_types;
                pub type Source = ::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()>;
                pub type Dest = ::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()>;
                pub type Value = ::core::primitive::u128;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for ForceTransfer {
                const PALLET: &'static str = "Balances";
                const CALL: &'static str = "force_transfer";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct TransferKeepAlive {
                pub dest: transfer_keep_alive::Dest,
                #[codec(compact)] pub value: transfer_keep_alive::Value,
            }
            pub mod transfer_keep_alive {
                use super::runtime_types;
                pub type Dest = ::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()>;
                pub type Value = ::core::primitive::u128;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for TransferKeepAlive {
                const PALLET: &'static str = "Balances";
                const CALL: &'static str = "transfer_keep_alive";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct TransferAll {
                pub dest: transfer_all::Dest,
                pub keep_alive: transfer_all::KeepAlive,
            }
            pub mod transfer_all {
                use super::runtime_types;
                pub type Dest = ::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()>;
                pub type KeepAlive = ::core::primitive::bool;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for TransferAll {
                const PALLET: &'static str = "Balances";
                const CALL: &'static str = "transfer_all";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct ForceUnreserve {
                pub who: force_unreserve::Who,
                pub amount: force_unreserve::Amount,
            }
            pub mod force_unreserve {
                use super::runtime_types;
                pub type Who = ::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()>;
                pub type Amount = ::core::primitive::u128;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for ForceUnreserve {
                const PALLET: &'static str = "Balances";
                const CALL: &'static str = "force_unreserve";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct UpgradeAccounts {
                pub who: upgrade_accounts::Who,
            }
            pub mod upgrade_accounts {
                use super::runtime_types;
                pub type Who = ::subxt::ext::subxt_core::alloc::vec::Vec<::subxt::ext::subxt_core::utils::AccountId32>;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for UpgradeAccounts {
                const PALLET: &'static str = "Balances";
                const CALL: &'static str = "upgrade_accounts";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct ForceSetBalance {
                pub who: force_set_balance::Who,
                #[codec(compact)] pub new_free: force_set_balance::NewFree,
            }
            pub mod force_set_balance {
                use super::runtime_types;
                pub type Who = ::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()>;
                pub type NewFree = ::core::primitive::u128;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for ForceSetBalance {
                const PALLET: &'static str = "Balances";
                const CALL: &'static str = "force_set_balance";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct ForceAdjustTotalIssuance {
                pub direction: force_adjust_total_issuance::Direction,
                #[codec(compact)] pub delta: force_adjust_total_issuance::Delta,
            }
            pub mod force_adjust_total_issuance {
                use super::runtime_types;
                pub type Direction = runtime_types::pallet_balances::types::AdjustmentDirection;
                pub type Delta = ::core::primitive::u128;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for ForceAdjustTotalIssuance {
                const PALLET: &'static str = "Balances";
                const CALL: &'static str = "force_adjust_total_issuance";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct Burn {
                #[codec(compact)] pub value: burn::Value,
                pub keep_alive: burn::KeepAlive,
            }
            pub mod burn {
                use super::runtime_types;
                pub type Value = ::core::primitive::u128;
                pub type KeepAlive = ::core::primitive::bool;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for Burn {
                const PALLET: &'static str = "Balances";
                const CALL: &'static str = "burn";
            }
        }
        pub struct TransactionApi;
        impl TransactionApi {
            pub fn transfer_allow_death(&self, dest: types::transfer_allow_death::Dest, value: types::transfer_allow_death::Value) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::TransferAllowDeath> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Balances", "transfer_allow_death", types::TransferAllowDeath { dest, value }, [51u8, 166u8, 195u8, 10u8, 139u8, 218u8, 55u8, 130u8, 6u8, 194u8, 35u8, 140u8, 27u8, 205u8, 214u8, 222u8, 102u8, 43u8, 143u8, 145u8, 86u8, 219u8, 210u8, 147u8, 13u8, 39u8, 51u8, 21u8, 237u8, 179u8, 132u8, 130u8, ]) }
            pub fn force_transfer(&self, source: types::force_transfer::Source, dest: types::force_transfer::Dest, value: types::force_transfer::Value) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::ForceTransfer> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Balances", "force_transfer", types::ForceTransfer { source, dest, value }, [154u8, 93u8, 222u8, 27u8, 12u8, 248u8, 63u8, 213u8, 224u8, 86u8, 250u8, 153u8, 249u8, 102u8, 83u8, 160u8, 79u8, 125u8, 105u8, 222u8, 77u8, 180u8, 90u8, 105u8, 81u8, 217u8, 60u8, 25u8, 213u8, 51u8, 185u8, 96u8, ]) }
            pub fn transfer_keep_alive(&self, dest: types::transfer_keep_alive::Dest, value: types::transfer_keep_alive::Value) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::TransferKeepAlive> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Balances", "transfer_keep_alive", types::TransferKeepAlive { dest, value }, [245u8, 14u8, 190u8, 193u8, 32u8, 210u8, 74u8, 92u8, 25u8, 182u8, 76u8, 55u8, 247u8, 83u8, 114u8, 75u8, 143u8, 236u8, 117u8, 25u8, 54u8, 157u8, 208u8, 207u8, 233u8, 89u8, 70u8, 161u8, 235u8, 242u8, 222u8, 59u8, ]) }
            pub fn transfer_all(&self, dest: types::transfer_all::Dest, keep_alive: types::transfer_all::KeepAlive) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::TransferAll> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Balances", "transfer_all", types::TransferAll { dest, keep_alive }, [105u8, 132u8, 49u8, 144u8, 195u8, 250u8, 34u8, 46u8, 213u8, 248u8, 112u8, 188u8, 81u8, 228u8, 136u8, 18u8, 67u8, 172u8, 37u8, 38u8, 238u8, 9u8, 34u8, 15u8, 67u8, 34u8, 148u8, 195u8, 223u8, 29u8, 154u8, 6u8, ]) }
            pub fn force_unreserve(&self, who: types::force_unreserve::Who, amount: types::force_unreserve::Amount) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::ForceUnreserve> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Balances", "force_unreserve", types::ForceUnreserve { who, amount }, [142u8, 151u8, 64u8, 205u8, 46u8, 64u8, 62u8, 122u8, 108u8, 49u8, 223u8, 140u8, 120u8, 153u8, 35u8, 165u8, 187u8, 38u8, 157u8, 200u8, 123u8, 199u8, 198u8, 168u8, 208u8, 159u8, 39u8, 134u8, 92u8, 103u8, 84u8, 171u8, ]) }
            pub fn upgrade_accounts(&self, who: types::upgrade_accounts::Who) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::UpgradeAccounts> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Balances", "upgrade_accounts", types::UpgradeAccounts { who }, [66u8, 200u8, 179u8, 104u8, 65u8, 2u8, 101u8, 56u8, 130u8, 161u8, 224u8, 233u8, 255u8, 124u8, 70u8, 122u8, 8u8, 49u8, 103u8, 178u8, 68u8, 47u8, 214u8, 166u8, 217u8, 116u8, 178u8, 50u8, 212u8, 164u8, 98u8, 226u8, ]) }
            pub fn force_set_balance(&self, who: types::force_set_balance::Who, new_free: types::force_set_balance::NewFree) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::ForceSetBalance> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Balances", "force_set_balance", types::ForceSetBalance { who, new_free }, [114u8, 229u8, 59u8, 204u8, 180u8, 83u8, 17u8, 4u8, 59u8, 4u8, 55u8, 39u8, 151u8, 196u8, 124u8, 60u8, 209u8, 65u8, 193u8, 11u8, 44u8, 164u8, 116u8, 93u8, 169u8, 30u8, 199u8, 165u8, 55u8, 231u8, 223u8, 43u8, ]) }
            pub fn force_adjust_total_issuance(&self, direction: types::force_adjust_total_issuance::Direction, delta: types::force_adjust_total_issuance::Delta) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::ForceAdjustTotalIssuance> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Balances", "force_adjust_total_issuance", types::ForceAdjustTotalIssuance { direction, delta }, [208u8, 134u8, 56u8, 133u8, 232u8, 164u8, 10u8, 213u8, 53u8, 193u8, 190u8, 63u8, 236u8, 186u8, 96u8, 122u8, 104u8, 87u8, 173u8, 38u8, 58u8, 176u8, 21u8, 78u8, 42u8, 106u8, 46u8, 248u8, 251u8, 190u8, 150u8, 202u8, ]) }
            pub fn burn(&self, value: types::burn::Value, keep_alive: types::burn::KeepAlive) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::Burn> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Balances", "burn", types::Burn { value, keep_alive }, [176u8, 64u8, 7u8, 109u8, 16u8, 44u8, 145u8, 125u8, 147u8, 152u8, 130u8, 114u8, 221u8, 201u8, 150u8, 162u8, 118u8, 71u8, 52u8, 92u8, 240u8, 116u8, 203u8, 98u8, 5u8, 22u8, 43u8, 102u8, 94u8, 208u8, 101u8, 57u8, ]) }
        }
    }
    pub type Event = runtime_types::pallet_balances::pallet::Event;
    pub mod events {
        use super::runtime_types;
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct Endowed {
            pub account: endowed::Account,
            pub free_balance: endowed::FreeBalance,
        }
        pub mod endowed {
            use super::runtime_types;
            pub type Account = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type FreeBalance = ::core::primitive::u128;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for Endowed {
            const PALLET: &'static str = "Balances";
            const EVENT: &'static str = "Endowed";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct DustLost {
            pub account: dust_lost::Account,
            pub amount: dust_lost::Amount,
        }
        pub mod dust_lost {
            use super::runtime_types;
            pub type Account = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type Amount = ::core::primitive::u128;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for DustLost {
            const PALLET: &'static str = "Balances";
            const EVENT: &'static str = "DustLost";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct Transfer {
            pub from: transfer::From,
            pub to: transfer::To,
            pub amount: transfer::Amount,
        }
        pub mod transfer {
            use super::runtime_types;
            pub type From = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type To = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type Amount = ::core::primitive::u128;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for Transfer {
            const PALLET: &'static str = "Balances";
            const EVENT: &'static str = "Transfer";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct BalanceSet {
            pub who: balance_set::Who,
            pub free: balance_set::Free,
        }
        pub mod balance_set {
            use super::runtime_types;
            pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type Free = ::core::primitive::u128;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for BalanceSet {
            const PALLET: &'static str = "Balances";
            const EVENT: &'static str = "BalanceSet";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct Reserved {
            pub who: reserved::Who,
            pub amount: reserved::Amount,
        }
        pub mod reserved {
            use super::runtime_types;
            pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type Amount = ::core::primitive::u128;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for Reserved {
            const PALLET: &'static str = "Balances";
            const EVENT: &'static str = "Reserved";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct Unreserved {
            pub who: unreserved::Who,
            pub amount: unreserved::Amount,
        }
        pub mod unreserved {
            use super::runtime_types;
            pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type Amount = ::core::primitive::u128;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for Unreserved {
            const PALLET: &'static str = "Balances";
            const EVENT: &'static str = "Unreserved";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct ReserveRepatriated {
            pub from: reserve_repatriated::From,
            pub to: reserve_repatriated::To,
            pub amount: reserve_repatriated::Amount,
            pub destination_status: reserve_repatriated::DestinationStatus,
        }
        pub mod reserve_repatriated {
            use super::runtime_types;
            pub type From = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type To = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type Amount = ::core::primitive::u128;
            pub type DestinationStatus = runtime_types::frame_support::traits::tokens::misc::BalanceStatus;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for ReserveRepatriated {
            const PALLET: &'static str = "Balances";
            const EVENT: &'static str = "ReserveRepatriated";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct Deposit {
            pub who: deposit::Who,
            pub amount: deposit::Amount,
        }
        pub mod deposit {
            use super::runtime_types;
            pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type Amount = ::core::primitive::u128;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for Deposit {
            const PALLET: &'static str = "Balances";
            const EVENT: &'static str = "Deposit";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct Withdraw {
            pub who: withdraw::Who,
            pub amount: withdraw::Amount,
        }
        pub mod withdraw {
            use super::runtime_types;
            pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type Amount = ::core::primitive::u128;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for Withdraw {
            const PALLET: &'static str = "Balances";
            const EVENT: &'static str = "Withdraw";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct Slashed {
            pub who: slashed::Who,
            pub amount: slashed::Amount,
        }
        pub mod slashed {
            use super::runtime_types;
            pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type Amount = ::core::primitive::u128;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for Slashed {
            const PALLET: &'static str = "Balances";
            const EVENT: &'static str = "Slashed";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct Minted {
            pub who: minted::Who,
            pub amount: minted::Amount,
        }
        pub mod minted {
            use super::runtime_types;
            pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type Amount = ::core::primitive::u128;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for Minted {
            const PALLET: &'static str = "Balances";
            const EVENT: &'static str = "Minted";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct Burned {
            pub who: burned::Who,
            pub amount: burned::Amount,
        }
        pub mod burned {
            use super::runtime_types;
            pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type Amount = ::core::primitive::u128;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for Burned {
            const PALLET: &'static str = "Balances";
            const EVENT: &'static str = "Burned";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct Suspended {
            pub who: suspended::Who,
            pub amount: suspended::Amount,
        }
        pub mod suspended {
            use super::runtime_types;
            pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type Amount = ::core::primitive::u128;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for Suspended {
            const PALLET: &'static str = "Balances";
            const EVENT: &'static str = "Suspended";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct Restored {
            pub who: restored::Who,
            pub amount: restored::Amount,
        }
        pub mod restored {
            use super::runtime_types;
            pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type Amount = ::core::primitive::u128;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for Restored {
            const PALLET: &'static str = "Balances";
            const EVENT: &'static str = "Restored";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct Upgraded {
            pub who: upgraded::Who,
        }
        pub mod upgraded {
            use super::runtime_types;
            pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for Upgraded {
            const PALLET: &'static str = "Balances";
            const EVENT: &'static str = "Upgraded";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct Issued {
            pub amount: issued::Amount,
        }
        pub mod issued {
            use super::runtime_types;
            pub type Amount = ::core::primitive::u128;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for Issued {
            const PALLET: &'static str = "Balances";
            const EVENT: &'static str = "Issued";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct Rescinded {
            pub amount: rescinded::Amount,
        }
        pub mod rescinded {
            use super::runtime_types;
            pub type Amount = ::core::primitive::u128;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for Rescinded {
            const PALLET: &'static str = "Balances";
            const EVENT: &'static str = "Rescinded";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct Locked {
            pub who: locked::Who,
            pub amount: locked::Amount,
        }
        pub mod locked {
            use super::runtime_types;
            pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type Amount = ::core::primitive::u128;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for Locked {
            const PALLET: &'static str = "Balances";
            const EVENT: &'static str = "Locked";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct Unlocked {
            pub who: unlocked::Who,
            pub amount: unlocked::Amount,
        }
        pub mod unlocked {
            use super::runtime_types;
            pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type Amount = ::core::primitive::u128;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for Unlocked {
            const PALLET: &'static str = "Balances";
            const EVENT: &'static str = "Unlocked";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct Frozen {
            pub who: frozen::Who,
            pub amount: frozen::Amount,
        }
        pub mod frozen {
            use super::runtime_types;
            pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type Amount = ::core::primitive::u128;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for Frozen {
            const PALLET: &'static str = "Balances";
            const EVENT: &'static str = "Frozen";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct Thawed {
            pub who: thawed::Who,
            pub amount: thawed::Amount,
        }
        pub mod thawed {
            use super::runtime_types;
            pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type Amount = ::core::primitive::u128;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for Thawed {
            const PALLET: &'static str = "Balances";
            const EVENT: &'static str = "Thawed";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct TotalIssuanceForced {
            pub old: total_issuance_forced::Old,
            pub new: total_issuance_forced::New,
        }
        pub mod total_issuance_forced {
            use super::runtime_types;
            pub type Old = ::core::primitive::u128;
            pub type New = ::core::primitive::u128;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for TotalIssuanceForced {
            const PALLET: &'static str = "Balances";
            const EVENT: &'static str = "TotalIssuanceForced";
        }
    }
    pub mod storage {
        use super::runtime_types;
        pub mod types {
            use super::runtime_types;
            pub mod total_issuance {
                use super::runtime_types;
                pub type TotalIssuance = ::core::primitive::u128;
            }
            pub mod inactive_issuance {
                use super::runtime_types;
                pub type InactiveIssuance = ::core::primitive::u128;
            }
            pub mod account {
                use super::runtime_types;
                pub type Account = runtime_types::pallet_balances::types::AccountData<::core::primitive::u128>;
                pub type Param0 = ::subxt::ext::subxt_core::utils::AccountId32;
            }
            pub mod locks {
                use super::runtime_types;
                pub type Locks = runtime_types::bounded_collections::weak_bounded_vec::WeakBoundedVec<runtime_types::pallet_balances::types::BalanceLock<::core::primitive::u128>>;
                pub type Param0 = ::subxt::ext::subxt_core::utils::AccountId32;
            }
            pub mod reserves {
                use super::runtime_types;
                pub type Reserves = runtime_types::bounded_collections::bounded_vec::BoundedVec<runtime_types::pallet_balances::types::ReserveData<[::core::primitive::u8; 8usize], ::core::primitive::u128>>;
                pub type Param0 = ::subxt::ext::subxt_core::utils::AccountId32;
            }
            pub mod holds {
                use super::runtime_types;
                pub type Holds = runtime_types::bounded_collections::bounded_vec::BoundedVec<runtime_types::pallet_balances::types::IdAmount<runtime_types::people_rococo_runtime::RuntimeHoldReason, ::core::primitive::u128>>;
                pub type Param0 = ::subxt::ext::subxt_core::utils::AccountId32;
            }
            pub mod freezes {
                use super::runtime_types;
                pub type Freezes = runtime_types::bounded_collections::bounded_vec::BoundedVec<runtime_types::pallet_balances::types::IdAmount<(), ::core::primitive::u128>>;
                pub type Param0 = ::subxt::ext::subxt_core::utils::AccountId32;
            }
        }
        pub struct StorageApi;
        impl StorageApi {
            pub fn total_issuance(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::total_issuance::TotalIssuance, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Balances", "TotalIssuance", (), [116u8, 70u8, 119u8, 194u8, 69u8, 37u8, 116u8, 206u8, 171u8, 70u8, 171u8, 210u8, 226u8, 111u8, 184u8, 204u8, 206u8, 11u8, 68u8, 72u8, 255u8, 19u8, 194u8, 11u8, 27u8, 194u8, 81u8, 204u8, 59u8, 224u8, 202u8, 185u8, ]) }
            pub fn inactive_issuance(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::inactive_issuance::InactiveIssuance, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Balances", "InactiveIssuance", (), [212u8, 185u8, 19u8, 50u8, 250u8, 72u8, 173u8, 50u8, 4u8, 104u8, 161u8, 249u8, 77u8, 247u8, 204u8, 248u8, 11u8, 18u8, 57u8, 4u8, 82u8, 110u8, 30u8, 216u8, 16u8, 37u8, 87u8, 67u8, 189u8, 235u8, 214u8, 155u8, ]) }
            pub fn account_iter(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::account::Account, (), ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Balances", "Account", (), [213u8, 38u8, 200u8, 69u8, 218u8, 0u8, 112u8, 181u8, 160u8, 23u8, 96u8, 90u8, 3u8, 88u8, 126u8, 22u8, 103u8, 74u8, 64u8, 69u8, 29u8, 247u8, 18u8, 17u8, 234u8, 143u8, 189u8, 22u8, 247u8, 194u8, 154u8, 249u8, ]) }
            pub fn account(&self, _0: impl ::core::borrow::Borrow<types::account::Param0>) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::account::Param0>, types::account::Account, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Balances", "Account", ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0.borrow()), [213u8, 38u8, 200u8, 69u8, 218u8, 0u8, 112u8, 181u8, 160u8, 23u8, 96u8, 90u8, 3u8, 88u8, 126u8, 22u8, 103u8, 74u8, 64u8, 69u8, 29u8, 247u8, 18u8, 17u8, 234u8, 143u8, 189u8, 22u8, 247u8, 194u8, 154u8, 249u8, ]) }
            pub fn locks_iter(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::locks::Locks, (), ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Balances", "Locks", (), [10u8, 223u8, 55u8, 0u8, 249u8, 69u8, 168u8, 41u8, 75u8, 35u8, 120u8, 167u8, 18u8, 132u8, 9u8, 20u8, 91u8, 51u8, 27u8, 69u8, 136u8, 187u8, 13u8, 220u8, 163u8, 122u8, 26u8, 141u8, 174u8, 249u8, 85u8, 37u8, ]) }
            pub fn locks(&self, _0: impl ::core::borrow::Borrow<types::locks::Param0>) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::locks::Param0>, types::locks::Locks, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Balances", "Locks", ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0.borrow()), [10u8, 223u8, 55u8, 0u8, 249u8, 69u8, 168u8, 41u8, 75u8, 35u8, 120u8, 167u8, 18u8, 132u8, 9u8, 20u8, 91u8, 51u8, 27u8, 69u8, 136u8, 187u8, 13u8, 220u8, 163u8, 122u8, 26u8, 141u8, 174u8, 249u8, 85u8, 37u8, ]) }
            pub fn reserves_iter(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::reserves::Reserves, (), ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Balances", "Reserves", (), [112u8, 10u8, 241u8, 77u8, 64u8, 187u8, 106u8, 159u8, 13u8, 153u8, 140u8, 178u8, 182u8, 50u8, 1u8, 55u8, 149u8, 92u8, 196u8, 229u8, 170u8, 106u8, 193u8, 88u8, 255u8, 244u8, 2u8, 193u8, 62u8, 235u8, 204u8, 91u8, ]) }
            pub fn reserves(&self, _0: impl ::core::borrow::Borrow<types::reserves::Param0>) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::reserves::Param0>, types::reserves::Reserves, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Balances", "Reserves", ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0.borrow()), [112u8, 10u8, 241u8, 77u8, 64u8, 187u8, 106u8, 159u8, 13u8, 153u8, 140u8, 178u8, 182u8, 50u8, 1u8, 55u8, 149u8, 92u8, 196u8, 229u8, 170u8, 106u8, 193u8, 88u8, 255u8, 244u8, 2u8, 193u8, 62u8, 235u8, 204u8, 91u8, ]) }
            pub fn holds_iter(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::holds::Holds, (), ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Balances", "Holds", (), [37u8, 176u8, 2u8, 18u8, 109u8, 26u8, 66u8, 81u8, 28u8, 104u8, 149u8, 117u8, 119u8, 114u8, 196u8, 35u8, 172u8, 155u8, 66u8, 195u8, 98u8, 37u8, 134u8, 22u8, 106u8, 221u8, 215u8, 97u8, 25u8, 28u8, 21u8, 206u8, ]) }
            pub fn holds(&self, _0: impl ::core::borrow::Borrow<types::holds::Param0>) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::holds::Param0>, types::holds::Holds, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Balances", "Holds", ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0.borrow()), [37u8, 176u8, 2u8, 18u8, 109u8, 26u8, 66u8, 81u8, 28u8, 104u8, 149u8, 117u8, 119u8, 114u8, 196u8, 35u8, 172u8, 155u8, 66u8, 195u8, 98u8, 37u8, 134u8, 22u8, 106u8, 221u8, 215u8, 97u8, 25u8, 28u8, 21u8, 206u8, ]) }
            pub fn freezes_iter(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::freezes::Freezes, (), ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Balances", "Freezes", (), [69u8, 49u8, 165u8, 76u8, 135u8, 142u8, 179u8, 118u8, 50u8, 109u8, 53u8, 112u8, 110u8, 94u8, 30u8, 93u8, 173u8, 38u8, 27u8, 142u8, 19u8, 5u8, 163u8, 4u8, 68u8, 218u8, 179u8, 224u8, 118u8, 218u8, 115u8, 64u8, ]) }
            pub fn freezes(&self, _0: impl ::core::borrow::Borrow<types::freezes::Param0>) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::freezes::Param0>, types::freezes::Freezes, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Balances", "Freezes", ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0.borrow()), [69u8, 49u8, 165u8, 76u8, 135u8, 142u8, 179u8, 118u8, 50u8, 109u8, 53u8, 112u8, 110u8, 94u8, 30u8, 93u8, 173u8, 38u8, 27u8, 142u8, 19u8, 5u8, 163u8, 4u8, 68u8, 218u8, 179u8, 224u8, 118u8, 218u8, 115u8, 64u8, ]) }
        }
    }
    pub mod constants {
        use super::runtime_types;
        pub struct ConstantsApi;
        impl ConstantsApi {
            pub fn existential_deposit(&self) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<::core::primitive::u128> { ::subxt::ext::subxt_core::constants::address::StaticAddress::new_static("Balances", "ExistentialDeposit", [84u8, 157u8, 140u8, 4u8, 93u8, 57u8, 29u8, 133u8, 105u8, 200u8, 214u8, 27u8, 144u8, 208u8, 218u8, 160u8, 130u8, 109u8, 101u8, 54u8, 210u8, 136u8, 71u8, 63u8, 49u8, 237u8, 234u8, 15u8, 178u8, 98u8, 148u8, 156u8, ]) }
            pub fn max_locks(&self) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<::core::primitive::u32> { ::subxt::ext::subxt_core::constants::address::StaticAddress::new_static("Balances", "MaxLocks", [98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8, 125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8, 178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8, 145u8, ]) }
            pub fn max_reserves(&self) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<::core::primitive::u32> { ::subxt::ext::subxt_core::constants::address::StaticAddress::new_static("Balances", "MaxReserves", [98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8, 125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8, 178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8, 145u8, ]) }
            pub fn max_freezes(&self) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<::core::primitive::u32> { ::subxt::ext::subxt_core::constants::address::StaticAddress::new_static("Balances", "MaxFreezes", [98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8, 125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8, 178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8, 145u8, ]) }
        }
    }
}
pub mod transaction_payment {
    use super::root_mod;
    use super::runtime_types;
    pub type Event = runtime_types::pallet_transaction_payment::pallet::Event;
    pub mod events {
        use super::runtime_types;
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct TransactionFeePaid {
            pub who: transaction_fee_paid::Who,
            pub actual_fee: transaction_fee_paid::ActualFee,
            pub tip: transaction_fee_paid::Tip,
        }
        pub mod transaction_fee_paid {
            use super::runtime_types;
            pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type ActualFee = ::core::primitive::u128;
            pub type Tip = ::core::primitive::u128;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for TransactionFeePaid {
            const PALLET: &'static str = "TransactionPayment";
            const EVENT: &'static str = "TransactionFeePaid";
        }
    }
    pub mod storage {
        use super::runtime_types;
        pub mod types {
            use super::runtime_types;
            pub mod next_fee_multiplier {
                use super::runtime_types;
                pub type NextFeeMultiplier = runtime_types::sp_arithmetic::fixed_point::FixedU128;
            }
            pub mod storage_version {
                use super::runtime_types;
                pub type StorageVersion = runtime_types::pallet_transaction_payment::Releases;
            }
        }
        pub struct StorageApi;
        impl StorageApi {
            pub fn next_fee_multiplier(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::next_fee_multiplier::NextFeeMultiplier, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("TransactionPayment", "NextFeeMultiplier", (), [247u8, 39u8, 81u8, 170u8, 225u8, 226u8, 82u8, 147u8, 34u8, 113u8, 147u8, 213u8, 59u8, 80u8, 139u8, 35u8, 36u8, 196u8, 152u8, 19u8, 9u8, 159u8, 176u8, 79u8, 249u8, 201u8, 170u8, 1u8, 129u8, 79u8, 146u8, 197u8, ]) }
            pub fn storage_version(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::storage_version::StorageVersion, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("TransactionPayment", "StorageVersion", (), [105u8, 243u8, 158u8, 241u8, 159u8, 231u8, 253u8, 6u8, 4u8, 32u8, 85u8, 178u8, 126u8, 31u8, 203u8, 134u8, 154u8, 38u8, 122u8, 155u8, 150u8, 251u8, 174u8, 15u8, 74u8, 134u8, 216u8, 244u8, 168u8, 175u8, 158u8, 144u8, ]) }
        }
    }
    pub mod constants {
        use super::runtime_types;
        pub struct ConstantsApi;
        impl ConstantsApi { pub fn operational_fee_multiplier(&self) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<::core::primitive::u8> { ::subxt::ext::subxt_core::constants::address::StaticAddress::new_static("TransactionPayment", "OperationalFeeMultiplier", [141u8, 130u8, 11u8, 35u8, 226u8, 114u8, 92u8, 179u8, 168u8, 110u8, 28u8, 91u8, 221u8, 64u8, 4u8, 148u8, 201u8, 193u8, 185u8, 66u8, 226u8, 114u8, 97u8, 79u8, 62u8, 212u8, 202u8, 114u8, 237u8, 228u8, 183u8, 165u8, ]) } }
    }
}
pub mod authorship {
    use super::root_mod;
    use super::runtime_types;
    pub mod storage {
        use super::runtime_types;
        pub mod types {
            use super::runtime_types;
            pub mod author {
                use super::runtime_types;
                pub type Author = ::subxt::ext::subxt_core::utils::AccountId32;
            }
        }
        pub struct StorageApi;
        impl StorageApi { pub fn author(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::author::Author, ::subxt::ext::subxt_core::utils::Yes, (), ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Authorship", "Author", (), [247u8, 192u8, 118u8, 227u8, 47u8, 20u8, 203u8, 199u8, 216u8, 87u8, 220u8, 50u8, 166u8, 61u8, 168u8, 213u8, 253u8, 62u8, 202u8, 199u8, 61u8, 192u8, 237u8, 53u8, 22u8, 148u8, 164u8, 245u8, 99u8, 24u8, 146u8, 18u8, ]) } }
    }
}
pub mod collator_selection {
    use super::root_mod;
    use super::runtime_types;
    pub type Error = runtime_types::pallet_collator_selection::pallet::Error;
    pub type Call = runtime_types::pallet_collator_selection::pallet::Call;
    pub mod calls {
        use super::root_mod;
        use super::runtime_types;
        type DispatchError = runtime_types::sp_runtime::DispatchError;
        pub mod types {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct SetInvulnerables {
                pub new: set_invulnerables::New,
            }
            pub mod set_invulnerables {
                use super::runtime_types;
                pub type New = ::subxt::ext::subxt_core::alloc::vec::Vec<::subxt::ext::subxt_core::utils::AccountId32>;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for SetInvulnerables {
                const PALLET: &'static str = "CollatorSelection";
                const CALL: &'static str = "set_invulnerables";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct SetDesiredCandidates {
                pub max: set_desired_candidates::Max,
            }
            pub mod set_desired_candidates {
                use super::runtime_types;
                pub type Max = ::core::primitive::u32;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for SetDesiredCandidates {
                const PALLET: &'static str = "CollatorSelection";
                const CALL: &'static str = "set_desired_candidates";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct SetCandidacyBond {
                pub bond: set_candidacy_bond::Bond,
            }
            pub mod set_candidacy_bond {
                use super::runtime_types;
                pub type Bond = ::core::primitive::u128;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for SetCandidacyBond {
                const PALLET: &'static str = "CollatorSelection";
                const CALL: &'static str = "set_candidacy_bond";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct RegisterAsCandidate;
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for RegisterAsCandidate {
                const PALLET: &'static str = "CollatorSelection";
                const CALL: &'static str = "register_as_candidate";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct LeaveIntent;
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for LeaveIntent {
                const PALLET: &'static str = "CollatorSelection";
                const CALL: &'static str = "leave_intent";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct AddInvulnerable {
                pub who: add_invulnerable::Who,
            }
            pub mod add_invulnerable {
                use super::runtime_types;
                pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for AddInvulnerable {
                const PALLET: &'static str = "CollatorSelection";
                const CALL: &'static str = "add_invulnerable";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct RemoveInvulnerable {
                pub who: remove_invulnerable::Who,
            }
            pub mod remove_invulnerable {
                use super::runtime_types;
                pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for RemoveInvulnerable {
                const PALLET: &'static str = "CollatorSelection";
                const CALL: &'static str = "remove_invulnerable";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct UpdateBond {
                pub new_deposit: update_bond::NewDeposit,
            }
            pub mod update_bond {
                use super::runtime_types;
                pub type NewDeposit = ::core::primitive::u128;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for UpdateBond {
                const PALLET: &'static str = "CollatorSelection";
                const CALL: &'static str = "update_bond";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct TakeCandidateSlot {
                pub deposit: take_candidate_slot::Deposit,
                pub target: take_candidate_slot::Target,
            }
            pub mod take_candidate_slot {
                use super::runtime_types;
                pub type Deposit = ::core::primitive::u128;
                pub type Target = ::subxt::ext::subxt_core::utils::AccountId32;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for TakeCandidateSlot {
                const PALLET: &'static str = "CollatorSelection";
                const CALL: &'static str = "take_candidate_slot";
            }
        }
        pub struct TransactionApi;
        impl TransactionApi {
            pub fn set_invulnerables(&self, new: types::set_invulnerables::New) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::SetInvulnerables> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("CollatorSelection", "set_invulnerables", types::SetInvulnerables { new }, [113u8, 217u8, 14u8, 48u8, 6u8, 198u8, 8u8, 170u8, 8u8, 237u8, 230u8, 184u8, 17u8, 181u8, 15u8, 126u8, 117u8, 3u8, 208u8, 215u8, 40u8, 16u8, 150u8, 162u8, 37u8, 196u8, 235u8, 36u8, 247u8, 24u8, 187u8, 17u8, ]) }
            pub fn set_desired_candidates(&self, max: types::set_desired_candidates::Max) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::SetDesiredCandidates> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("CollatorSelection", "set_desired_candidates", types::SetDesiredCandidates { max }, [174u8, 44u8, 232u8, 155u8, 228u8, 219u8, 239u8, 75u8, 86u8, 150u8, 135u8, 214u8, 58u8, 9u8, 25u8, 133u8, 245u8, 101u8, 85u8, 246u8, 15u8, 248u8, 165u8, 87u8, 88u8, 28u8, 10u8, 196u8, 86u8, 89u8, 28u8, 165u8, ]) }
            pub fn set_candidacy_bond(&self, bond: types::set_candidacy_bond::Bond) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::SetCandidacyBond> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("CollatorSelection", "set_candidacy_bond", types::SetCandidacyBond { bond }, [250u8, 4u8, 185u8, 228u8, 101u8, 223u8, 49u8, 44u8, 172u8, 148u8, 216u8, 242u8, 192u8, 88u8, 228u8, 59u8, 225u8, 222u8, 171u8, 40u8, 23u8, 1u8, 46u8, 183u8, 189u8, 191u8, 156u8, 12u8, 218u8, 116u8, 76u8, 59u8, ]) }
            pub fn register_as_candidate(&self) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::RegisterAsCandidate> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("CollatorSelection", "register_as_candidate", types::RegisterAsCandidate {}, [69u8, 222u8, 214u8, 106u8, 105u8, 168u8, 82u8, 239u8, 158u8, 117u8, 224u8, 89u8, 228u8, 51u8, 221u8, 244u8, 88u8, 63u8, 72u8, 119u8, 224u8, 111u8, 93u8, 39u8, 18u8, 66u8, 72u8, 105u8, 70u8, 66u8, 178u8, 173u8, ]) }
            pub fn leave_intent(&self) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::LeaveIntent> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("CollatorSelection", "leave_intent", types::LeaveIntent {}, [126u8, 57u8, 10u8, 67u8, 120u8, 229u8, 70u8, 23u8, 154u8, 215u8, 226u8, 178u8, 203u8, 152u8, 195u8, 177u8, 157u8, 158u8, 40u8, 17u8, 93u8, 225u8, 253u8, 217u8, 48u8, 165u8, 55u8, 79u8, 43u8, 123u8, 193u8, 147u8, ]) }
            pub fn add_invulnerable(&self, who: types::add_invulnerable::Who) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::AddInvulnerable> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("CollatorSelection", "add_invulnerable", types::AddInvulnerable { who }, [115u8, 109u8, 38u8, 19u8, 81u8, 194u8, 124u8, 140u8, 239u8, 23u8, 85u8, 62u8, 241u8, 83u8, 11u8, 241u8, 14u8, 34u8, 206u8, 63u8, 104u8, 78u8, 96u8, 182u8, 173u8, 198u8, 230u8, 107u8, 102u8, 6u8, 164u8, 75u8, ]) }
            pub fn remove_invulnerable(&self, who: types::remove_invulnerable::Who) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::RemoveInvulnerable> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("CollatorSelection", "remove_invulnerable", types::RemoveInvulnerable { who }, [103u8, 146u8, 23u8, 136u8, 61u8, 65u8, 172u8, 157u8, 216u8, 200u8, 119u8, 28u8, 189u8, 215u8, 13u8, 100u8, 102u8, 13u8, 94u8, 12u8, 78u8, 156u8, 149u8, 74u8, 126u8, 118u8, 127u8, 49u8, 129u8, 2u8, 12u8, 118u8, ]) }
            pub fn update_bond(&self, new_deposit: types::update_bond::NewDeposit) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::UpdateBond> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("CollatorSelection", "update_bond", types::UpdateBond { new_deposit }, [47u8, 184u8, 193u8, 220u8, 160u8, 1u8, 253u8, 203u8, 8u8, 142u8, 43u8, 151u8, 190u8, 138u8, 201u8, 174u8, 233u8, 112u8, 200u8, 247u8, 251u8, 94u8, 23u8, 224u8, 150u8, 179u8, 190u8, 140u8, 199u8, 50u8, 2u8, 249u8, ]) }
            pub fn take_candidate_slot(&self, deposit: types::take_candidate_slot::Deposit, target: types::take_candidate_slot::Target) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::TakeCandidateSlot> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("CollatorSelection", "take_candidate_slot", types::TakeCandidateSlot { deposit, target }, [48u8, 150u8, 189u8, 206u8, 199u8, 196u8, 173u8, 3u8, 206u8, 10u8, 50u8, 160u8, 15u8, 53u8, 189u8, 126u8, 154u8, 36u8, 90u8, 66u8, 235u8, 12u8, 107u8, 44u8, 117u8, 33u8, 207u8, 194u8, 251u8, 194u8, 224u8, 80u8, ]) }
        }
    }
    pub type Event = runtime_types::pallet_collator_selection::pallet::Event;
    pub mod events {
        use super::runtime_types;
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct NewInvulnerables {
            pub invulnerables: new_invulnerables::Invulnerables,
        }
        pub mod new_invulnerables {
            use super::runtime_types;
            pub type Invulnerables = ::subxt::ext::subxt_core::alloc::vec::Vec<::subxt::ext::subxt_core::utils::AccountId32>;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for NewInvulnerables {
            const PALLET: &'static str = "CollatorSelection";
            const EVENT: &'static str = "NewInvulnerables";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct InvulnerableAdded {
            pub account_id: invulnerable_added::AccountId,
        }
        pub mod invulnerable_added {
            use super::runtime_types;
            pub type AccountId = ::subxt::ext::subxt_core::utils::AccountId32;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for InvulnerableAdded {
            const PALLET: &'static str = "CollatorSelection";
            const EVENT: &'static str = "InvulnerableAdded";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct InvulnerableRemoved {
            pub account_id: invulnerable_removed::AccountId,
        }
        pub mod invulnerable_removed {
            use super::runtime_types;
            pub type AccountId = ::subxt::ext::subxt_core::utils::AccountId32;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for InvulnerableRemoved {
            const PALLET: &'static str = "CollatorSelection";
            const EVENT: &'static str = "InvulnerableRemoved";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct NewDesiredCandidates {
            pub desired_candidates: new_desired_candidates::DesiredCandidates,
        }
        pub mod new_desired_candidates {
            use super::runtime_types;
            pub type DesiredCandidates = ::core::primitive::u32;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for NewDesiredCandidates {
            const PALLET: &'static str = "CollatorSelection";
            const EVENT: &'static str = "NewDesiredCandidates";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct NewCandidacyBond {
            pub bond_amount: new_candidacy_bond::BondAmount,
        }
        pub mod new_candidacy_bond {
            use super::runtime_types;
            pub type BondAmount = ::core::primitive::u128;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for NewCandidacyBond {
            const PALLET: &'static str = "CollatorSelection";
            const EVENT: &'static str = "NewCandidacyBond";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct CandidateAdded {
            pub account_id: candidate_added::AccountId,
            pub deposit: candidate_added::Deposit,
        }
        pub mod candidate_added {
            use super::runtime_types;
            pub type AccountId = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type Deposit = ::core::primitive::u128;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for CandidateAdded {
            const PALLET: &'static str = "CollatorSelection";
            const EVENT: &'static str = "CandidateAdded";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct CandidateBondUpdated {
            pub account_id: candidate_bond_updated::AccountId,
            pub deposit: candidate_bond_updated::Deposit,
        }
        pub mod candidate_bond_updated {
            use super::runtime_types;
            pub type AccountId = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type Deposit = ::core::primitive::u128;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for CandidateBondUpdated {
            const PALLET: &'static str = "CollatorSelection";
            const EVENT: &'static str = "CandidateBondUpdated";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct CandidateRemoved {
            pub account_id: candidate_removed::AccountId,
        }
        pub mod candidate_removed {
            use super::runtime_types;
            pub type AccountId = ::subxt::ext::subxt_core::utils::AccountId32;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for CandidateRemoved {
            const PALLET: &'static str = "CollatorSelection";
            const EVENT: &'static str = "CandidateRemoved";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct CandidateReplaced {
            pub old: candidate_replaced::Old,
            pub new: candidate_replaced::New,
            pub deposit: candidate_replaced::Deposit,
        }
        pub mod candidate_replaced {
            use super::runtime_types;
            pub type Old = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type New = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type Deposit = ::core::primitive::u128;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for CandidateReplaced {
            const PALLET: &'static str = "CollatorSelection";
            const EVENT: &'static str = "CandidateReplaced";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct InvalidInvulnerableSkipped {
            pub account_id: invalid_invulnerable_skipped::AccountId,
        }
        pub mod invalid_invulnerable_skipped {
            use super::runtime_types;
            pub type AccountId = ::subxt::ext::subxt_core::utils::AccountId32;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for InvalidInvulnerableSkipped {
            const PALLET: &'static str = "CollatorSelection";
            const EVENT: &'static str = "InvalidInvulnerableSkipped";
        }
    }
    pub mod storage {
        use super::runtime_types;
        pub mod types {
            use super::runtime_types;
            pub mod invulnerables {
                use super::runtime_types;
                pub type Invulnerables = runtime_types::bounded_collections::bounded_vec::BoundedVec<::subxt::ext::subxt_core::utils::AccountId32>;
            }
            pub mod candidate_list {
                use super::runtime_types;
                pub type CandidateList = runtime_types::bounded_collections::bounded_vec::BoundedVec<runtime_types::pallet_collator_selection::pallet::CandidateInfo<::subxt::ext::subxt_core::utils::AccountId32, ::core::primitive::u128>>;
            }
            pub mod last_authored_block {
                use super::runtime_types;
                pub type LastAuthoredBlock = ::core::primitive::u32;
                pub type Param0 = ::subxt::ext::subxt_core::utils::AccountId32;
            }
            pub mod desired_candidates {
                use super::runtime_types;
                pub type DesiredCandidates = ::core::primitive::u32;
            }
            pub mod candidacy_bond {
                use super::runtime_types;
                pub type CandidacyBond = ::core::primitive::u128;
            }
        }
        pub struct StorageApi;
        impl StorageApi {
            pub fn invulnerables(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::invulnerables::Invulnerables, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("CollatorSelection", "Invulnerables", (), [109u8, 180u8, 25u8, 41u8, 152u8, 158u8, 186u8, 214u8, 89u8, 222u8, 103u8, 14u8, 91u8, 3u8, 65u8, 6u8, 255u8, 62u8, 47u8, 255u8, 132u8, 164u8, 217u8, 200u8, 130u8, 29u8, 168u8, 23u8, 81u8, 217u8, 35u8, 123u8, ]) }
            pub fn candidate_list(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::candidate_list::CandidateList, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("CollatorSelection", "CandidateList", (), [77u8, 195u8, 89u8, 139u8, 79u8, 111u8, 151u8, 215u8, 19u8, 152u8, 67u8, 49u8, 74u8, 76u8, 3u8, 60u8, 51u8, 140u8, 6u8, 134u8, 159u8, 55u8, 196u8, 57u8, 189u8, 31u8, 219u8, 218u8, 164u8, 189u8, 196u8, 60u8, ]) }
            pub fn last_authored_block_iter(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::last_authored_block::LastAuthoredBlock, (), ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("CollatorSelection", "LastAuthoredBlock", (), [176u8, 170u8, 165u8, 244u8, 101u8, 126u8, 24u8, 132u8, 228u8, 138u8, 72u8, 241u8, 144u8, 100u8, 79u8, 112u8, 9u8, 46u8, 210u8, 80u8, 12u8, 126u8, 32u8, 214u8, 26u8, 171u8, 155u8, 3u8, 233u8, 22u8, 164u8, 25u8, ]) }
            pub fn last_authored_block(&self, _0: impl ::core::borrow::Borrow<types::last_authored_block::Param0>) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::last_authored_block::Param0>, types::last_authored_block::LastAuthoredBlock, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("CollatorSelection", "LastAuthoredBlock", ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0.borrow()), [176u8, 170u8, 165u8, 244u8, 101u8, 126u8, 24u8, 132u8, 228u8, 138u8, 72u8, 241u8, 144u8, 100u8, 79u8, 112u8, 9u8, 46u8, 210u8, 80u8, 12u8, 126u8, 32u8, 214u8, 26u8, 171u8, 155u8, 3u8, 233u8, 22u8, 164u8, 25u8, ]) }
            pub fn desired_candidates(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::desired_candidates::DesiredCandidates, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("CollatorSelection", "DesiredCandidates", (), [69u8, 199u8, 130u8, 132u8, 10u8, 127u8, 204u8, 220u8, 59u8, 107u8, 96u8, 180u8, 42u8, 235u8, 14u8, 126u8, 231u8, 242u8, 162u8, 126u8, 63u8, 223u8, 15u8, 250u8, 22u8, 210u8, 54u8, 34u8, 235u8, 191u8, 250u8, 21u8, ]) }
            pub fn candidacy_bond(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::candidacy_bond::CandidacyBond, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("CollatorSelection", "CandidacyBond", (), [71u8, 134u8, 156u8, 102u8, 201u8, 83u8, 240u8, 251u8, 189u8, 213u8, 211u8, 182u8, 126u8, 122u8, 41u8, 174u8, 105u8, 29u8, 216u8, 23u8, 255u8, 55u8, 245u8, 187u8, 234u8, 234u8, 178u8, 155u8, 145u8, 49u8, 196u8, 214u8, ]) }
        }
    }
}
pub mod session {
    use super::root_mod;
    use super::runtime_types;
    pub type Error = runtime_types::pallet_session::pallet::Error;
    pub type Call = runtime_types::pallet_session::pallet::Call;
    pub mod calls {
        use super::root_mod;
        use super::runtime_types;
        type DispatchError = runtime_types::sp_runtime::DispatchError;
        pub mod types {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct SetKeys {
                pub keys: set_keys::Keys,
                pub proof: set_keys::Proof,
            }
            pub mod set_keys {
                use super::runtime_types;
                pub type Keys = runtime_types::people_rococo_runtime::SessionKeys;
                pub type Proof = ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for SetKeys {
                const PALLET: &'static str = "Session";
                const CALL: &'static str = "set_keys";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct PurgeKeys;
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for PurgeKeys {
                const PALLET: &'static str = "Session";
                const CALL: &'static str = "purge_keys";
            }
        }
        pub struct TransactionApi;
        impl TransactionApi {
            pub fn set_keys(&self, keys: types::set_keys::Keys, proof: types::set_keys::Proof) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::SetKeys> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Session", "set_keys", types::SetKeys { keys, proof }, [219u8, 63u8, 235u8, 242u8, 176u8, 248u8, 204u8, 20u8, 121u8, 176u8, 105u8, 242u8, 190u8, 124u8, 153u8, 219u8, 12u8, 224u8, 196u8, 18u8, 183u8, 159u8, 33u8, 97u8, 44u8, 64u8, 0u8, 10u8, 52u8, 181u8, 70u8, 206u8, ]) }
            pub fn purge_keys(&self) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::PurgeKeys> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Session", "purge_keys", types::PurgeKeys {}, [215u8, 204u8, 146u8, 236u8, 32u8, 78u8, 198u8, 79u8, 85u8, 214u8, 15u8, 151u8, 158u8, 31u8, 146u8, 119u8, 119u8, 204u8, 151u8, 169u8, 226u8, 67u8, 217u8, 39u8, 241u8, 245u8, 203u8, 240u8, 203u8, 172u8, 16u8, 209u8, ]) }
        }
    }
    pub type Event = runtime_types::pallet_session::pallet::Event;
    pub mod events {
        use super::runtime_types;
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct NewSession {
            pub session_index: new_session::SessionIndex,
        }
        pub mod new_session {
            use super::runtime_types;
            pub type SessionIndex = ::core::primitive::u32;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for NewSession {
            const PALLET: &'static str = "Session";
            const EVENT: &'static str = "NewSession";
        }
    }
    pub mod storage {
        use super::runtime_types;
        pub mod types {
            use super::runtime_types;
            pub mod validators {
                use super::runtime_types;
                pub type Validators = ::subxt::ext::subxt_core::alloc::vec::Vec<::subxt::ext::subxt_core::utils::AccountId32>;
            }
            pub mod current_index {
                use super::runtime_types;
                pub type CurrentIndex = ::core::primitive::u32;
            }
            pub mod queued_changed {
                use super::runtime_types;
                pub type QueuedChanged = ::core::primitive::bool;
            }
            pub mod queued_keys {
                use super::runtime_types;
                pub type QueuedKeys = ::subxt::ext::subxt_core::alloc::vec::Vec<(::subxt::ext::subxt_core::utils::AccountId32, runtime_types::people_rococo_runtime::SessionKeys,)>;
            }
            pub mod disabled_validators {
                use super::runtime_types;
                pub type DisabledValidators = ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u32>;
            }
            pub mod next_keys {
                use super::runtime_types;
                pub type NextKeys = runtime_types::people_rococo_runtime::SessionKeys;
                pub type Param0 = ::subxt::ext::subxt_core::utils::AccountId32;
            }
            pub mod key_owner {
                use super::runtime_types;
                pub type KeyOwner = ::subxt::ext::subxt_core::utils::AccountId32;
                pub type Param0 = runtime_types::sp_core::crypto::KeyTypeId;
                pub type Param1 = [::core::primitive::u8];
            }
        }
        pub struct StorageApi;
        impl StorageApi {
            pub fn validators(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::validators::Validators, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Session", "Validators", (), [50u8, 86u8, 154u8, 222u8, 249u8, 209u8, 156u8, 22u8, 155u8, 25u8, 133u8, 194u8, 210u8, 50u8, 38u8, 28u8, 139u8, 201u8, 90u8, 139u8, 115u8, 12u8, 12u8, 141u8, 4u8, 178u8, 201u8, 241u8, 223u8, 234u8, 6u8, 86u8, ]) }
            pub fn current_index(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::current_index::CurrentIndex, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Session", "CurrentIndex", (), [167u8, 151u8, 125u8, 150u8, 159u8, 21u8, 78u8, 217u8, 237u8, 183u8, 135u8, 65u8, 187u8, 114u8, 188u8, 206u8, 16u8, 32u8, 69u8, 208u8, 134u8, 159u8, 232u8, 224u8, 243u8, 27u8, 31u8, 166u8, 145u8, 44u8, 221u8, 230u8, ]) }
            pub fn queued_changed(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::queued_changed::QueuedChanged, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Session", "QueuedChanged", (), [184u8, 137u8, 224u8, 137u8, 31u8, 236u8, 95u8, 164u8, 102u8, 225u8, 198u8, 227u8, 140u8, 37u8, 113u8, 57u8, 59u8, 4u8, 202u8, 102u8, 117u8, 36u8, 226u8, 64u8, 113u8, 141u8, 199u8, 111u8, 99u8, 144u8, 198u8, 153u8, ]) }
            pub fn queued_keys(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::queued_keys::QueuedKeys, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Session", "QueuedKeys", (), [205u8, 110u8, 116u8, 201u8, 29u8, 220u8, 3u8, 147u8, 3u8, 236u8, 73u8, 108u8, 108u8, 173u8, 76u8, 44u8, 102u8, 69u8, 47u8, 90u8, 185u8, 162u8, 57u8, 23u8, 210u8, 45u8, 18u8, 242u8, 10u8, 95u8, 67u8, 109u8, ]) }
            pub fn disabled_validators(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::disabled_validators::DisabledValidators, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Session", "DisabledValidators", (), [213u8, 19u8, 168u8, 234u8, 187u8, 200u8, 180u8, 97u8, 234u8, 189u8, 36u8, 233u8, 158u8, 184u8, 45u8, 35u8, 129u8, 213u8, 133u8, 8u8, 104u8, 183u8, 46u8, 68u8, 154u8, 240u8, 132u8, 22u8, 247u8, 11u8, 54u8, 221u8, ]) }
            pub fn next_keys_iter(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::next_keys::NextKeys, (), (), ::subxt::ext::subxt_core::utils::Yes> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Session", "NextKeys", (), [45u8, 92u8, 45u8, 21u8, 150u8, 181u8, 197u8, 56u8, 229u8, 146u8, 183u8, 210u8, 56u8, 197u8, 9u8, 202u8, 226u8, 183u8, 110u8, 173u8, 100u8, 75u8, 248u8, 207u8, 215u8, 163u8, 13u8, 113u8, 222u8, 128u8, 18u8, 192u8, ]) }
            pub fn next_keys(&self, _0: impl ::core::borrow::Borrow<types::next_keys::Param0>) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::next_keys::Param0>, types::next_keys::NextKeys, ::subxt::ext::subxt_core::utils::Yes, (), ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Session", "NextKeys", ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0.borrow()), [45u8, 92u8, 45u8, 21u8, 150u8, 181u8, 197u8, 56u8, 229u8, 146u8, 183u8, 210u8, 56u8, 197u8, 9u8, 202u8, 226u8, 183u8, 110u8, 173u8, 100u8, 75u8, 248u8, 207u8, 215u8, 163u8, 13u8, 113u8, 222u8, 128u8, 18u8, 192u8, ]) }
            pub fn key_owner_iter(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::key_owner::KeyOwner, (), (), ::subxt::ext::subxt_core::utils::Yes> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Session", "KeyOwner", (), [217u8, 204u8, 21u8, 114u8, 247u8, 129u8, 32u8, 242u8, 93u8, 91u8, 253u8, 253u8, 248u8, 90u8, 12u8, 202u8, 195u8, 25u8, 18u8, 100u8, 253u8, 109u8, 88u8, 77u8, 217u8, 140u8, 51u8, 40u8, 118u8, 35u8, 107u8, 206u8, ]) }
            pub fn key_owner_iter1(&self, _0: impl ::core::borrow::Borrow<types::key_owner::Param0>) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::key_owner::Param0>, types::key_owner::KeyOwner, (), (), ::subxt::ext::subxt_core::utils::Yes> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Session", "KeyOwner", ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0.borrow()), [217u8, 204u8, 21u8, 114u8, 247u8, 129u8, 32u8, 242u8, 93u8, 91u8, 253u8, 253u8, 248u8, 90u8, 12u8, 202u8, 195u8, 25u8, 18u8, 100u8, 253u8, 109u8, 88u8, 77u8, 217u8, 140u8, 51u8, 40u8, 118u8, 35u8, 107u8, 206u8, ]) }
            pub fn key_owner(&self, _0: impl ::core::borrow::Borrow<types::key_owner::Param0>, _1: impl ::core::borrow::Borrow<types::key_owner::Param1>) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::key_owner::Param0>, ::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::key_owner::Param1>,), types::key_owner::KeyOwner, ::subxt::ext::subxt_core::utils::Yes, (), ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Session", "KeyOwner", (::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0.borrow()), ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_1.borrow()),), [217u8, 204u8, 21u8, 114u8, 247u8, 129u8, 32u8, 242u8, 93u8, 91u8, 253u8, 253u8, 248u8, 90u8, 12u8, 202u8, 195u8, 25u8, 18u8, 100u8, 253u8, 109u8, 88u8, 77u8, 217u8, 140u8, 51u8, 40u8, 118u8, 35u8, 107u8, 206u8, ]) }
        }
    }
}
pub mod aura {
    use super::root_mod;
    use super::runtime_types;
    pub mod storage {
        use super::runtime_types;
        pub mod types {
            use super::runtime_types;
            pub mod authorities {
                use super::runtime_types;
                pub type Authorities = runtime_types::bounded_collections::bounded_vec::BoundedVec<runtime_types::sp_consensus_aura::sr25519::app_sr25519::Public>;
            }
            pub mod current_slot {
                use super::runtime_types;
                pub type CurrentSlot = runtime_types::sp_consensus_slots::Slot;
            }
        }
        pub struct StorageApi;
        impl StorageApi {
            pub fn authorities(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::authorities::Authorities, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Aura", "Authorities", (), [95u8, 52u8, 203u8, 53u8, 254u8, 107u8, 134u8, 122u8, 95u8, 253u8, 51u8, 137u8, 142u8, 106u8, 237u8, 248u8, 159u8, 80u8, 41u8, 233u8, 137u8, 133u8, 13u8, 217u8, 176u8, 88u8, 132u8, 199u8, 241u8, 47u8, 125u8, 27u8, ]) }
            pub fn current_slot(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::current_slot::CurrentSlot, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Aura", "CurrentSlot", (), [112u8, 199u8, 115u8, 248u8, 217u8, 242u8, 45u8, 231u8, 178u8, 53u8, 236u8, 167u8, 219u8, 238u8, 81u8, 243u8, 39u8, 140u8, 68u8, 19u8, 201u8, 169u8, 211u8, 133u8, 135u8, 213u8, 150u8, 105u8, 60u8, 252u8, 43u8, 57u8, ]) }
        }
    }
    pub mod constants {
        use super::runtime_types;
        pub struct ConstantsApi;
        impl ConstantsApi { pub fn slot_duration(&self) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<::core::primitive::u64> { ::subxt::ext::subxt_core::constants::address::StaticAddress::new_static("Aura", "SlotDuration", [128u8, 214u8, 205u8, 242u8, 181u8, 142u8, 124u8, 231u8, 190u8, 146u8, 59u8, 226u8, 157u8, 101u8, 103u8, 117u8, 249u8, 65u8, 18u8, 191u8, 103u8, 119u8, 53u8, 85u8, 81u8, 96u8, 220u8, 42u8, 184u8, 239u8, 42u8, 246u8, ]) } }
    }
}
pub mod aura_ext {
    use super::root_mod;
    use super::runtime_types;
    pub mod storage {
        use super::runtime_types;
        pub mod types {
            use super::runtime_types;
            pub mod authorities {
                use super::runtime_types;
                pub type Authorities = runtime_types::bounded_collections::bounded_vec::BoundedVec<runtime_types::sp_consensus_aura::sr25519::app_sr25519::Public>;
            }
            pub mod slot_info {
                use super::runtime_types;
                pub type SlotInfo = (runtime_types::sp_consensus_slots::Slot, ::core::primitive::u32,);
            }
        }
        pub struct StorageApi;
        impl StorageApi {
            pub fn authorities(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::authorities::Authorities, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("AuraExt", "Authorities", (), [95u8, 52u8, 203u8, 53u8, 254u8, 107u8, 134u8, 122u8, 95u8, 253u8, 51u8, 137u8, 142u8, 106u8, 237u8, 248u8, 159u8, 80u8, 41u8, 233u8, 137u8, 133u8, 13u8, 217u8, 176u8, 88u8, 132u8, 199u8, 241u8, 47u8, 125u8, 27u8, ]) }
            pub fn slot_info(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::slot_info::SlotInfo, ::subxt::ext::subxt_core::utils::Yes, (), ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("AuraExt", "SlotInfo", (), [135u8, 135u8, 71u8, 123u8, 102u8, 223u8, 215u8, 76u8, 183u8, 169u8, 108u8, 60u8, 122u8, 5u8, 24u8, 201u8, 96u8, 59u8, 132u8, 95u8, 253u8, 100u8, 148u8, 184u8, 133u8, 146u8, 101u8, 201u8, 91u8, 30u8, 76u8, 169u8, ]) }
        }
    }
}
pub mod xcmp_queue {
    use super::root_mod;
    use super::runtime_types;
    pub type Error = runtime_types::cumulus_pallet_xcmp_queue::pallet::Error;
    pub type Call = runtime_types::cumulus_pallet_xcmp_queue::pallet::Call;
    pub mod calls {
        use super::root_mod;
        use super::runtime_types;
        type DispatchError = runtime_types::sp_runtime::DispatchError;
        pub mod types {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct SuspendXcmExecution;
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for SuspendXcmExecution {
                const PALLET: &'static str = "XcmpQueue";
                const CALL: &'static str = "suspend_xcm_execution";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct ResumeXcmExecution;
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for ResumeXcmExecution {
                const PALLET: &'static str = "XcmpQueue";
                const CALL: &'static str = "resume_xcm_execution";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct UpdateSuspendThreshold {
                pub new: update_suspend_threshold::New,
            }
            pub mod update_suspend_threshold {
                use super::runtime_types;
                pub type New = ::core::primitive::u32;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for UpdateSuspendThreshold {
                const PALLET: &'static str = "XcmpQueue";
                const CALL: &'static str = "update_suspend_threshold";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct UpdateDropThreshold {
                pub new: update_drop_threshold::New,
            }
            pub mod update_drop_threshold {
                use super::runtime_types;
                pub type New = ::core::primitive::u32;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for UpdateDropThreshold {
                const PALLET: &'static str = "XcmpQueue";
                const CALL: &'static str = "update_drop_threshold";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct UpdateResumeThreshold {
                pub new: update_resume_threshold::New,
            }
            pub mod update_resume_threshold {
                use super::runtime_types;
                pub type New = ::core::primitive::u32;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for UpdateResumeThreshold {
                const PALLET: &'static str = "XcmpQueue";
                const CALL: &'static str = "update_resume_threshold";
            }
        }
        pub struct TransactionApi;
        impl TransactionApi {
            pub fn suspend_xcm_execution(&self) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::SuspendXcmExecution> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("XcmpQueue", "suspend_xcm_execution", types::SuspendXcmExecution {}, [54u8, 120u8, 33u8, 251u8, 74u8, 56u8, 29u8, 76u8, 104u8, 218u8, 115u8, 198u8, 148u8, 237u8, 9u8, 191u8, 241u8, 48u8, 33u8, 24u8, 60u8, 144u8, 22u8, 78u8, 58u8, 50u8, 26u8, 188u8, 231u8, 42u8, 201u8, 76u8, ]) }
            pub fn resume_xcm_execution(&self) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::ResumeXcmExecution> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("XcmpQueue", "resume_xcm_execution", types::ResumeXcmExecution {}, [173u8, 231u8, 78u8, 253u8, 108u8, 234u8, 199u8, 124u8, 184u8, 154u8, 95u8, 194u8, 13u8, 77u8, 175u8, 7u8, 7u8, 112u8, 161u8, 72u8, 133u8, 71u8, 63u8, 218u8, 97u8, 226u8, 133u8, 6u8, 93u8, 177u8, 247u8, 109u8, ]) }
            pub fn update_suspend_threshold(&self, new: types::update_suspend_threshold::New) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::UpdateSuspendThreshold> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("XcmpQueue", "update_suspend_threshold", types::UpdateSuspendThreshold { new }, [64u8, 91u8, 172u8, 51u8, 220u8, 174u8, 54u8, 47u8, 57u8, 89u8, 75u8, 39u8, 126u8, 198u8, 143u8, 35u8, 70u8, 125u8, 167u8, 14u8, 17u8, 18u8, 146u8, 222u8, 100u8, 92u8, 81u8, 239u8, 173u8, 43u8, 42u8, 174u8, ]) }
            pub fn update_drop_threshold(&self, new: types::update_drop_threshold::New) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::UpdateDropThreshold> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("XcmpQueue", "update_drop_threshold", types::UpdateDropThreshold { new }, [123u8, 54u8, 12u8, 180u8, 165u8, 198u8, 141u8, 200u8, 149u8, 168u8, 186u8, 237u8, 162u8, 91u8, 89u8, 242u8, 229u8, 16u8, 32u8, 254u8, 59u8, 168u8, 31u8, 134u8, 217u8, 251u8, 0u8, 102u8, 113u8, 194u8, 175u8, 9u8, ]) }
            pub fn update_resume_threshold(&self, new: types::update_resume_threshold::New) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::UpdateResumeThreshold> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("XcmpQueue", "update_resume_threshold", types::UpdateResumeThreshold { new }, [172u8, 136u8, 11u8, 106u8, 42u8, 157u8, 167u8, 183u8, 87u8, 62u8, 182u8, 17u8, 184u8, 59u8, 215u8, 230u8, 18u8, 243u8, 212u8, 34u8, 54u8, 188u8, 95u8, 119u8, 173u8, 20u8, 91u8, 206u8, 212u8, 57u8, 136u8, 77u8, ]) }
        }
    }
    pub type Event = runtime_types::cumulus_pallet_xcmp_queue::pallet::Event;
    pub mod events {
        use super::runtime_types;
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct XcmpMessageSent {
            pub message_hash: xcmp_message_sent::MessageHash,
        }
        pub mod xcmp_message_sent {
            use super::runtime_types;
            pub type MessageHash = [::core::primitive::u8; 32usize];
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for XcmpMessageSent {
            const PALLET: &'static str = "XcmpQueue";
            const EVENT: &'static str = "XcmpMessageSent";
        }
    }
    pub mod storage {
        use super::runtime_types;
        pub mod types {
            use super::runtime_types;
            pub mod inbound_xcmp_suspended {
                use super::runtime_types;
                pub type InboundXcmpSuspended = runtime_types::bounded_collections::bounded_btree_set::BoundedBTreeSet<runtime_types::polkadot_parachain_primitives::primitives::Id>;
            }
            pub mod outbound_xcmp_status {
                use super::runtime_types;
                pub type OutboundXcmpStatus = runtime_types::bounded_collections::bounded_vec::BoundedVec<runtime_types::cumulus_pallet_xcmp_queue::OutboundChannelDetails>;
            }
            pub mod outbound_xcmp_messages {
                use super::runtime_types;
                pub type OutboundXcmpMessages = runtime_types::bounded_collections::weak_bounded_vec::WeakBoundedVec<::core::primitive::u8>;
                pub type Param0 = runtime_types::polkadot_parachain_primitives::primitives::Id;
                pub type Param1 = ::core::primitive::u16;
            }
            pub mod signal_messages {
                use super::runtime_types;
                pub type SignalMessages = runtime_types::bounded_collections::weak_bounded_vec::WeakBoundedVec<::core::primitive::u8>;
                pub type Param0 = runtime_types::polkadot_parachain_primitives::primitives::Id;
            }
            pub mod queue_config {
                use super::runtime_types;
                pub type QueueConfig = runtime_types::cumulus_pallet_xcmp_queue::QueueConfigData;
            }
            pub mod queue_suspended {
                use super::runtime_types;
                pub type QueueSuspended = ::core::primitive::bool;
            }
            pub mod delivery_fee_factor {
                use super::runtime_types;
                pub type DeliveryFeeFactor = runtime_types::sp_arithmetic::fixed_point::FixedU128;
                pub type Param0 = runtime_types::polkadot_parachain_primitives::primitives::Id;
            }
        }
        pub struct StorageApi;
        impl StorageApi {
            pub fn inbound_xcmp_suspended(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::inbound_xcmp_suspended::InboundXcmpSuspended, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("XcmpQueue", "InboundXcmpSuspended", (), [110u8, 23u8, 239u8, 104u8, 136u8, 224u8, 179u8, 180u8, 40u8, 159u8, 54u8, 15u8, 55u8, 111u8, 75u8, 147u8, 131u8, 127u8, 9u8, 57u8, 133u8, 70u8, 175u8, 181u8, 232u8, 49u8, 13u8, 19u8, 59u8, 151u8, 179u8, 215u8, ]) }
            pub fn outbound_xcmp_status(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::outbound_xcmp_status::OutboundXcmpStatus, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("XcmpQueue", "OutboundXcmpStatus", (), [236u8, 81u8, 241u8, 94u8, 247u8, 213u8, 123u8, 240u8, 144u8, 27u8, 39u8, 73u8, 147u8, 85u8, 18u8, 2u8, 249u8, 25u8, 132u8, 158u8, 118u8, 84u8, 2u8, 226u8, 174u8, 94u8, 25u8, 117u8, 86u8, 121u8, 214u8, 32u8, ]) }
            pub fn outbound_xcmp_messages_iter(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::outbound_xcmp_messages::OutboundXcmpMessages, (), ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("XcmpQueue", "OutboundXcmpMessages", (), [163u8, 69u8, 82u8, 238u8, 52u8, 57u8, 181u8, 23u8, 138u8, 75u8, 43u8, 208u8, 209u8, 195u8, 180u8, 199u8, 174u8, 101u8, 28u8, 248u8, 76u8, 190u8, 140u8, 116u8, 251u8, 123u8, 160u8, 119u8, 204u8, 91u8, 59u8, 234u8, ]) }
            pub fn outbound_xcmp_messages_iter1(&self, _0: impl ::core::borrow::Borrow<types::outbound_xcmp_messages::Param0>) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::outbound_xcmp_messages::Param0>, types::outbound_xcmp_messages::OutboundXcmpMessages, (), ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("XcmpQueue", "OutboundXcmpMessages", ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0.borrow()), [163u8, 69u8, 82u8, 238u8, 52u8, 57u8, 181u8, 23u8, 138u8, 75u8, 43u8, 208u8, 209u8, 195u8, 180u8, 199u8, 174u8, 101u8, 28u8, 248u8, 76u8, 190u8, 140u8, 116u8, 251u8, 123u8, 160u8, 119u8, 204u8, 91u8, 59u8, 234u8, ]) }
            pub fn outbound_xcmp_messages(&self, _0: impl ::core::borrow::Borrow<types::outbound_xcmp_messages::Param0>, _1: impl ::core::borrow::Borrow<types::outbound_xcmp_messages::Param1>) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::outbound_xcmp_messages::Param0>, ::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::outbound_xcmp_messages::Param1>,), types::outbound_xcmp_messages::OutboundXcmpMessages, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("XcmpQueue", "OutboundXcmpMessages", (::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0.borrow()), ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_1.borrow()),), [163u8, 69u8, 82u8, 238u8, 52u8, 57u8, 181u8, 23u8, 138u8, 75u8, 43u8, 208u8, 209u8, 195u8, 180u8, 199u8, 174u8, 101u8, 28u8, 248u8, 76u8, 190u8, 140u8, 116u8, 251u8, 123u8, 160u8, 119u8, 204u8, 91u8, 59u8, 234u8, ]) }
            pub fn signal_messages_iter(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::signal_messages::SignalMessages, (), ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("XcmpQueue", "SignalMessages", (), [35u8, 133u8, 54u8, 149u8, 97u8, 64u8, 30u8, 174u8, 154u8, 60u8, 119u8, 92u8, 207u8, 67u8, 151u8, 242u8, 6u8, 128u8, 60u8, 204u8, 15u8, 135u8, 36u8, 234u8, 29u8, 122u8, 220u8, 28u8, 243u8, 152u8, 217u8, 61u8, ]) }
            pub fn signal_messages(&self, _0: impl ::core::borrow::Borrow<types::signal_messages::Param0>) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::signal_messages::Param0>, types::signal_messages::SignalMessages, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("XcmpQueue", "SignalMessages", ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0.borrow()), [35u8, 133u8, 54u8, 149u8, 97u8, 64u8, 30u8, 174u8, 154u8, 60u8, 119u8, 92u8, 207u8, 67u8, 151u8, 242u8, 6u8, 128u8, 60u8, 204u8, 15u8, 135u8, 36u8, 234u8, 29u8, 122u8, 220u8, 28u8, 243u8, 152u8, 217u8, 61u8, ]) }
            pub fn queue_config(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::queue_config::QueueConfig, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("XcmpQueue", "QueueConfig", (), [185u8, 67u8, 247u8, 243u8, 211u8, 232u8, 57u8, 240u8, 237u8, 181u8, 23u8, 114u8, 215u8, 128u8, 193u8, 1u8, 176u8, 53u8, 110u8, 195u8, 148u8, 80u8, 187u8, 143u8, 62u8, 30u8, 143u8, 34u8, 248u8, 109u8, 3u8, 141u8, ]) }
            pub fn queue_suspended(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::queue_suspended::QueueSuspended, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("XcmpQueue", "QueueSuspended", (), [165u8, 66u8, 105u8, 244u8, 113u8, 43u8, 177u8, 252u8, 212u8, 243u8, 143u8, 184u8, 87u8, 51u8, 163u8, 104u8, 29u8, 84u8, 119u8, 74u8, 233u8, 129u8, 203u8, 105u8, 2u8, 101u8, 19u8, 170u8, 69u8, 253u8, 80u8, 132u8, ]) }
            pub fn delivery_fee_factor_iter(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::delivery_fee_factor::DeliveryFeeFactor, (), ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("XcmpQueue", "DeliveryFeeFactor", (), [43u8, 5u8, 63u8, 235u8, 115u8, 155u8, 130u8, 27u8, 75u8, 216u8, 177u8, 135u8, 203u8, 147u8, 167u8, 95u8, 208u8, 188u8, 25u8, 14u8, 84u8, 63u8, 116u8, 41u8, 148u8, 110u8, 115u8, 215u8, 196u8, 36u8, 75u8, 102u8, ]) }
            pub fn delivery_fee_factor(&self, _0: impl ::core::borrow::Borrow<types::delivery_fee_factor::Param0>) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::delivery_fee_factor::Param0>, types::delivery_fee_factor::DeliveryFeeFactor, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("XcmpQueue", "DeliveryFeeFactor", ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0.borrow()), [43u8, 5u8, 63u8, 235u8, 115u8, 155u8, 130u8, 27u8, 75u8, 216u8, 177u8, 135u8, 203u8, 147u8, 167u8, 95u8, 208u8, 188u8, 25u8, 14u8, 84u8, 63u8, 116u8, 41u8, 148u8, 110u8, 115u8, 215u8, 196u8, 36u8, 75u8, 102u8, ]) }
        }
    }
    pub mod constants {
        use super::runtime_types;
        pub struct ConstantsApi;
        impl ConstantsApi {
            pub fn max_inbound_suspended(&self) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<::core::primitive::u32> { ::subxt::ext::subxt_core::constants::address::StaticAddress::new_static("XcmpQueue", "MaxInboundSuspended", [98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8, 125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8, 178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8, 145u8, ]) }
            pub fn max_active_outbound_channels(&self) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<::core::primitive::u32> { ::subxt::ext::subxt_core::constants::address::StaticAddress::new_static("XcmpQueue", "MaxActiveOutboundChannels", [98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8, 125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8, 178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8, 145u8, ]) }
            pub fn max_page_size(&self) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<::core::primitive::u32> { ::subxt::ext::subxt_core::constants::address::StaticAddress::new_static("XcmpQueue", "MaxPageSize", [98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8, 125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8, 178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8, 145u8, ]) }
        }
    }
}
pub mod polkadot_xcm {
    use super::root_mod;
    use super::runtime_types;
    pub type Error = runtime_types::pallet_xcm::pallet::Error;
    pub type Call = runtime_types::pallet_xcm::pallet::Call;
    pub mod calls {
        use super::root_mod;
        use super::runtime_types;
        type DispatchError = runtime_types::sp_runtime::DispatchError;
        pub mod types {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct Send {
                pub dest: ::subxt::ext::subxt_core::alloc::boxed::Box<send::Dest>,
                pub message: ::subxt::ext::subxt_core::alloc::boxed::Box<send::Message>,
            }
            pub mod send {
                use super::runtime_types;
                pub type Dest = runtime_types::xcm::VersionedLocation;
                pub type Message = runtime_types::xcm::VersionedXcm;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for Send {
                const PALLET: &'static str = "PolkadotXcm";
                const CALL: &'static str = "send";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct TeleportAssets {
                pub dest: ::subxt::ext::subxt_core::alloc::boxed::Box<teleport_assets::Dest>,
                pub beneficiary: ::subxt::ext::subxt_core::alloc::boxed::Box<teleport_assets::Beneficiary>,
                pub assets: ::subxt::ext::subxt_core::alloc::boxed::Box<teleport_assets::Assets>,
                pub fee_asset_item: teleport_assets::FeeAssetItem,
            }
            pub mod teleport_assets {
                use super::runtime_types;
                pub type Dest = runtime_types::xcm::VersionedLocation;
                pub type Beneficiary = runtime_types::xcm::VersionedLocation;
                pub type Assets = runtime_types::xcm::VersionedAssets;
                pub type FeeAssetItem = ::core::primitive::u32;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for TeleportAssets {
                const PALLET: &'static str = "PolkadotXcm";
                const CALL: &'static str = "teleport_assets";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct ReserveTransferAssets {
                pub dest: ::subxt::ext::subxt_core::alloc::boxed::Box<reserve_transfer_assets::Dest>,
                pub beneficiary: ::subxt::ext::subxt_core::alloc::boxed::Box<reserve_transfer_assets::Beneficiary>,
                pub assets: ::subxt::ext::subxt_core::alloc::boxed::Box<reserve_transfer_assets::Assets>,
                pub fee_asset_item: reserve_transfer_assets::FeeAssetItem,
            }
            pub mod reserve_transfer_assets {
                use super::runtime_types;
                pub type Dest = runtime_types::xcm::VersionedLocation;
                pub type Beneficiary = runtime_types::xcm::VersionedLocation;
                pub type Assets = runtime_types::xcm::VersionedAssets;
                pub type FeeAssetItem = ::core::primitive::u32;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for ReserveTransferAssets {
                const PALLET: &'static str = "PolkadotXcm";
                const CALL: &'static str = "reserve_transfer_assets";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct Execute {
                pub message: ::subxt::ext::subxt_core::alloc::boxed::Box<execute::Message>,
                pub max_weight: execute::MaxWeight,
            }
            pub mod execute {
                use super::runtime_types;
                pub type Message = runtime_types::xcm::VersionedXcm;
                pub type MaxWeight = runtime_types::sp_weights::weight_v2::Weight;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for Execute {
                const PALLET: &'static str = "PolkadotXcm";
                const CALL: &'static str = "execute";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct ForceXcmVersion {
                pub location: ::subxt::ext::subxt_core::alloc::boxed::Box<force_xcm_version::Location>,
                pub version: force_xcm_version::Version,
            }
            pub mod force_xcm_version {
                use super::runtime_types;
                pub type Location = runtime_types::staging_xcm::v4::location::Location;
                pub type Version = ::core::primitive::u32;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for ForceXcmVersion {
                const PALLET: &'static str = "PolkadotXcm";
                const CALL: &'static str = "force_xcm_version";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct ForceDefaultXcmVersion {
                pub maybe_xcm_version: force_default_xcm_version::MaybeXcmVersion,
            }
            pub mod force_default_xcm_version {
                use super::runtime_types;
                pub type MaybeXcmVersion = ::core::option::Option<::core::primitive::u32>;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for ForceDefaultXcmVersion {
                const PALLET: &'static str = "PolkadotXcm";
                const CALL: &'static str = "force_default_xcm_version";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct ForceSubscribeVersionNotify {
                pub location: ::subxt::ext::subxt_core::alloc::boxed::Box<force_subscribe_version_notify::Location>,
            }
            pub mod force_subscribe_version_notify {
                use super::runtime_types;
                pub type Location = runtime_types::xcm::VersionedLocation;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for ForceSubscribeVersionNotify {
                const PALLET: &'static str = "PolkadotXcm";
                const CALL: &'static str = "force_subscribe_version_notify";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct ForceUnsubscribeVersionNotify {
                pub location: ::subxt::ext::subxt_core::alloc::boxed::Box<force_unsubscribe_version_notify::Location>,
            }
            pub mod force_unsubscribe_version_notify {
                use super::runtime_types;
                pub type Location = runtime_types::xcm::VersionedLocation;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for ForceUnsubscribeVersionNotify {
                const PALLET: &'static str = "PolkadotXcm";
                const CALL: &'static str = "force_unsubscribe_version_notify";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct LimitedReserveTransferAssets {
                pub dest: ::subxt::ext::subxt_core::alloc::boxed::Box<limited_reserve_transfer_assets::Dest>,
                pub beneficiary: ::subxt::ext::subxt_core::alloc::boxed::Box<limited_reserve_transfer_assets::Beneficiary>,
                pub assets: ::subxt::ext::subxt_core::alloc::boxed::Box<limited_reserve_transfer_assets::Assets>,
                pub fee_asset_item: limited_reserve_transfer_assets::FeeAssetItem,
                pub weight_limit: limited_reserve_transfer_assets::WeightLimit,
            }
            pub mod limited_reserve_transfer_assets {
                use super::runtime_types;
                pub type Dest = runtime_types::xcm::VersionedLocation;
                pub type Beneficiary = runtime_types::xcm::VersionedLocation;
                pub type Assets = runtime_types::xcm::VersionedAssets;
                pub type FeeAssetItem = ::core::primitive::u32;
                pub type WeightLimit = runtime_types::xcm::v3::WeightLimit;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for LimitedReserveTransferAssets {
                const PALLET: &'static str = "PolkadotXcm";
                const CALL: &'static str = "limited_reserve_transfer_assets";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct LimitedTeleportAssets {
                pub dest: ::subxt::ext::subxt_core::alloc::boxed::Box<limited_teleport_assets::Dest>,
                pub beneficiary: ::subxt::ext::subxt_core::alloc::boxed::Box<limited_teleport_assets::Beneficiary>,
                pub assets: ::subxt::ext::subxt_core::alloc::boxed::Box<limited_teleport_assets::Assets>,
                pub fee_asset_item: limited_teleport_assets::FeeAssetItem,
                pub weight_limit: limited_teleport_assets::WeightLimit,
            }
            pub mod limited_teleport_assets {
                use super::runtime_types;
                pub type Dest = runtime_types::xcm::VersionedLocation;
                pub type Beneficiary = runtime_types::xcm::VersionedLocation;
                pub type Assets = runtime_types::xcm::VersionedAssets;
                pub type FeeAssetItem = ::core::primitive::u32;
                pub type WeightLimit = runtime_types::xcm::v3::WeightLimit;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for LimitedTeleportAssets {
                const PALLET: &'static str = "PolkadotXcm";
                const CALL: &'static str = "limited_teleport_assets";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct ForceSuspension {
                pub suspended: force_suspension::Suspended,
            }
            pub mod force_suspension {
                use super::runtime_types;
                pub type Suspended = ::core::primitive::bool;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for ForceSuspension {
                const PALLET: &'static str = "PolkadotXcm";
                const CALL: &'static str = "force_suspension";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct TransferAssets {
                pub dest: ::subxt::ext::subxt_core::alloc::boxed::Box<transfer_assets::Dest>,
                pub beneficiary: ::subxt::ext::subxt_core::alloc::boxed::Box<transfer_assets::Beneficiary>,
                pub assets: ::subxt::ext::subxt_core::alloc::boxed::Box<transfer_assets::Assets>,
                pub fee_asset_item: transfer_assets::FeeAssetItem,
                pub weight_limit: transfer_assets::WeightLimit,
            }
            pub mod transfer_assets {
                use super::runtime_types;
                pub type Dest = runtime_types::xcm::VersionedLocation;
                pub type Beneficiary = runtime_types::xcm::VersionedLocation;
                pub type Assets = runtime_types::xcm::VersionedAssets;
                pub type FeeAssetItem = ::core::primitive::u32;
                pub type WeightLimit = runtime_types::xcm::v3::WeightLimit;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for TransferAssets {
                const PALLET: &'static str = "PolkadotXcm";
                const CALL: &'static str = "transfer_assets";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct ClaimAssets {
                pub assets: ::subxt::ext::subxt_core::alloc::boxed::Box<claim_assets::Assets>,
                pub beneficiary: ::subxt::ext::subxt_core::alloc::boxed::Box<claim_assets::Beneficiary>,
            }
            pub mod claim_assets {
                use super::runtime_types;
                pub type Assets = runtime_types::xcm::VersionedAssets;
                pub type Beneficiary = runtime_types::xcm::VersionedLocation;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for ClaimAssets {
                const PALLET: &'static str = "PolkadotXcm";
                const CALL: &'static str = "claim_assets";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct TransferAssetsUsingTypeAndThen {
                pub dest: ::subxt::ext::subxt_core::alloc::boxed::Box<transfer_assets_using_type_and_then::Dest>,
                pub assets: ::subxt::ext::subxt_core::alloc::boxed::Box<transfer_assets_using_type_and_then::Assets>,
                pub assets_transfer_type: ::subxt::ext::subxt_core::alloc::boxed::Box<transfer_assets_using_type_and_then::AssetsTransferType>,
                pub remote_fees_id: ::subxt::ext::subxt_core::alloc::boxed::Box<transfer_assets_using_type_and_then::RemoteFeesId>,
                pub fees_transfer_type: ::subxt::ext::subxt_core::alloc::boxed::Box<transfer_assets_using_type_and_then::FeesTransferType>,
                pub custom_xcm_on_dest: ::subxt::ext::subxt_core::alloc::boxed::Box<transfer_assets_using_type_and_then::CustomXcmOnDest>,
                pub weight_limit: transfer_assets_using_type_and_then::WeightLimit,
            }
            pub mod transfer_assets_using_type_and_then {
                use super::runtime_types;
                pub type Dest = runtime_types::xcm::VersionedLocation;
                pub type Assets = runtime_types::xcm::VersionedAssets;
                pub type AssetsTransferType = runtime_types::staging_xcm_executor::traits::asset_transfer::TransferType;
                pub type RemoteFeesId = runtime_types::xcm::VersionedAssetId;
                pub type FeesTransferType = runtime_types::staging_xcm_executor::traits::asset_transfer::TransferType;
                pub type CustomXcmOnDest = runtime_types::xcm::VersionedXcm;
                pub type WeightLimit = runtime_types::xcm::v3::WeightLimit;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for TransferAssetsUsingTypeAndThen {
                const PALLET: &'static str = "PolkadotXcm";
                const CALL: &'static str = "transfer_assets_using_type_and_then";
            }
        }
        pub struct TransactionApi;
        impl TransactionApi {
            pub fn send(&self, dest: types::send::Dest, message: types::send::Message) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::Send> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("PolkadotXcm", "send", types::Send { dest: ::subxt::ext::subxt_core::alloc::boxed::Box::new(dest), message: ::subxt::ext::subxt_core::alloc::boxed::Box::new(message) }, [47u8, 63u8, 128u8, 176u8, 10u8, 137u8, 124u8, 238u8, 155u8, 37u8, 193u8, 160u8, 83u8, 240u8, 21u8, 179u8, 169u8, 131u8, 27u8, 104u8, 195u8, 208u8, 123u8, 14u8, 221u8, 12u8, 45u8, 81u8, 148u8, 76u8, 17u8, 100u8, ]) }
            pub fn teleport_assets(&self, dest: types::teleport_assets::Dest, beneficiary: types::teleport_assets::Beneficiary, assets: types::teleport_assets::Assets, fee_asset_item: types::teleport_assets::FeeAssetItem) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::TeleportAssets> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("PolkadotXcm", "teleport_assets", types::TeleportAssets { dest: ::subxt::ext::subxt_core::alloc::boxed::Box::new(dest), beneficiary: ::subxt::ext::subxt_core::alloc::boxed::Box::new(beneficiary), assets: ::subxt::ext::subxt_core::alloc::boxed::Box::new(assets), fee_asset_item }, [124u8, 191u8, 118u8, 61u8, 45u8, 225u8, 97u8, 83u8, 198u8, 20u8, 139u8, 117u8, 241u8, 1u8, 19u8, 54u8, 79u8, 181u8, 131u8, 112u8, 11u8, 118u8, 147u8, 12u8, 89u8, 156u8, 123u8, 123u8, 195u8, 45u8, 50u8, 107u8, ]) }
            pub fn reserve_transfer_assets(&self, dest: types::reserve_transfer_assets::Dest, beneficiary: types::reserve_transfer_assets::Beneficiary, assets: types::reserve_transfer_assets::Assets, fee_asset_item: types::reserve_transfer_assets::FeeAssetItem) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::ReserveTransferAssets> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("PolkadotXcm", "reserve_transfer_assets", types::ReserveTransferAssets { dest: ::subxt::ext::subxt_core::alloc::boxed::Box::new(dest), beneficiary: ::subxt::ext::subxt_core::alloc::boxed::Box::new(beneficiary), assets: ::subxt::ext::subxt_core::alloc::boxed::Box::new(assets), fee_asset_item }, [97u8, 102u8, 230u8, 44u8, 135u8, 197u8, 43u8, 53u8, 182u8, 125u8, 140u8, 141u8, 229u8, 73u8, 29u8, 55u8, 159u8, 104u8, 197u8, 20u8, 124u8, 234u8, 250u8, 94u8, 133u8, 253u8, 189u8, 6u8, 216u8, 162u8, 218u8, 89u8, ]) }
            pub fn execute(&self, message: types::execute::Message, max_weight: types::execute::MaxWeight) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::Execute> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("PolkadotXcm", "execute", types::Execute { message: ::subxt::ext::subxt_core::alloc::boxed::Box::new(message), max_weight }, [71u8, 109u8, 92u8, 110u8, 198u8, 150u8, 140u8, 125u8, 248u8, 236u8, 177u8, 156u8, 198u8, 223u8, 51u8, 15u8, 52u8, 240u8, 20u8, 200u8, 68u8, 145u8, 36u8, 156u8, 159u8, 153u8, 125u8, 48u8, 181u8, 61u8, 53u8, 208u8, ]) }
            pub fn force_xcm_version(&self, location: types::force_xcm_version::Location, version: types::force_xcm_version::Version) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::ForceXcmVersion> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("PolkadotXcm", "force_xcm_version", types::ForceXcmVersion { location: ::subxt::ext::subxt_core::alloc::boxed::Box::new(location), version }, [69u8, 151u8, 198u8, 154u8, 69u8, 181u8, 41u8, 111u8, 145u8, 230u8, 103u8, 42u8, 237u8, 91u8, 235u8, 6u8, 156u8, 65u8, 187u8, 48u8, 171u8, 200u8, 49u8, 4u8, 9u8, 210u8, 229u8, 152u8, 187u8, 88u8, 80u8, 246u8, ]) }
            pub fn force_default_xcm_version(&self, maybe_xcm_version: types::force_default_xcm_version::MaybeXcmVersion) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::ForceDefaultXcmVersion> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("PolkadotXcm", "force_default_xcm_version", types::ForceDefaultXcmVersion { maybe_xcm_version }, [43u8, 114u8, 102u8, 104u8, 209u8, 234u8, 108u8, 173u8, 109u8, 188u8, 94u8, 214u8, 136u8, 43u8, 153u8, 75u8, 161u8, 192u8, 76u8, 12u8, 221u8, 237u8, 158u8, 247u8, 41u8, 193u8, 35u8, 174u8, 183u8, 207u8, 79u8, 213u8, ]) }
            pub fn force_subscribe_version_notify(&self, location: types::force_subscribe_version_notify::Location) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::ForceSubscribeVersionNotify> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("PolkadotXcm", "force_subscribe_version_notify", types::ForceSubscribeVersionNotify { location: ::subxt::ext::subxt_core::alloc::boxed::Box::new(location) }, [203u8, 171u8, 70u8, 130u8, 46u8, 63u8, 76u8, 50u8, 105u8, 23u8, 249u8, 190u8, 115u8, 74u8, 70u8, 125u8, 132u8, 112u8, 138u8, 60u8, 33u8, 35u8, 45u8, 29u8, 95u8, 103u8, 187u8, 182u8, 188u8, 196u8, 248u8, 152u8, ]) }
            pub fn force_unsubscribe_version_notify(&self, location: types::force_unsubscribe_version_notify::Location) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::ForceUnsubscribeVersionNotify> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("PolkadotXcm", "force_unsubscribe_version_notify", types::ForceUnsubscribeVersionNotify { location: ::subxt::ext::subxt_core::alloc::boxed::Box::new(location) }, [6u8, 113u8, 168u8, 215u8, 233u8, 202u8, 249u8, 134u8, 131u8, 8u8, 142u8, 203u8, 142u8, 95u8, 216u8, 70u8, 38u8, 99u8, 166u8, 97u8, 218u8, 132u8, 247u8, 14u8, 42u8, 99u8, 4u8, 115u8, 200u8, 180u8, 213u8, 50u8, ]) }
            pub fn limited_reserve_transfer_assets(&self, dest: types::limited_reserve_transfer_assets::Dest, beneficiary: types::limited_reserve_transfer_assets::Beneficiary, assets: types::limited_reserve_transfer_assets::Assets, fee_asset_item: types::limited_reserve_transfer_assets::FeeAssetItem, weight_limit: types::limited_reserve_transfer_assets::WeightLimit) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::LimitedReserveTransferAssets> {
                ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("PolkadotXcm", "limited_reserve_transfer_assets", types::LimitedReserveTransferAssets { dest: ::subxt::ext::subxt_core::alloc::boxed::Box::new(dest), beneficiary: ::subxt::ext::subxt_core::alloc::boxed::Box::new(beneficiary), assets: ::subxt::ext::subxt_core::alloc::boxed::Box::new(assets), fee_asset_item, weight_limit }, [198u8, 66u8, 204u8, 162u8, 222u8, 246u8, 141u8, 165u8, 241u8, 62u8, 43u8, 236u8, 56u8, 200u8, 54u8, 47u8, 174u8, 83u8, 167u8, 220u8, 174u8, 111u8, 123u8, 202u8, 248u8, 232u8, 166u8, 80u8, 152u8, 223u8, 86u8, 141u8, ])
            }
            pub fn limited_teleport_assets(&self, dest: types::limited_teleport_assets::Dest, beneficiary: types::limited_teleport_assets::Beneficiary, assets: types::limited_teleport_assets::Assets, fee_asset_item: types::limited_teleport_assets::FeeAssetItem, weight_limit: types::limited_teleport_assets::WeightLimit) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::LimitedTeleportAssets> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("PolkadotXcm", "limited_teleport_assets", types::LimitedTeleportAssets { dest: ::subxt::ext::subxt_core::alloc::boxed::Box::new(dest), beneficiary: ::subxt::ext::subxt_core::alloc::boxed::Box::new(beneficiary), assets: ::subxt::ext::subxt_core::alloc::boxed::Box::new(assets), fee_asset_item, weight_limit }, [70u8, 61u8, 32u8, 43u8, 101u8, 104u8, 251u8, 60u8, 212u8, 124u8, 113u8, 243u8, 241u8, 183u8, 5u8, 231u8, 209u8, 231u8, 136u8, 3u8, 145u8, 242u8, 179u8, 171u8, 185u8, 185u8, 7u8, 34u8, 5u8, 203u8, 21u8, 210u8, ]) }
            pub fn force_suspension(&self, suspended: types::force_suspension::Suspended) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::ForceSuspension> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("PolkadotXcm", "force_suspension", types::ForceSuspension { suspended }, [78u8, 125u8, 93u8, 55u8, 129u8, 44u8, 36u8, 227u8, 75u8, 46u8, 68u8, 202u8, 81u8, 127u8, 111u8, 92u8, 149u8, 38u8, 225u8, 185u8, 183u8, 154u8, 89u8, 159u8, 79u8, 10u8, 229u8, 1u8, 226u8, 243u8, 65u8, 238u8, ]) }
            pub fn transfer_assets(&self, dest: types::transfer_assets::Dest, beneficiary: types::transfer_assets::Beneficiary, assets: types::transfer_assets::Assets, fee_asset_item: types::transfer_assets::FeeAssetItem, weight_limit: types::transfer_assets::WeightLimit) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::TransferAssets> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("PolkadotXcm", "transfer_assets", types::TransferAssets { dest: ::subxt::ext::subxt_core::alloc::boxed::Box::new(dest), beneficiary: ::subxt::ext::subxt_core::alloc::boxed::Box::new(beneficiary), assets: ::subxt::ext::subxt_core::alloc::boxed::Box::new(assets), fee_asset_item, weight_limit }, [44u8, 155u8, 182u8, 37u8, 123u8, 148u8, 150u8, 191u8, 117u8, 32u8, 16u8, 238u8, 121u8, 188u8, 217u8, 110u8, 10u8, 236u8, 174u8, 91u8, 100u8, 201u8, 109u8, 109u8, 60u8, 177u8, 233u8, 66u8, 181u8, 191u8, 105u8, 37u8, ]) }
            pub fn claim_assets(&self, assets: types::claim_assets::Assets, beneficiary: types::claim_assets::Beneficiary) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::ClaimAssets> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("PolkadotXcm", "claim_assets", types::ClaimAssets { assets: ::subxt::ext::subxt_core::alloc::boxed::Box::new(assets), beneficiary: ::subxt::ext::subxt_core::alloc::boxed::Box::new(beneficiary) }, [155u8, 23u8, 166u8, 172u8, 251u8, 171u8, 136u8, 240u8, 253u8, 51u8, 164u8, 43u8, 141u8, 23u8, 189u8, 177u8, 33u8, 32u8, 212u8, 56u8, 174u8, 165u8, 129u8, 7u8, 49u8, 217u8, 213u8, 214u8, 250u8, 91u8, 200u8, 195u8, ]) }
            pub fn transfer_assets_using_type_and_then(&self, dest: types::transfer_assets_using_type_and_then::Dest, assets: types::transfer_assets_using_type_and_then::Assets, assets_transfer_type: types::transfer_assets_using_type_and_then::AssetsTransferType, remote_fees_id: types::transfer_assets_using_type_and_then::RemoteFeesId, fees_transfer_type: types::transfer_assets_using_type_and_then::FeesTransferType, custom_xcm_on_dest: types::transfer_assets_using_type_and_then::CustomXcmOnDest, weight_limit: types::transfer_assets_using_type_and_then::WeightLimit) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::TransferAssetsUsingTypeAndThen> {
                ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("PolkadotXcm", "transfer_assets_using_type_and_then", types::TransferAssetsUsingTypeAndThen { dest: ::subxt::ext::subxt_core::alloc::boxed::Box::new(dest), assets: ::subxt::ext::subxt_core::alloc::boxed::Box::new(assets), assets_transfer_type: ::subxt::ext::subxt_core::alloc::boxed::Box::new(assets_transfer_type), remote_fees_id: ::subxt::ext::subxt_core::alloc::boxed::Box::new(remote_fees_id), fees_transfer_type: ::subxt::ext::subxt_core::alloc::boxed::Box::new(fees_transfer_type), custom_xcm_on_dest: ::subxt::ext::subxt_core::alloc::boxed::Box::new(custom_xcm_on_dest), weight_limit }, [128u8, 51u8, 64u8, 139u8, 106u8, 225u8, 14u8, 247u8, 44u8, 109u8, 11u8, 15u8, 7u8, 235u8, 7u8, 195u8, 177u8, 94u8, 9u8, 107u8, 110u8, 174u8, 154u8, 157u8, 20u8, 232u8, 38u8, 207u8, 228u8, 151u8, 10u8, 226u8, ])
            }
        }
    }
    pub type Event = runtime_types::pallet_xcm::pallet::Event;
    pub mod events {
        use super::runtime_types;
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct Attempted {
            pub outcome: attempted::Outcome,
        }
        pub mod attempted {
            use super::runtime_types;
            pub type Outcome = runtime_types::staging_xcm::v4::traits::Outcome;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for Attempted {
            const PALLET: &'static str = "PolkadotXcm";
            const EVENT: &'static str = "Attempted";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct Sent {
            pub origin: sent::Origin,
            pub destination: sent::Destination,
            pub message: sent::Message,
            pub message_id: sent::MessageId,
        }
        pub mod sent {
            use super::runtime_types;
            pub type Origin = runtime_types::staging_xcm::v4::location::Location;
            pub type Destination = runtime_types::staging_xcm::v4::location::Location;
            pub type Message = runtime_types::staging_xcm::v4::Xcm;
            pub type MessageId = [::core::primitive::u8; 32usize];
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for Sent {
            const PALLET: &'static str = "PolkadotXcm";
            const EVENT: &'static str = "Sent";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct UnexpectedResponse {
            pub origin: unexpected_response::Origin,
            pub query_id: unexpected_response::QueryId,
        }
        pub mod unexpected_response {
            use super::runtime_types;
            pub type Origin = runtime_types::staging_xcm::v4::location::Location;
            pub type QueryId = ::core::primitive::u64;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for UnexpectedResponse {
            const PALLET: &'static str = "PolkadotXcm";
            const EVENT: &'static str = "UnexpectedResponse";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct ResponseReady {
            pub query_id: response_ready::QueryId,
            pub response: response_ready::Response,
        }
        pub mod response_ready {
            use super::runtime_types;
            pub type QueryId = ::core::primitive::u64;
            pub type Response = runtime_types::staging_xcm::v4::Response;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for ResponseReady {
            const PALLET: &'static str = "PolkadotXcm";
            const EVENT: &'static str = "ResponseReady";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct Notified {
            pub query_id: notified::QueryId,
            pub pallet_index: notified::PalletIndex,
            pub call_index: notified::CallIndex,
        }
        pub mod notified {
            use super::runtime_types;
            pub type QueryId = ::core::primitive::u64;
            pub type PalletIndex = ::core::primitive::u8;
            pub type CallIndex = ::core::primitive::u8;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for Notified {
            const PALLET: &'static str = "PolkadotXcm";
            const EVENT: &'static str = "Notified";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct NotifyOverweight {
            pub query_id: notify_overweight::QueryId,
            pub pallet_index: notify_overweight::PalletIndex,
            pub call_index: notify_overweight::CallIndex,
            pub actual_weight: notify_overweight::ActualWeight,
            pub max_budgeted_weight: notify_overweight::MaxBudgetedWeight,
        }
        pub mod notify_overweight {
            use super::runtime_types;
            pub type QueryId = ::core::primitive::u64;
            pub type PalletIndex = ::core::primitive::u8;
            pub type CallIndex = ::core::primitive::u8;
            pub type ActualWeight = runtime_types::sp_weights::weight_v2::Weight;
            pub type MaxBudgetedWeight = runtime_types::sp_weights::weight_v2::Weight;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for NotifyOverweight {
            const PALLET: &'static str = "PolkadotXcm";
            const EVENT: &'static str = "NotifyOverweight";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct NotifyDispatchError {
            pub query_id: notify_dispatch_error::QueryId,
            pub pallet_index: notify_dispatch_error::PalletIndex,
            pub call_index: notify_dispatch_error::CallIndex,
        }
        pub mod notify_dispatch_error {
            use super::runtime_types;
            pub type QueryId = ::core::primitive::u64;
            pub type PalletIndex = ::core::primitive::u8;
            pub type CallIndex = ::core::primitive::u8;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for NotifyDispatchError {
            const PALLET: &'static str = "PolkadotXcm";
            const EVENT: &'static str = "NotifyDispatchError";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct NotifyDecodeFailed {
            pub query_id: notify_decode_failed::QueryId,
            pub pallet_index: notify_decode_failed::PalletIndex,
            pub call_index: notify_decode_failed::CallIndex,
        }
        pub mod notify_decode_failed {
            use super::runtime_types;
            pub type QueryId = ::core::primitive::u64;
            pub type PalletIndex = ::core::primitive::u8;
            pub type CallIndex = ::core::primitive::u8;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for NotifyDecodeFailed {
            const PALLET: &'static str = "PolkadotXcm";
            const EVENT: &'static str = "NotifyDecodeFailed";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct InvalidResponder {
            pub origin: invalid_responder::Origin,
            pub query_id: invalid_responder::QueryId,
            pub expected_location: invalid_responder::ExpectedLocation,
        }
        pub mod invalid_responder {
            use super::runtime_types;
            pub type Origin = runtime_types::staging_xcm::v4::location::Location;
            pub type QueryId = ::core::primitive::u64;
            pub type ExpectedLocation = ::core::option::Option<runtime_types::staging_xcm::v4::location::Location>;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for InvalidResponder {
            const PALLET: &'static str = "PolkadotXcm";
            const EVENT: &'static str = "InvalidResponder";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct InvalidResponderVersion {
            pub origin: invalid_responder_version::Origin,
            pub query_id: invalid_responder_version::QueryId,
        }
        pub mod invalid_responder_version {
            use super::runtime_types;
            pub type Origin = runtime_types::staging_xcm::v4::location::Location;
            pub type QueryId = ::core::primitive::u64;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for InvalidResponderVersion {
            const PALLET: &'static str = "PolkadotXcm";
            const EVENT: &'static str = "InvalidResponderVersion";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct ResponseTaken {
            pub query_id: response_taken::QueryId,
        }
        pub mod response_taken {
            use super::runtime_types;
            pub type QueryId = ::core::primitive::u64;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for ResponseTaken {
            const PALLET: &'static str = "PolkadotXcm";
            const EVENT: &'static str = "ResponseTaken";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct AssetsTrapped {
            pub hash: assets_trapped::Hash,
            pub origin: assets_trapped::Origin,
            pub assets: assets_trapped::Assets,
        }
        pub mod assets_trapped {
            use super::runtime_types;
            pub type Hash = ::subxt::ext::subxt_core::utils::H256;
            pub type Origin = runtime_types::staging_xcm::v4::location::Location;
            pub type Assets = runtime_types::xcm::VersionedAssets;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for AssetsTrapped {
            const PALLET: &'static str = "PolkadotXcm";
            const EVENT: &'static str = "AssetsTrapped";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct VersionChangeNotified {
            pub destination: version_change_notified::Destination,
            pub result: version_change_notified::Result,
            pub cost: version_change_notified::Cost,
            pub message_id: version_change_notified::MessageId,
        }
        pub mod version_change_notified {
            use super::runtime_types;
            pub type Destination = runtime_types::staging_xcm::v4::location::Location;
            pub type Result = ::core::primitive::u32;
            pub type Cost = runtime_types::staging_xcm::v4::asset::Assets;
            pub type MessageId = [::core::primitive::u8; 32usize];
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for VersionChangeNotified {
            const PALLET: &'static str = "PolkadotXcm";
            const EVENT: &'static str = "VersionChangeNotified";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct SupportedVersionChanged {
            pub location: supported_version_changed::Location,
            pub version: supported_version_changed::Version,
        }
        pub mod supported_version_changed {
            use super::runtime_types;
            pub type Location = runtime_types::staging_xcm::v4::location::Location;
            pub type Version = ::core::primitive::u32;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for SupportedVersionChanged {
            const PALLET: &'static str = "PolkadotXcm";
            const EVENT: &'static str = "SupportedVersionChanged";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct NotifyTargetSendFail {
            pub location: notify_target_send_fail::Location,
            pub query_id: notify_target_send_fail::QueryId,
            pub error: notify_target_send_fail::Error,
        }
        pub mod notify_target_send_fail {
            use super::runtime_types;
            pub type Location = runtime_types::staging_xcm::v4::location::Location;
            pub type QueryId = ::core::primitive::u64;
            pub type Error = runtime_types::xcm::v3::traits::Error;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for NotifyTargetSendFail {
            const PALLET: &'static str = "PolkadotXcm";
            const EVENT: &'static str = "NotifyTargetSendFail";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct NotifyTargetMigrationFail {
            pub location: notify_target_migration_fail::Location,
            pub query_id: notify_target_migration_fail::QueryId,
        }
        pub mod notify_target_migration_fail {
            use super::runtime_types;
            pub type Location = runtime_types::xcm::VersionedLocation;
            pub type QueryId = ::core::primitive::u64;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for NotifyTargetMigrationFail {
            const PALLET: &'static str = "PolkadotXcm";
            const EVENT: &'static str = "NotifyTargetMigrationFail";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct InvalidQuerierVersion {
            pub origin: invalid_querier_version::Origin,
            pub query_id: invalid_querier_version::QueryId,
        }
        pub mod invalid_querier_version {
            use super::runtime_types;
            pub type Origin = runtime_types::staging_xcm::v4::location::Location;
            pub type QueryId = ::core::primitive::u64;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for InvalidQuerierVersion {
            const PALLET: &'static str = "PolkadotXcm";
            const EVENT: &'static str = "InvalidQuerierVersion";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct InvalidQuerier {
            pub origin: invalid_querier::Origin,
            pub query_id: invalid_querier::QueryId,
            pub expected_querier: invalid_querier::ExpectedQuerier,
            pub maybe_actual_querier: invalid_querier::MaybeActualQuerier,
        }
        pub mod invalid_querier {
            use super::runtime_types;
            pub type Origin = runtime_types::staging_xcm::v4::location::Location;
            pub type QueryId = ::core::primitive::u64;
            pub type ExpectedQuerier = runtime_types::staging_xcm::v4::location::Location;
            pub type MaybeActualQuerier = ::core::option::Option<runtime_types::staging_xcm::v4::location::Location>;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for InvalidQuerier {
            const PALLET: &'static str = "PolkadotXcm";
            const EVENT: &'static str = "InvalidQuerier";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct VersionNotifyStarted {
            pub destination: version_notify_started::Destination,
            pub cost: version_notify_started::Cost,
            pub message_id: version_notify_started::MessageId,
        }
        pub mod version_notify_started {
            use super::runtime_types;
            pub type Destination = runtime_types::staging_xcm::v4::location::Location;
            pub type Cost = runtime_types::staging_xcm::v4::asset::Assets;
            pub type MessageId = [::core::primitive::u8; 32usize];
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for VersionNotifyStarted {
            const PALLET: &'static str = "PolkadotXcm";
            const EVENT: &'static str = "VersionNotifyStarted";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct VersionNotifyRequested {
            pub destination: version_notify_requested::Destination,
            pub cost: version_notify_requested::Cost,
            pub message_id: version_notify_requested::MessageId,
        }
        pub mod version_notify_requested {
            use super::runtime_types;
            pub type Destination = runtime_types::staging_xcm::v4::location::Location;
            pub type Cost = runtime_types::staging_xcm::v4::asset::Assets;
            pub type MessageId = [::core::primitive::u8; 32usize];
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for VersionNotifyRequested {
            const PALLET: &'static str = "PolkadotXcm";
            const EVENT: &'static str = "VersionNotifyRequested";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct VersionNotifyUnrequested {
            pub destination: version_notify_unrequested::Destination,
            pub cost: version_notify_unrequested::Cost,
            pub message_id: version_notify_unrequested::MessageId,
        }
        pub mod version_notify_unrequested {
            use super::runtime_types;
            pub type Destination = runtime_types::staging_xcm::v4::location::Location;
            pub type Cost = runtime_types::staging_xcm::v4::asset::Assets;
            pub type MessageId = [::core::primitive::u8; 32usize];
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for VersionNotifyUnrequested {
            const PALLET: &'static str = "PolkadotXcm";
            const EVENT: &'static str = "VersionNotifyUnrequested";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct FeesPaid {
            pub paying: fees_paid::Paying,
            pub fees: fees_paid::Fees,
        }
        pub mod fees_paid {
            use super::runtime_types;
            pub type Paying = runtime_types::staging_xcm::v4::location::Location;
            pub type Fees = runtime_types::staging_xcm::v4::asset::Assets;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for FeesPaid {
            const PALLET: &'static str = "PolkadotXcm";
            const EVENT: &'static str = "FeesPaid";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct AssetsClaimed {
            pub hash: assets_claimed::Hash,
            pub origin: assets_claimed::Origin,
            pub assets: assets_claimed::Assets,
        }
        pub mod assets_claimed {
            use super::runtime_types;
            pub type Hash = ::subxt::ext::subxt_core::utils::H256;
            pub type Origin = runtime_types::staging_xcm::v4::location::Location;
            pub type Assets = runtime_types::xcm::VersionedAssets;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for AssetsClaimed {
            const PALLET: &'static str = "PolkadotXcm";
            const EVENT: &'static str = "AssetsClaimed";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct VersionMigrationFinished {
            pub version: version_migration_finished::Version,
        }
        pub mod version_migration_finished {
            use super::runtime_types;
            pub type Version = ::core::primitive::u32;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for VersionMigrationFinished {
            const PALLET: &'static str = "PolkadotXcm";
            const EVENT: &'static str = "VersionMigrationFinished";
        }
    }
    pub mod storage {
        use super::runtime_types;
        pub mod types {
            use super::runtime_types;
            pub mod query_counter {
                use super::runtime_types;
                pub type QueryCounter = ::core::primitive::u64;
            }
            pub mod queries {
                use super::runtime_types;
                pub type Queries = runtime_types::pallet_xcm::pallet::QueryStatus<::core::primitive::u32>;
                pub type Param0 = ::core::primitive::u64;
            }
            pub mod asset_traps {
                use super::runtime_types;
                pub type AssetTraps = ::core::primitive::u32;
                pub type Param0 = ::subxt::ext::subxt_core::utils::H256;
            }
            pub mod safe_xcm_version {
                use super::runtime_types;
                pub type SafeXcmVersion = ::core::primitive::u32;
            }
            pub mod supported_version {
                use super::runtime_types;
                pub type SupportedVersion = ::core::primitive::u32;
                pub type Param0 = ::core::primitive::u32;
                pub type Param1 = runtime_types::xcm::VersionedLocation;
            }
            pub mod version_notifiers {
                use super::runtime_types;
                pub type VersionNotifiers = ::core::primitive::u64;
                pub type Param0 = ::core::primitive::u32;
                pub type Param1 = runtime_types::xcm::VersionedLocation;
            }
            pub mod version_notify_targets {
                use super::runtime_types;
                pub type VersionNotifyTargets = (::core::primitive::u64, runtime_types::sp_weights::weight_v2::Weight, ::core::primitive::u32,);
                pub type Param0 = ::core::primitive::u32;
                pub type Param1 = runtime_types::xcm::VersionedLocation;
            }
            pub mod version_discovery_queue {
                use super::runtime_types;
                pub type VersionDiscoveryQueue = runtime_types::bounded_collections::bounded_vec::BoundedVec<(runtime_types::xcm::VersionedLocation, ::core::primitive::u32,)>;
            }
            pub mod current_migration {
                use super::runtime_types;
                pub type CurrentMigration = runtime_types::pallet_xcm::pallet::VersionMigrationStage;
            }
            pub mod remote_locked_fungibles {
                use super::runtime_types;
                pub type RemoteLockedFungibles = runtime_types::pallet_xcm::pallet::RemoteLockedFungibleRecord<()>;
                pub type Param0 = ::core::primitive::u32;
                pub type Param1 = ::subxt::ext::subxt_core::utils::AccountId32;
                pub type Param2 = runtime_types::xcm::VersionedAssetId;
            }
            pub mod locked_fungibles {
                use super::runtime_types;
                pub type LockedFungibles = runtime_types::bounded_collections::bounded_vec::BoundedVec<(::core::primitive::u128, runtime_types::xcm::VersionedLocation,)>;
                pub type Param0 = ::subxt::ext::subxt_core::utils::AccountId32;
            }
            pub mod xcm_execution_suspended {
                use super::runtime_types;
                pub type XcmExecutionSuspended = ::core::primitive::bool;
            }
            pub mod should_record_xcm {
                use super::runtime_types;
                pub type ShouldRecordXcm = ::core::primitive::bool;
            }
            pub mod recorded_xcm {
                use super::runtime_types;
                pub type RecordedXcm = runtime_types::staging_xcm::v4::Xcm;
            }
        }
        pub struct StorageApi;
        impl StorageApi {
            pub fn query_counter(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::query_counter::QueryCounter, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("PolkadotXcm", "QueryCounter", (), [216u8, 73u8, 160u8, 232u8, 60u8, 245u8, 218u8, 219u8, 152u8, 68u8, 146u8, 219u8, 255u8, 7u8, 86u8, 112u8, 83u8, 49u8, 94u8, 173u8, 64u8, 203u8, 147u8, 226u8, 236u8, 39u8, 129u8, 106u8, 209u8, 113u8, 150u8, 50u8, ]) }
            pub fn queries_iter(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::queries::Queries, (), (), ::subxt::ext::subxt_core::utils::Yes> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("PolkadotXcm", "Queries", (), [246u8, 75u8, 240u8, 129u8, 106u8, 114u8, 99u8, 154u8, 176u8, 188u8, 146u8, 125u8, 244u8, 103u8, 187u8, 171u8, 60u8, 119u8, 4u8, 90u8, 58u8, 180u8, 48u8, 165u8, 145u8, 125u8, 227u8, 233u8, 11u8, 142u8, 122u8, 3u8, ]) }
            pub fn queries(&self, _0: impl ::core::borrow::Borrow<types::queries::Param0>) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::queries::Param0>, types::queries::Queries, ::subxt::ext::subxt_core::utils::Yes, (), ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("PolkadotXcm", "Queries", ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0.borrow()), [246u8, 75u8, 240u8, 129u8, 106u8, 114u8, 99u8, 154u8, 176u8, 188u8, 146u8, 125u8, 244u8, 103u8, 187u8, 171u8, 60u8, 119u8, 4u8, 90u8, 58u8, 180u8, 48u8, 165u8, 145u8, 125u8, 227u8, 233u8, 11u8, 142u8, 122u8, 3u8, ]) }
            pub fn asset_traps_iter(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::asset_traps::AssetTraps, (), ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("PolkadotXcm", "AssetTraps", (), [148u8, 41u8, 254u8, 134u8, 61u8, 172u8, 126u8, 146u8, 78u8, 178u8, 50u8, 77u8, 226u8, 8u8, 200u8, 78u8, 77u8, 91u8, 26u8, 133u8, 104u8, 126u8, 28u8, 28u8, 202u8, 62u8, 87u8, 183u8, 231u8, 191u8, 5u8, 181u8, ]) }
            pub fn asset_traps(&self, _0: impl ::core::borrow::Borrow<types::asset_traps::Param0>) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::asset_traps::Param0>, types::asset_traps::AssetTraps, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("PolkadotXcm", "AssetTraps", ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0.borrow()), [148u8, 41u8, 254u8, 134u8, 61u8, 172u8, 126u8, 146u8, 78u8, 178u8, 50u8, 77u8, 226u8, 8u8, 200u8, 78u8, 77u8, 91u8, 26u8, 133u8, 104u8, 126u8, 28u8, 28u8, 202u8, 62u8, 87u8, 183u8, 231u8, 191u8, 5u8, 181u8, ]) }
            pub fn safe_xcm_version(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::safe_xcm_version::SafeXcmVersion, ::subxt::ext::subxt_core::utils::Yes, (), ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("PolkadotXcm", "SafeXcmVersion", (), [187u8, 8u8, 74u8, 126u8, 80u8, 215u8, 177u8, 60u8, 223u8, 123u8, 196u8, 155u8, 166u8, 66u8, 25u8, 164u8, 191u8, 66u8, 116u8, 131u8, 116u8, 188u8, 224u8, 122u8, 75u8, 195u8, 246u8, 188u8, 83u8, 134u8, 49u8, 143u8, ]) }
            pub fn supported_version_iter(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::supported_version::SupportedVersion, (), (), ::subxt::ext::subxt_core::utils::Yes> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("PolkadotXcm", "SupportedVersion", (), [144u8, 218u8, 177u8, 254u8, 210u8, 8u8, 84u8, 149u8, 163u8, 162u8, 238u8, 37u8, 157u8, 28u8, 140u8, 121u8, 201u8, 173u8, 204u8, 92u8, 133u8, 45u8, 156u8, 38u8, 61u8, 51u8, 153u8, 161u8, 147u8, 146u8, 202u8, 24u8, ]) }
            pub fn supported_version_iter1(&self, _0: impl ::core::borrow::Borrow<types::supported_version::Param0>) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::supported_version::Param0>, types::supported_version::SupportedVersion, (), (), ::subxt::ext::subxt_core::utils::Yes> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("PolkadotXcm", "SupportedVersion", ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0.borrow()), [144u8, 218u8, 177u8, 254u8, 210u8, 8u8, 84u8, 149u8, 163u8, 162u8, 238u8, 37u8, 157u8, 28u8, 140u8, 121u8, 201u8, 173u8, 204u8, 92u8, 133u8, 45u8, 156u8, 38u8, 61u8, 51u8, 153u8, 161u8, 147u8, 146u8, 202u8, 24u8, ]) }
            pub fn supported_version(&self, _0: impl ::core::borrow::Borrow<types::supported_version::Param0>, _1: impl ::core::borrow::Borrow<types::supported_version::Param1>) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::supported_version::Param0>, ::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::supported_version::Param1>,), types::supported_version::SupportedVersion, ::subxt::ext::subxt_core::utils::Yes, (), ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("PolkadotXcm", "SupportedVersion", (::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0.borrow()), ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_1.borrow()),), [144u8, 218u8, 177u8, 254u8, 210u8, 8u8, 84u8, 149u8, 163u8, 162u8, 238u8, 37u8, 157u8, 28u8, 140u8, 121u8, 201u8, 173u8, 204u8, 92u8, 133u8, 45u8, 156u8, 38u8, 61u8, 51u8, 153u8, 161u8, 147u8, 146u8, 202u8, 24u8, ]) }
            pub fn version_notifiers_iter(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::version_notifiers::VersionNotifiers, (), (), ::subxt::ext::subxt_core::utils::Yes> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("PolkadotXcm", "VersionNotifiers", (), [175u8, 206u8, 29u8, 14u8, 111u8, 123u8, 211u8, 109u8, 159u8, 131u8, 80u8, 149u8, 216u8, 196u8, 181u8, 105u8, 117u8, 138u8, 80u8, 69u8, 237u8, 116u8, 195u8, 66u8, 209u8, 102u8, 42u8, 126u8, 222u8, 176u8, 201u8, 49u8, ]) }
            pub fn version_notifiers_iter1(&self, _0: impl ::core::borrow::Borrow<types::version_notifiers::Param0>) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::version_notifiers::Param0>, types::version_notifiers::VersionNotifiers, (), (), ::subxt::ext::subxt_core::utils::Yes> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("PolkadotXcm", "VersionNotifiers", ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0.borrow()), [175u8, 206u8, 29u8, 14u8, 111u8, 123u8, 211u8, 109u8, 159u8, 131u8, 80u8, 149u8, 216u8, 196u8, 181u8, 105u8, 117u8, 138u8, 80u8, 69u8, 237u8, 116u8, 195u8, 66u8, 209u8, 102u8, 42u8, 126u8, 222u8, 176u8, 201u8, 49u8, ]) }
            pub fn version_notifiers(&self, _0: impl ::core::borrow::Borrow<types::version_notifiers::Param0>, _1: impl ::core::borrow::Borrow<types::version_notifiers::Param1>) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::version_notifiers::Param0>, ::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::version_notifiers::Param1>,), types::version_notifiers::VersionNotifiers, ::subxt::ext::subxt_core::utils::Yes, (), ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("PolkadotXcm", "VersionNotifiers", (::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0.borrow()), ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_1.borrow()),), [175u8, 206u8, 29u8, 14u8, 111u8, 123u8, 211u8, 109u8, 159u8, 131u8, 80u8, 149u8, 216u8, 196u8, 181u8, 105u8, 117u8, 138u8, 80u8, 69u8, 237u8, 116u8, 195u8, 66u8, 209u8, 102u8, 42u8, 126u8, 222u8, 176u8, 201u8, 49u8, ]) }
            pub fn version_notify_targets_iter(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::version_notify_targets::VersionNotifyTargets, (), (), ::subxt::ext::subxt_core::utils::Yes> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("PolkadotXcm", "VersionNotifyTargets", (), [113u8, 77u8, 150u8, 42u8, 82u8, 49u8, 195u8, 120u8, 96u8, 80u8, 152u8, 67u8, 27u8, 142u8, 10u8, 74u8, 66u8, 134u8, 35u8, 202u8, 77u8, 187u8, 174u8, 22u8, 207u8, 199u8, 57u8, 85u8, 53u8, 208u8, 146u8, 81u8, ]) }
            pub fn version_notify_targets_iter1(&self, _0: impl ::core::borrow::Borrow<types::version_notify_targets::Param0>) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::version_notify_targets::Param0>, types::version_notify_targets::VersionNotifyTargets, (), (), ::subxt::ext::subxt_core::utils::Yes> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("PolkadotXcm", "VersionNotifyTargets", ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0.borrow()), [113u8, 77u8, 150u8, 42u8, 82u8, 49u8, 195u8, 120u8, 96u8, 80u8, 152u8, 67u8, 27u8, 142u8, 10u8, 74u8, 66u8, 134u8, 35u8, 202u8, 77u8, 187u8, 174u8, 22u8, 207u8, 199u8, 57u8, 85u8, 53u8, 208u8, 146u8, 81u8, ]) }
            pub fn version_notify_targets(&self, _0: impl ::core::borrow::Borrow<types::version_notify_targets::Param0>, _1: impl ::core::borrow::Borrow<types::version_notify_targets::Param1>) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::version_notify_targets::Param0>, ::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::version_notify_targets::Param1>,), types::version_notify_targets::VersionNotifyTargets, ::subxt::ext::subxt_core::utils::Yes, (), ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("PolkadotXcm", "VersionNotifyTargets", (::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0.borrow()), ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_1.borrow()),), [113u8, 77u8, 150u8, 42u8, 82u8, 49u8, 195u8, 120u8, 96u8, 80u8, 152u8, 67u8, 27u8, 142u8, 10u8, 74u8, 66u8, 134u8, 35u8, 202u8, 77u8, 187u8, 174u8, 22u8, 207u8, 199u8, 57u8, 85u8, 53u8, 208u8, 146u8, 81u8, ]) }
            pub fn version_discovery_queue(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::version_discovery_queue::VersionDiscoveryQueue, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("PolkadotXcm", "VersionDiscoveryQueue", (), [95u8, 74u8, 97u8, 94u8, 40u8, 140u8, 175u8, 176u8, 224u8, 222u8, 83u8, 199u8, 170u8, 102u8, 3u8, 77u8, 127u8, 208u8, 155u8, 122u8, 176u8, 51u8, 15u8, 253u8, 231u8, 245u8, 91u8, 192u8, 60u8, 144u8, 101u8, 168u8, ]) }
            pub fn current_migration(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::current_migration::CurrentMigration, ::subxt::ext::subxt_core::utils::Yes, (), ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("PolkadotXcm", "CurrentMigration", (), [74u8, 138u8, 181u8, 162u8, 59u8, 251u8, 37u8, 28u8, 232u8, 51u8, 30u8, 152u8, 252u8, 133u8, 95u8, 195u8, 47u8, 127u8, 21u8, 44u8, 62u8, 143u8, 170u8, 234u8, 160u8, 37u8, 131u8, 179u8, 57u8, 241u8, 140u8, 124u8, ]) }
            pub fn remote_locked_fungibles_iter(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::remote_locked_fungibles::RemoteLockedFungibles, (), (), ::subxt::ext::subxt_core::utils::Yes> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("PolkadotXcm", "RemoteLockedFungibles", (), [247u8, 124u8, 77u8, 42u8, 208u8, 183u8, 99u8, 196u8, 50u8, 113u8, 250u8, 221u8, 222u8, 170u8, 10u8, 60u8, 143u8, 172u8, 149u8, 198u8, 125u8, 154u8, 196u8, 196u8, 145u8, 209u8, 68u8, 28u8, 241u8, 241u8, 201u8, 150u8, ]) }
            pub fn remote_locked_fungibles_iter1(&self, _0: impl ::core::borrow::Borrow<types::remote_locked_fungibles::Param0>) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::remote_locked_fungibles::Param0>, types::remote_locked_fungibles::RemoteLockedFungibles, (), (), ::subxt::ext::subxt_core::utils::Yes> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("PolkadotXcm", "RemoteLockedFungibles", ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0.borrow()), [247u8, 124u8, 77u8, 42u8, 208u8, 183u8, 99u8, 196u8, 50u8, 113u8, 250u8, 221u8, 222u8, 170u8, 10u8, 60u8, 143u8, 172u8, 149u8, 198u8, 125u8, 154u8, 196u8, 196u8, 145u8, 209u8, 68u8, 28u8, 241u8, 241u8, 201u8, 150u8, ]) }
            pub fn remote_locked_fungibles_iter2(&self, _0: impl ::core::borrow::Borrow<types::remote_locked_fungibles::Param0>, _1: impl ::core::borrow::Borrow<types::remote_locked_fungibles::Param1>) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::remote_locked_fungibles::Param0>, ::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::remote_locked_fungibles::Param1>,), types::remote_locked_fungibles::RemoteLockedFungibles, (), (), ::subxt::ext::subxt_core::utils::Yes> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("PolkadotXcm", "RemoteLockedFungibles", (::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0.borrow()), ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_1.borrow()),), [247u8, 124u8, 77u8, 42u8, 208u8, 183u8, 99u8, 196u8, 50u8, 113u8, 250u8, 221u8, 222u8, 170u8, 10u8, 60u8, 143u8, 172u8, 149u8, 198u8, 125u8, 154u8, 196u8, 196u8, 145u8, 209u8, 68u8, 28u8, 241u8, 241u8, 201u8, 150u8, ]) }
            pub fn remote_locked_fungibles(&self, _0: impl ::core::borrow::Borrow<types::remote_locked_fungibles::Param0>, _1: impl ::core::borrow::Borrow<types::remote_locked_fungibles::Param1>, _2: impl ::core::borrow::Borrow<types::remote_locked_fungibles::Param2>) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::remote_locked_fungibles::Param0>, ::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::remote_locked_fungibles::Param1>, ::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::remote_locked_fungibles::Param2>,), types::remote_locked_fungibles::RemoteLockedFungibles, ::subxt::ext::subxt_core::utils::Yes, (), ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("PolkadotXcm", "RemoteLockedFungibles", (::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0.borrow()), ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_1.borrow()), ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_2.borrow()),), [247u8, 124u8, 77u8, 42u8, 208u8, 183u8, 99u8, 196u8, 50u8, 113u8, 250u8, 221u8, 222u8, 170u8, 10u8, 60u8, 143u8, 172u8, 149u8, 198u8, 125u8, 154u8, 196u8, 196u8, 145u8, 209u8, 68u8, 28u8, 241u8, 241u8, 201u8, 150u8, ]) }
            pub fn locked_fungibles_iter(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::locked_fungibles::LockedFungibles, (), (), ::subxt::ext::subxt_core::utils::Yes> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("PolkadotXcm", "LockedFungibles", (), [254u8, 234u8, 1u8, 27u8, 27u8, 32u8, 217u8, 24u8, 47u8, 30u8, 62u8, 80u8, 86u8, 125u8, 120u8, 24u8, 143u8, 229u8, 161u8, 153u8, 240u8, 246u8, 80u8, 15u8, 49u8, 189u8, 20u8, 204u8, 239u8, 198u8, 97u8, 174u8, ]) }
            pub fn locked_fungibles(&self, _0: impl ::core::borrow::Borrow<types::locked_fungibles::Param0>) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::locked_fungibles::Param0>, types::locked_fungibles::LockedFungibles, ::subxt::ext::subxt_core::utils::Yes, (), ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("PolkadotXcm", "LockedFungibles", ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0.borrow()), [254u8, 234u8, 1u8, 27u8, 27u8, 32u8, 217u8, 24u8, 47u8, 30u8, 62u8, 80u8, 86u8, 125u8, 120u8, 24u8, 143u8, 229u8, 161u8, 153u8, 240u8, 246u8, 80u8, 15u8, 49u8, 189u8, 20u8, 204u8, 239u8, 198u8, 97u8, 174u8, ]) }
            pub fn xcm_execution_suspended(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::xcm_execution_suspended::XcmExecutionSuspended, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("PolkadotXcm", "XcmExecutionSuspended", (), [182u8, 54u8, 69u8, 68u8, 78u8, 76u8, 103u8, 79u8, 47u8, 136u8, 99u8, 104u8, 128u8, 129u8, 249u8, 54u8, 214u8, 136u8, 97u8, 48u8, 178u8, 42u8, 26u8, 27u8, 82u8, 24u8, 33u8, 77u8, 33u8, 27u8, 20u8, 127u8, ]) }
            pub fn should_record_xcm(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::should_record_xcm::ShouldRecordXcm, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("PolkadotXcm", "ShouldRecordXcm", (), [77u8, 184u8, 154u8, 92u8, 185u8, 225u8, 131u8, 210u8, 55u8, 115u8, 3u8, 182u8, 191u8, 132u8, 51u8, 136u8, 42u8, 136u8, 54u8, 36u8, 229u8, 229u8, 47u8, 88u8, 4u8, 175u8, 136u8, 78u8, 226u8, 253u8, 13u8, 178u8, ]) }
            pub fn recorded_xcm(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::recorded_xcm::RecordedXcm, ::subxt::ext::subxt_core::utils::Yes, (), ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("PolkadotXcm", "RecordedXcm", (), [20u8, 231u8, 100u8, 77u8, 9u8, 170u8, 144u8, 49u8, 131u8, 233u8, 184u8, 123u8, 186u8, 56u8, 115u8, 3u8, 79u8, 234u8, 71u8, 93u8, 87u8, 172u8, 2u8, 3u8, 144u8, 151u8, 135u8, 149u8, 106u8, 96u8, 125u8, 12u8, ]) }
        }
    }
}
pub mod cumulus_xcm {
    use super::root_mod;
    use super::runtime_types;
    pub type Call = runtime_types::cumulus_pallet_xcm::pallet::Call;
    pub mod calls {
        use super::root_mod;
        use super::runtime_types;
        type DispatchError = runtime_types::sp_runtime::DispatchError;
        pub mod types { use super::runtime_types; }
        pub struct TransactionApi;
        impl TransactionApi {}
    }
    pub type Event = runtime_types::cumulus_pallet_xcm::pallet::Event;
    pub mod events {
        use super::runtime_types;
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct InvalidFormat(pub invalid_format::Field0);
        pub mod invalid_format {
            use super::runtime_types;
            pub type Field0 = [::core::primitive::u8; 32usize];
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for InvalidFormat {
            const PALLET: &'static str = "CumulusXcm";
            const EVENT: &'static str = "InvalidFormat";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct UnsupportedVersion(pub unsupported_version::Field0);
        pub mod unsupported_version {
            use super::runtime_types;
            pub type Field0 = [::core::primitive::u8; 32usize];
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for UnsupportedVersion {
            const PALLET: &'static str = "CumulusXcm";
            const EVENT: &'static str = "UnsupportedVersion";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct ExecutedDownward(pub executed_downward::Field0, pub executed_downward::Field1);
        pub mod executed_downward {
            use super::runtime_types;
            pub type Field0 = [::core::primitive::u8; 32usize];
            pub type Field1 = runtime_types::staging_xcm::v4::traits::Outcome;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for ExecutedDownward {
            const PALLET: &'static str = "CumulusXcm";
            const EVENT: &'static str = "ExecutedDownward";
        }
    }
}
pub mod message_queue {
    use super::root_mod;
    use super::runtime_types;
    pub type Error = runtime_types::pallet_message_queue::pallet::Error;
    pub type Call = runtime_types::pallet_message_queue::pallet::Call;
    pub mod calls {
        use super::root_mod;
        use super::runtime_types;
        type DispatchError = runtime_types::sp_runtime::DispatchError;
        pub mod types {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct ReapPage {
                pub message_origin: reap_page::MessageOrigin,
                pub page_index: reap_page::PageIndex,
            }
            pub mod reap_page {
                use super::runtime_types;
                pub type MessageOrigin = runtime_types::cumulus_primitives_core::AggregateMessageOrigin;
                pub type PageIndex = ::core::primitive::u32;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for ReapPage {
                const PALLET: &'static str = "MessageQueue";
                const CALL: &'static str = "reap_page";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct ExecuteOverweight {
                pub message_origin: execute_overweight::MessageOrigin,
                pub page: execute_overweight::Page,
                pub index: execute_overweight::Index,
                pub weight_limit: execute_overweight::WeightLimit,
            }
            pub mod execute_overweight {
                use super::runtime_types;
                pub type MessageOrigin = runtime_types::cumulus_primitives_core::AggregateMessageOrigin;
                pub type Page = ::core::primitive::u32;
                pub type Index = ::core::primitive::u32;
                pub type WeightLimit = runtime_types::sp_weights::weight_v2::Weight;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for ExecuteOverweight {
                const PALLET: &'static str = "MessageQueue";
                const CALL: &'static str = "execute_overweight";
            }
        }
        pub struct TransactionApi;
        impl TransactionApi {
            pub fn reap_page(&self, message_origin: types::reap_page::MessageOrigin, page_index: types::reap_page::PageIndex) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::ReapPage> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("MessageQueue", "reap_page", types::ReapPage { message_origin, page_index }, [116u8, 17u8, 120u8, 238u8, 117u8, 222u8, 10u8, 166u8, 132u8, 181u8, 114u8, 150u8, 242u8, 202u8, 31u8, 143u8, 212u8, 65u8, 145u8, 249u8, 27u8, 204u8, 137u8, 133u8, 220u8, 187u8, 137u8, 90u8, 112u8, 55u8, 104u8, 163u8, ]) }
            pub fn execute_overweight(&self, message_origin: types::execute_overweight::MessageOrigin, page: types::execute_overweight::Page, index: types::execute_overweight::Index, weight_limit: types::execute_overweight::WeightLimit) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::ExecuteOverweight> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("MessageQueue", "execute_overweight", types::ExecuteOverweight { message_origin, page, index, weight_limit }, [177u8, 54u8, 82u8, 58u8, 94u8, 125u8, 241u8, 172u8, 52u8, 7u8, 236u8, 80u8, 66u8, 99u8, 42u8, 199u8, 38u8, 195u8, 65u8, 118u8, 166u8, 246u8, 239u8, 195u8, 144u8, 153u8, 155u8, 8u8, 224u8, 56u8, 106u8, 135u8, ]) }
        }
    }
    pub type Event = runtime_types::pallet_message_queue::pallet::Event;
    pub mod events {
        use super::runtime_types;
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct ProcessingFailed {
            pub id: processing_failed::Id,
            pub origin: processing_failed::Origin,
            pub error: processing_failed::Error,
        }
        pub mod processing_failed {
            use super::runtime_types;
            pub type Id = ::subxt::ext::subxt_core::utils::H256;
            pub type Origin = runtime_types::cumulus_primitives_core::AggregateMessageOrigin;
            pub type Error = runtime_types::frame_support::traits::messages::ProcessMessageError;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for ProcessingFailed {
            const PALLET: &'static str = "MessageQueue";
            const EVENT: &'static str = "ProcessingFailed";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct Processed {
            pub id: processed::Id,
            pub origin: processed::Origin,
            pub weight_used: processed::WeightUsed,
            pub success: processed::Success,
        }
        pub mod processed {
            use super::runtime_types;
            pub type Id = ::subxt::ext::subxt_core::utils::H256;
            pub type Origin = runtime_types::cumulus_primitives_core::AggregateMessageOrigin;
            pub type WeightUsed = runtime_types::sp_weights::weight_v2::Weight;
            pub type Success = ::core::primitive::bool;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for Processed {
            const PALLET: &'static str = "MessageQueue";
            const EVENT: &'static str = "Processed";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct OverweightEnqueued {
            pub id: overweight_enqueued::Id,
            pub origin: overweight_enqueued::Origin,
            pub page_index: overweight_enqueued::PageIndex,
            pub message_index: overweight_enqueued::MessageIndex,
        }
        pub mod overweight_enqueued {
            use super::runtime_types;
            pub type Id = [::core::primitive::u8; 32usize];
            pub type Origin = runtime_types::cumulus_primitives_core::AggregateMessageOrigin;
            pub type PageIndex = ::core::primitive::u32;
            pub type MessageIndex = ::core::primitive::u32;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for OverweightEnqueued {
            const PALLET: &'static str = "MessageQueue";
            const EVENT: &'static str = "OverweightEnqueued";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct PageReaped {
            pub origin: page_reaped::Origin,
            pub index: page_reaped::Index,
        }
        pub mod page_reaped {
            use super::runtime_types;
            pub type Origin = runtime_types::cumulus_primitives_core::AggregateMessageOrigin;
            pub type Index = ::core::primitive::u32;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for PageReaped {
            const PALLET: &'static str = "MessageQueue";
            const EVENT: &'static str = "PageReaped";
        }
    }
    pub mod storage {
        use super::runtime_types;
        pub mod types {
            use super::runtime_types;
            pub mod book_state_for {
                use super::runtime_types;
                pub type BookStateFor = runtime_types::pallet_message_queue::BookState<runtime_types::cumulus_primitives_core::AggregateMessageOrigin>;
                pub type Param0 = runtime_types::cumulus_primitives_core::AggregateMessageOrigin;
            }
            pub mod service_head {
                use super::runtime_types;
                pub type ServiceHead = runtime_types::cumulus_primitives_core::AggregateMessageOrigin;
            }
            pub mod pages {
                use super::runtime_types;
                pub type Pages = runtime_types::pallet_message_queue::Page<::core::primitive::u32>;
                pub type Param0 = runtime_types::cumulus_primitives_core::AggregateMessageOrigin;
                pub type Param1 = ::core::primitive::u32;
            }
        }
        pub struct StorageApi;
        impl StorageApi {
            pub fn book_state_for_iter(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::book_state_for::BookStateFor, (), ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("MessageQueue", "BookStateFor", (), [33u8, 240u8, 235u8, 59u8, 150u8, 42u8, 91u8, 248u8, 235u8, 52u8, 170u8, 52u8, 195u8, 129u8, 6u8, 174u8, 57u8, 242u8, 30u8, 220u8, 232u8, 4u8, 246u8, 218u8, 162u8, 174u8, 102u8, 95u8, 210u8, 92u8, 133u8, 143u8, ]) }
            pub fn book_state_for(&self, _0: impl ::core::borrow::Borrow<types::book_state_for::Param0>) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::book_state_for::Param0>, types::book_state_for::BookStateFor, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("MessageQueue", "BookStateFor", ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0.borrow()), [33u8, 240u8, 235u8, 59u8, 150u8, 42u8, 91u8, 248u8, 235u8, 52u8, 170u8, 52u8, 195u8, 129u8, 6u8, 174u8, 57u8, 242u8, 30u8, 220u8, 232u8, 4u8, 246u8, 218u8, 162u8, 174u8, 102u8, 95u8, 210u8, 92u8, 133u8, 143u8, ]) }
            pub fn service_head(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::service_head::ServiceHead, ::subxt::ext::subxt_core::utils::Yes, (), ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("MessageQueue", "ServiceHead", (), [104u8, 146u8, 240u8, 41u8, 171u8, 68u8, 20u8, 147u8, 212u8, 155u8, 59u8, 39u8, 174u8, 186u8, 97u8, 250u8, 41u8, 247u8, 67u8, 190u8, 252u8, 167u8, 234u8, 36u8, 124u8, 239u8, 163u8, 72u8, 223u8, 82u8, 82u8, 171u8, ]) }
            pub fn pages_iter(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::pages::Pages, (), (), ::subxt::ext::subxt_core::utils::Yes> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("MessageQueue", "Pages", (), [45u8, 202u8, 18u8, 128u8, 31u8, 194u8, 175u8, 173u8, 99u8, 81u8, 161u8, 44u8, 32u8, 183u8, 238u8, 181u8, 110u8, 240u8, 203u8, 12u8, 152u8, 58u8, 239u8, 190u8, 144u8, 168u8, 210u8, 33u8, 121u8, 250u8, 137u8, 142u8, ]) }
            pub fn pages_iter1(&self, _0: impl ::core::borrow::Borrow<types::pages::Param0>) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::pages::Param0>, types::pages::Pages, (), (), ::subxt::ext::subxt_core::utils::Yes> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("MessageQueue", "Pages", ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0.borrow()), [45u8, 202u8, 18u8, 128u8, 31u8, 194u8, 175u8, 173u8, 99u8, 81u8, 161u8, 44u8, 32u8, 183u8, 238u8, 181u8, 110u8, 240u8, 203u8, 12u8, 152u8, 58u8, 239u8, 190u8, 144u8, 168u8, 210u8, 33u8, 121u8, 250u8, 137u8, 142u8, ]) }
            pub fn pages(&self, _0: impl ::core::borrow::Borrow<types::pages::Param0>, _1: impl ::core::borrow::Borrow<types::pages::Param1>) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::pages::Param0>, ::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::pages::Param1>,), types::pages::Pages, ::subxt::ext::subxt_core::utils::Yes, (), ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("MessageQueue", "Pages", (::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0.borrow()), ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_1.borrow()),), [45u8, 202u8, 18u8, 128u8, 31u8, 194u8, 175u8, 173u8, 99u8, 81u8, 161u8, 44u8, 32u8, 183u8, 238u8, 181u8, 110u8, 240u8, 203u8, 12u8, 152u8, 58u8, 239u8, 190u8, 144u8, 168u8, 210u8, 33u8, 121u8, 250u8, 137u8, 142u8, ]) }
        }
    }
    pub mod constants {
        use super::runtime_types;
        pub struct ConstantsApi;
        impl ConstantsApi {
            pub fn heap_size(&self) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<::core::primitive::u32> { ::subxt::ext::subxt_core::constants::address::StaticAddress::new_static("MessageQueue", "HeapSize", [98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8, 125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8, 178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8, 145u8, ]) }
            pub fn max_stale(&self) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<::core::primitive::u32> { ::subxt::ext::subxt_core::constants::address::StaticAddress::new_static("MessageQueue", "MaxStale", [98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8, 125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8, 178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8, 145u8, ]) }
            pub fn service_weight(&self) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<::core::option::Option<runtime_types::sp_weights::weight_v2::Weight>> { ::subxt::ext::subxt_core::constants::address::StaticAddress::new_static("MessageQueue", "ServiceWeight", [204u8, 140u8, 63u8, 167u8, 49u8, 8u8, 148u8, 163u8, 190u8, 224u8, 15u8, 103u8, 86u8, 153u8, 248u8, 117u8, 223u8, 117u8, 210u8, 80u8, 205u8, 155u8, 40u8, 11u8, 59u8, 63u8, 129u8, 156u8, 17u8, 83u8, 177u8, 250u8, ]) }
            pub fn idle_max_service_weight(&self) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<::core::option::Option<runtime_types::sp_weights::weight_v2::Weight>> { ::subxt::ext::subxt_core::constants::address::StaticAddress::new_static("MessageQueue", "IdleMaxServiceWeight", [204u8, 140u8, 63u8, 167u8, 49u8, 8u8, 148u8, 163u8, 190u8, 224u8, 15u8, 103u8, 86u8, 153u8, 248u8, 117u8, 223u8, 117u8, 210u8, 80u8, 205u8, 155u8, 40u8, 11u8, 59u8, 63u8, 129u8, 156u8, 17u8, 83u8, 177u8, 250u8, ]) }
        }
    }
}
pub mod utility {
    use super::root_mod;
    use super::runtime_types;
    pub type Error = runtime_types::pallet_utility::pallet::Error;
    pub type Call = runtime_types::pallet_utility::pallet::Call;
    pub mod calls {
        use super::root_mod;
        use super::runtime_types;
        type DispatchError = runtime_types::sp_runtime::DispatchError;
        pub mod types {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct Batch {
                pub calls: batch::Calls,
            }
            pub mod batch {
                use super::runtime_types;
                pub type Calls = ::subxt::ext::subxt_core::alloc::vec::Vec<runtime_types::people_rococo_runtime::RuntimeCall>;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for Batch {
                const PALLET: &'static str = "Utility";
                const CALL: &'static str = "batch";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct AsDerivative {
                pub index: as_derivative::Index,
                pub call: ::subxt::ext::subxt_core::alloc::boxed::Box<as_derivative::Call>,
            }
            pub mod as_derivative {
                use super::runtime_types;
                pub type Index = ::core::primitive::u16;
                pub type Call = runtime_types::people_rococo_runtime::RuntimeCall;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for AsDerivative {
                const PALLET: &'static str = "Utility";
                const CALL: &'static str = "as_derivative";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct BatchAll {
                pub calls: batch_all::Calls,
            }
            pub mod batch_all {
                use super::runtime_types;
                pub type Calls = ::subxt::ext::subxt_core::alloc::vec::Vec<runtime_types::people_rococo_runtime::RuntimeCall>;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for BatchAll {
                const PALLET: &'static str = "Utility";
                const CALL: &'static str = "batch_all";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct DispatchAs {
                pub as_origin: ::subxt::ext::subxt_core::alloc::boxed::Box<dispatch_as::AsOrigin>,
                pub call: ::subxt::ext::subxt_core::alloc::boxed::Box<dispatch_as::Call>,
            }
            pub mod dispatch_as {
                use super::runtime_types;
                pub type AsOrigin = runtime_types::people_rococo_runtime::OriginCaller;
                pub type Call = runtime_types::people_rococo_runtime::RuntimeCall;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for DispatchAs {
                const PALLET: &'static str = "Utility";
                const CALL: &'static str = "dispatch_as";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct ForceBatch {
                pub calls: force_batch::Calls,
            }
            pub mod force_batch {
                use super::runtime_types;
                pub type Calls = ::subxt::ext::subxt_core::alloc::vec::Vec<runtime_types::people_rococo_runtime::RuntimeCall>;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for ForceBatch {
                const PALLET: &'static str = "Utility";
                const CALL: &'static str = "force_batch";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct WithWeight {
                pub call: ::subxt::ext::subxt_core::alloc::boxed::Box<with_weight::Call>,
                pub weight: with_weight::Weight,
            }
            pub mod with_weight {
                use super::runtime_types;
                pub type Call = runtime_types::people_rococo_runtime::RuntimeCall;
                pub type Weight = runtime_types::sp_weights::weight_v2::Weight;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for WithWeight {
                const PALLET: &'static str = "Utility";
                const CALL: &'static str = "with_weight";
            }
        }
        pub struct TransactionApi;
        impl TransactionApi {
            pub fn batch(&self, calls: types::batch::Calls) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::Batch> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Utility", "batch", types::Batch { calls }, [221u8, 152u8, 12u8, 28u8, 97u8, 133u8, 108u8, 8u8, 246u8, 226u8, 182u8, 16u8, 1u8, 124u8, 183u8, 2u8, 22u8, 226u8, 180u8, 97u8, 156u8, 196u8, 221u8, 145u8, 64u8, 13u8, 147u8, 112u8, 11u8, 19u8, 29u8, 94u8, ]) }
            pub fn as_derivative(&self, index: types::as_derivative::Index, call: types::as_derivative::Call) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::AsDerivative> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Utility", "as_derivative", types::AsDerivative { index, call: ::subxt::ext::subxt_core::alloc::boxed::Box::new(call) }, [204u8, 141u8, 31u8, 18u8, 23u8, 201u8, 173u8, 207u8, 136u8, 48u8, 179u8, 129u8, 158u8, 252u8, 194u8, 124u8, 126u8, 94u8, 69u8, 78u8, 63u8, 116u8, 35u8, 19u8, 97u8, 52u8, 85u8, 37u8, 98u8, 197u8, 39u8, 54u8, ]) }
            pub fn batch_all(&self, calls: types::batch_all::Calls) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::BatchAll> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Utility", "batch_all", types::BatchAll { calls }, [44u8, 135u8, 98u8, 159u8, 25u8, 35u8, 230u8, 203u8, 192u8, 60u8, 9u8, 151u8, 83u8, 202u8, 0u8, 214u8, 14u8, 93u8, 134u8, 140u8, 91u8, 114u8, 244u8, 220u8, 77u8, 196u8, 158u8, 123u8, 234u8, 173u8, 202u8, 5u8, ]) }
            pub fn dispatch_as(&self, as_origin: types::dispatch_as::AsOrigin, call: types::dispatch_as::Call) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::DispatchAs> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Utility", "dispatch_as", types::DispatchAs { as_origin: ::subxt::ext::subxt_core::alloc::boxed::Box::new(as_origin), call: ::subxt::ext::subxt_core::alloc::boxed::Box::new(call) }, [129u8, 239u8, 10u8, 169u8, 62u8, 143u8, 146u8, 33u8, 200u8, 18u8, 248u8, 231u8, 247u8, 23u8, 159u8, 9u8, 39u8, 198u8, 55u8, 6u8, 64u8, 180u8, 146u8, 101u8, 231u8, 45u8, 66u8, 31u8, 114u8, 133u8, 94u8, 141u8, ]) }
            pub fn force_batch(&self, calls: types::force_batch::Calls) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::ForceBatch> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Utility", "force_batch", types::ForceBatch { calls }, [71u8, 16u8, 18u8, 40u8, 48u8, 142u8, 223u8, 123u8, 157u8, 109u8, 125u8, 125u8, 7u8, 170u8, 71u8, 105u8, 201u8, 79u8, 126u8, 107u8, 83u8, 58u8, 0u8, 197u8, 13u8, 114u8, 68u8, 191u8, 91u8, 182u8, 19u8, 100u8, ]) }
            pub fn with_weight(&self, call: types::with_weight::Call, weight: types::with_weight::Weight) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::WithWeight> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Utility", "with_weight", types::WithWeight { call: ::subxt::ext::subxt_core::alloc::boxed::Box::new(call), weight }, [96u8, 107u8, 172u8, 67u8, 61u8, 0u8, 99u8, 85u8, 221u8, 61u8, 41u8, 152u8, 246u8, 24u8, 57u8, 26u8, 69u8, 80u8, 7u8, 117u8, 103u8, 65u8, 11u8, 225u8, 77u8, 34u8, 60u8, 17u8, 128u8, 127u8, 125u8, 11u8, ]) }
        }
    }
    pub type Event = runtime_types::pallet_utility::pallet::Event;
    pub mod events {
        use super::runtime_types;
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct BatchInterrupted {
            pub index: batch_interrupted::Index,
            pub error: batch_interrupted::Error,
        }
        pub mod batch_interrupted {
            use super::runtime_types;
            pub type Index = ::core::primitive::u32;
            pub type Error = runtime_types::sp_runtime::DispatchError;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for BatchInterrupted {
            const PALLET: &'static str = "Utility";
            const EVENT: &'static str = "BatchInterrupted";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct BatchCompleted;
        impl ::subxt::ext::subxt_core::events::StaticEvent for BatchCompleted {
            const PALLET: &'static str = "Utility";
            const EVENT: &'static str = "BatchCompleted";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct BatchCompletedWithErrors;
        impl ::subxt::ext::subxt_core::events::StaticEvent for BatchCompletedWithErrors {
            const PALLET: &'static str = "Utility";
            const EVENT: &'static str = "BatchCompletedWithErrors";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct ItemCompleted;
        impl ::subxt::ext::subxt_core::events::StaticEvent for ItemCompleted {
            const PALLET: &'static str = "Utility";
            const EVENT: &'static str = "ItemCompleted";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct ItemFailed {
            pub error: item_failed::Error,
        }
        pub mod item_failed {
            use super::runtime_types;
            pub type Error = runtime_types::sp_runtime::DispatchError;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for ItemFailed {
            const PALLET: &'static str = "Utility";
            const EVENT: &'static str = "ItemFailed";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct DispatchedAs {
            pub result: dispatched_as::Result,
        }
        pub mod dispatched_as {
            use super::runtime_types;
            pub type Result = ::core::result::Result<(), runtime_types::sp_runtime::DispatchError>;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for DispatchedAs {
            const PALLET: &'static str = "Utility";
            const EVENT: &'static str = "DispatchedAs";
        }
    }
    pub mod constants {
        use super::runtime_types;
        pub struct ConstantsApi;
        impl ConstantsApi { pub fn batched_calls_limit(&self) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<::core::primitive::u32> { ::subxt::ext::subxt_core::constants::address::StaticAddress::new_static("Utility", "batched_calls_limit", [98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8, 125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8, 178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8, 145u8, ]) } }
    }
}
pub mod multisig {
    use super::root_mod;
    use super::runtime_types;
    pub type Error = runtime_types::pallet_multisig::pallet::Error;
    pub type Call = runtime_types::pallet_multisig::pallet::Call;
    pub mod calls {
        use super::root_mod;
        use super::runtime_types;
        type DispatchError = runtime_types::sp_runtime::DispatchError;
        pub mod types {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct AsMultiThreshold1 {
                pub other_signatories: as_multi_threshold1::OtherSignatories,
                pub call: ::subxt::ext::subxt_core::alloc::boxed::Box<as_multi_threshold1::Call>,
            }
            pub mod as_multi_threshold1 {
                use super::runtime_types;
                pub type OtherSignatories = ::subxt::ext::subxt_core::alloc::vec::Vec<::subxt::ext::subxt_core::utils::AccountId32>;
                pub type Call = runtime_types::people_rococo_runtime::RuntimeCall;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for AsMultiThreshold1 {
                const PALLET: &'static str = "Multisig";
                const CALL: &'static str = "as_multi_threshold_1";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct AsMulti {
                pub threshold: as_multi::Threshold,
                pub other_signatories: as_multi::OtherSignatories,
                pub maybe_timepoint: as_multi::MaybeTimepoint,
                pub call: ::subxt::ext::subxt_core::alloc::boxed::Box<as_multi::Call>,
                pub max_weight: as_multi::MaxWeight,
            }
            pub mod as_multi {
                use super::runtime_types;
                pub type Threshold = ::core::primitive::u16;
                pub type OtherSignatories = ::subxt::ext::subxt_core::alloc::vec::Vec<::subxt::ext::subxt_core::utils::AccountId32>;
                pub type MaybeTimepoint = ::core::option::Option<runtime_types::pallet_multisig::Timepoint<::core::primitive::u32>>;
                pub type Call = runtime_types::people_rococo_runtime::RuntimeCall;
                pub type MaxWeight = runtime_types::sp_weights::weight_v2::Weight;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for AsMulti {
                const PALLET: &'static str = "Multisig";
                const CALL: &'static str = "as_multi";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct ApproveAsMulti {
                pub threshold: approve_as_multi::Threshold,
                pub other_signatories: approve_as_multi::OtherSignatories,
                pub maybe_timepoint: approve_as_multi::MaybeTimepoint,
                pub call_hash: approve_as_multi::CallHash,
                pub max_weight: approve_as_multi::MaxWeight,
            }
            pub mod approve_as_multi {
                use super::runtime_types;
                pub type Threshold = ::core::primitive::u16;
                pub type OtherSignatories = ::subxt::ext::subxt_core::alloc::vec::Vec<::subxt::ext::subxt_core::utils::AccountId32>;
                pub type MaybeTimepoint = ::core::option::Option<runtime_types::pallet_multisig::Timepoint<::core::primitive::u32>>;
                pub type CallHash = [::core::primitive::u8; 32usize];
                pub type MaxWeight = runtime_types::sp_weights::weight_v2::Weight;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for ApproveAsMulti {
                const PALLET: &'static str = "Multisig";
                const CALL: &'static str = "approve_as_multi";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct CancelAsMulti {
                pub threshold: cancel_as_multi::Threshold,
                pub other_signatories: cancel_as_multi::OtherSignatories,
                pub timepoint: cancel_as_multi::Timepoint,
                pub call_hash: cancel_as_multi::CallHash,
            }
            pub mod cancel_as_multi {
                use super::runtime_types;
                pub type Threshold = ::core::primitive::u16;
                pub type OtherSignatories = ::subxt::ext::subxt_core::alloc::vec::Vec<::subxt::ext::subxt_core::utils::AccountId32>;
                pub type Timepoint = runtime_types::pallet_multisig::Timepoint<::core::primitive::u32>;
                pub type CallHash = [::core::primitive::u8; 32usize];
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for CancelAsMulti {
                const PALLET: &'static str = "Multisig";
                const CALL: &'static str = "cancel_as_multi";
            }
        }
        pub struct TransactionApi;
        impl TransactionApi {
            pub fn as_multi_threshold_1(&self, other_signatories: types::as_multi_threshold1::OtherSignatories, call: types::as_multi_threshold1::Call) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::AsMultiThreshold1> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Multisig", "as_multi_threshold_1", types::AsMultiThreshold1 { other_signatories, call: ::subxt::ext::subxt_core::alloc::boxed::Box::new(call) }, [148u8, 33u8, 244u8, 22u8, 116u8, 14u8, 22u8, 33u8, 198u8, 247u8, 222u8, 149u8, 90u8, 8u8, 71u8, 87u8, 83u8, 210u8, 102u8, 75u8, 8u8, 7u8, 79u8, 9u8, 246u8, 246u8, 40u8, 181u8, 22u8, 17u8, 81u8, 165u8, ]) }
            pub fn as_multi(&self, threshold: types::as_multi::Threshold, other_signatories: types::as_multi::OtherSignatories, maybe_timepoint: types::as_multi::MaybeTimepoint, call: types::as_multi::Call, max_weight: types::as_multi::MaxWeight) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::AsMulti> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Multisig", "as_multi", types::AsMulti { threshold, other_signatories, maybe_timepoint, call: ::subxt::ext::subxt_core::alloc::boxed::Box::new(call), max_weight }, [61u8, 53u8, 178u8, 129u8, 219u8, 26u8, 162u8, 19u8, 178u8, 219u8, 46u8, 233u8, 252u8, 179u8, 85u8, 180u8, 243u8, 21u8, 62u8, 194u8, 43u8, 235u8, 230u8, 46u8, 172u8, 51u8, 151u8, 15u8, 242u8, 223u8, 30u8, 150u8, ]) }
            pub fn approve_as_multi(&self, threshold: types::approve_as_multi::Threshold, other_signatories: types::approve_as_multi::OtherSignatories, maybe_timepoint: types::approve_as_multi::MaybeTimepoint, call_hash: types::approve_as_multi::CallHash, max_weight: types::approve_as_multi::MaxWeight) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::ApproveAsMulti> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Multisig", "approve_as_multi", types::ApproveAsMulti { threshold, other_signatories, maybe_timepoint, call_hash, max_weight }, [248u8, 46u8, 131u8, 35u8, 204u8, 12u8, 218u8, 150u8, 88u8, 131u8, 89u8, 13u8, 95u8, 122u8, 87u8, 107u8, 136u8, 154u8, 92u8, 199u8, 108u8, 92u8, 207u8, 171u8, 113u8, 8u8, 47u8, 248u8, 65u8, 26u8, 203u8, 135u8, ]) }
            pub fn cancel_as_multi(&self, threshold: types::cancel_as_multi::Threshold, other_signatories: types::cancel_as_multi::OtherSignatories, timepoint: types::cancel_as_multi::Timepoint, call_hash: types::cancel_as_multi::CallHash) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::CancelAsMulti> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Multisig", "cancel_as_multi", types::CancelAsMulti { threshold, other_signatories, timepoint, call_hash }, [212u8, 179u8, 123u8, 40u8, 209u8, 228u8, 181u8, 0u8, 109u8, 28u8, 27u8, 48u8, 15u8, 47u8, 203u8, 54u8, 106u8, 114u8, 28u8, 118u8, 101u8, 201u8, 95u8, 187u8, 46u8, 182u8, 4u8, 30u8, 227u8, 105u8, 14u8, 81u8, ]) }
        }
    }
    pub type Event = runtime_types::pallet_multisig::pallet::Event;
    pub mod events {
        use super::runtime_types;
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct NewMultisig {
            pub approving: new_multisig::Approving,
            pub multisig: new_multisig::Multisig,
            pub call_hash: new_multisig::CallHash,
        }
        pub mod new_multisig {
            use super::runtime_types;
            pub type Approving = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type Multisig = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type CallHash = [::core::primitive::u8; 32usize];
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for NewMultisig {
            const PALLET: &'static str = "Multisig";
            const EVENT: &'static str = "NewMultisig";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct MultisigApproval {
            pub approving: multisig_approval::Approving,
            pub timepoint: multisig_approval::Timepoint,
            pub multisig: multisig_approval::Multisig,
            pub call_hash: multisig_approval::CallHash,
        }
        pub mod multisig_approval {
            use super::runtime_types;
            pub type Approving = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type Timepoint = runtime_types::pallet_multisig::Timepoint<::core::primitive::u32>;
            pub type Multisig = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type CallHash = [::core::primitive::u8; 32usize];
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for MultisigApproval {
            const PALLET: &'static str = "Multisig";
            const EVENT: &'static str = "MultisigApproval";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct MultisigExecuted {
            pub approving: multisig_executed::Approving,
            pub timepoint: multisig_executed::Timepoint,
            pub multisig: multisig_executed::Multisig,
            pub call_hash: multisig_executed::CallHash,
            pub result: multisig_executed::Result,
        }
        pub mod multisig_executed {
            use super::runtime_types;
            pub type Approving = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type Timepoint = runtime_types::pallet_multisig::Timepoint<::core::primitive::u32>;
            pub type Multisig = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type CallHash = [::core::primitive::u8; 32usize];
            pub type Result = ::core::result::Result<(), runtime_types::sp_runtime::DispatchError>;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for MultisigExecuted {
            const PALLET: &'static str = "Multisig";
            const EVENT: &'static str = "MultisigExecuted";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct MultisigCancelled {
            pub cancelling: multisig_cancelled::Cancelling,
            pub timepoint: multisig_cancelled::Timepoint,
            pub multisig: multisig_cancelled::Multisig,
            pub call_hash: multisig_cancelled::CallHash,
        }
        pub mod multisig_cancelled {
            use super::runtime_types;
            pub type Cancelling = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type Timepoint = runtime_types::pallet_multisig::Timepoint<::core::primitive::u32>;
            pub type Multisig = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type CallHash = [::core::primitive::u8; 32usize];
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for MultisigCancelled {
            const PALLET: &'static str = "Multisig";
            const EVENT: &'static str = "MultisigCancelled";
        }
    }
    pub mod storage {
        use super::runtime_types;
        pub mod types {
            use super::runtime_types;
            pub mod multisigs {
                use super::runtime_types;
                pub type Multisigs = runtime_types::pallet_multisig::Multisig<::core::primitive::u32, ::core::primitive::u128, ::subxt::ext::subxt_core::utils::AccountId32>;
                pub type Param0 = ::subxt::ext::subxt_core::utils::AccountId32;
                pub type Param1 = [::core::primitive::u8; 32usize];
            }
        }
        pub struct StorageApi;
        impl StorageApi {
            pub fn multisigs_iter(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::multisigs::Multisigs, (), (), ::subxt::ext::subxt_core::utils::Yes> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Multisig", "Multisigs", (), [154u8, 109u8, 45u8, 18u8, 155u8, 151u8, 81u8, 28u8, 86u8, 127u8, 189u8, 151u8, 49u8, 61u8, 12u8, 149u8, 84u8, 61u8, 110u8, 197u8, 200u8, 140u8, 37u8, 100u8, 14u8, 162u8, 158u8, 161u8, 48u8, 117u8, 102u8, 61u8, ]) }
            pub fn multisigs_iter1(&self, _0: impl ::core::borrow::Borrow<types::multisigs::Param0>) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::multisigs::Param0>, types::multisigs::Multisigs, (), (), ::subxt::ext::subxt_core::utils::Yes> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Multisig", "Multisigs", ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0.borrow()), [154u8, 109u8, 45u8, 18u8, 155u8, 151u8, 81u8, 28u8, 86u8, 127u8, 189u8, 151u8, 49u8, 61u8, 12u8, 149u8, 84u8, 61u8, 110u8, 197u8, 200u8, 140u8, 37u8, 100u8, 14u8, 162u8, 158u8, 161u8, 48u8, 117u8, 102u8, 61u8, ]) }
            pub fn multisigs(&self, _0: impl ::core::borrow::Borrow<types::multisigs::Param0>, _1: impl ::core::borrow::Borrow<types::multisigs::Param1>) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::multisigs::Param0>, ::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::multisigs::Param1>,), types::multisigs::Multisigs, ::subxt::ext::subxt_core::utils::Yes, (), ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Multisig", "Multisigs", (::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0.borrow()), ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_1.borrow()),), [154u8, 109u8, 45u8, 18u8, 155u8, 151u8, 81u8, 28u8, 86u8, 127u8, 189u8, 151u8, 49u8, 61u8, 12u8, 149u8, 84u8, 61u8, 110u8, 197u8, 200u8, 140u8, 37u8, 100u8, 14u8, 162u8, 158u8, 161u8, 48u8, 117u8, 102u8, 61u8, ]) }
        }
    }
    pub mod constants {
        use super::runtime_types;
        pub struct ConstantsApi;
        impl ConstantsApi {
            pub fn deposit_base(&self) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<::core::primitive::u128> { ::subxt::ext::subxt_core::constants::address::StaticAddress::new_static("Multisig", "DepositBase", [84u8, 157u8, 140u8, 4u8, 93u8, 57u8, 29u8, 133u8, 105u8, 200u8, 214u8, 27u8, 144u8, 208u8, 218u8, 160u8, 130u8, 109u8, 101u8, 54u8, 210u8, 136u8, 71u8, 63u8, 49u8, 237u8, 234u8, 15u8, 178u8, 98u8, 148u8, 156u8, ]) }
            pub fn deposit_factor(&self) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<::core::primitive::u128> { ::subxt::ext::subxt_core::constants::address::StaticAddress::new_static("Multisig", "DepositFactor", [84u8, 157u8, 140u8, 4u8, 93u8, 57u8, 29u8, 133u8, 105u8, 200u8, 214u8, 27u8, 144u8, 208u8, 218u8, 160u8, 130u8, 109u8, 101u8, 54u8, 210u8, 136u8, 71u8, 63u8, 49u8, 237u8, 234u8, 15u8, 178u8, 98u8, 148u8, 156u8, ]) }
            pub fn max_signatories(&self) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<::core::primitive::u32> { ::subxt::ext::subxt_core::constants::address::StaticAddress::new_static("Multisig", "MaxSignatories", [98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8, 125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8, 178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8, 145u8, ]) }
        }
    }
}
pub mod identity {
    use super::root_mod;
    use super::runtime_types;
    pub type Error = runtime_types::pallet_identity::pallet::Error;
    pub type Call = runtime_types::pallet_identity::pallet::Call;
    pub mod calls {
        use super::root_mod;
        use super::runtime_types;
        type DispatchError = runtime_types::sp_runtime::DispatchError;
        pub mod types {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct AddRegistrar {
                pub account: add_registrar::Account,
            }
            pub mod add_registrar {
                use super::runtime_types;
                pub type Account = ::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()>;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for AddRegistrar {
                const PALLET: &'static str = "Identity";
                const CALL: &'static str = "add_registrar";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct SetIdentity {
                pub info: ::subxt::ext::subxt_core::alloc::boxed::Box<set_identity::Info>,
            }
            pub mod set_identity {
                use super::runtime_types;
                pub type Info = runtime_types::people_rococo_runtime::people::IdentityInfo;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for SetIdentity {
                const PALLET: &'static str = "Identity";
                const CALL: &'static str = "set_identity";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct SetSubs {
                pub subs: set_subs::Subs,
            }
            pub mod set_subs {
                use super::runtime_types;
                pub type Subs = ::subxt::ext::subxt_core::alloc::vec::Vec<(::subxt::ext::subxt_core::utils::AccountId32, runtime_types::pallet_identity::types::Data,)>;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for SetSubs {
                const PALLET: &'static str = "Identity";
                const CALL: &'static str = "set_subs";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct ClearIdentity;
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for ClearIdentity {
                const PALLET: &'static str = "Identity";
                const CALL: &'static str = "clear_identity";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct RequestJudgement {
                #[codec(compact)] pub reg_index: request_judgement::RegIndex,
                #[codec(compact)] pub max_fee: request_judgement::MaxFee,
            }
            pub mod request_judgement {
                use super::runtime_types;
                pub type RegIndex = ::core::primitive::u32;
                pub type MaxFee = ::core::primitive::u128;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for RequestJudgement {
                const PALLET: &'static str = "Identity";
                const CALL: &'static str = "request_judgement";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct CancelRequest {
                pub reg_index: cancel_request::RegIndex,
            }
            pub mod cancel_request {
                use super::runtime_types;
                pub type RegIndex = ::core::primitive::u32;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for CancelRequest {
                const PALLET: &'static str = "Identity";
                const CALL: &'static str = "cancel_request";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct SetFee {
                #[codec(compact)] pub index: set_fee::Index,
                #[codec(compact)] pub fee: set_fee::Fee,
            }
            pub mod set_fee {
                use super::runtime_types;
                pub type Index = ::core::primitive::u32;
                pub type Fee = ::core::primitive::u128;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for SetFee {
                const PALLET: &'static str = "Identity";
                const CALL: &'static str = "set_fee";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct SetAccountId {
                #[codec(compact)] pub index: set_account_id::Index,
                pub new: set_account_id::New,
            }
            pub mod set_account_id {
                use super::runtime_types;
                pub type Index = ::core::primitive::u32;
                pub type New = ::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()>;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for SetAccountId {
                const PALLET: &'static str = "Identity";
                const CALL: &'static str = "set_account_id";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct SetFields {
                #[codec(compact)] pub index: set_fields::Index,
                pub fields: set_fields::Fields,
            }
            pub mod set_fields {
                use super::runtime_types;
                pub type Index = ::core::primitive::u32;
                pub type Fields = ::core::primitive::u64;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for SetFields {
                const PALLET: &'static str = "Identity";
                const CALL: &'static str = "set_fields";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct ProvideJudgement {
                #[codec(compact)] pub reg_index: provide_judgement::RegIndex,
                pub target: provide_judgement::Target,
                pub judgement: provide_judgement::Judgement,
                pub identity: provide_judgement::Identity,
            }
            pub mod provide_judgement {
                use super::runtime_types;
                pub type RegIndex = ::core::primitive::u32;
                pub type Target = ::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()>;
                pub type Judgement = runtime_types::pallet_identity::types::Judgement<::core::primitive::u128>;
                pub type Identity = ::subxt::ext::subxt_core::utils::H256;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for ProvideJudgement {
                const PALLET: &'static str = "Identity";
                const CALL: &'static str = "provide_judgement";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct KillIdentity {
                pub target: kill_identity::Target,
            }
            pub mod kill_identity {
                use super::runtime_types;
                pub type Target = ::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()>;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for KillIdentity {
                const PALLET: &'static str = "Identity";
                const CALL: &'static str = "kill_identity";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct AddSub {
                pub sub: add_sub::Sub,
                pub data: add_sub::Data,
            }
            pub mod add_sub {
                use super::runtime_types;
                pub type Sub = ::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()>;
                pub type Data = runtime_types::pallet_identity::types::Data;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for AddSub {
                const PALLET: &'static str = "Identity";
                const CALL: &'static str = "add_sub";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct RenameSub {
                pub sub: rename_sub::Sub,
                pub data: rename_sub::Data,
            }
            pub mod rename_sub {
                use super::runtime_types;
                pub type Sub = ::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()>;
                pub type Data = runtime_types::pallet_identity::types::Data;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for RenameSub {
                const PALLET: &'static str = "Identity";
                const CALL: &'static str = "rename_sub";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct RemoveSub {
                pub sub: remove_sub::Sub,
            }
            pub mod remove_sub {
                use super::runtime_types;
                pub type Sub = ::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()>;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for RemoveSub {
                const PALLET: &'static str = "Identity";
                const CALL: &'static str = "remove_sub";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct QuitSub;
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for QuitSub {
                const PALLET: &'static str = "Identity";
                const CALL: &'static str = "quit_sub";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct AddUsernameAuthority {
                pub authority: add_username_authority::Authority,
                pub suffix: add_username_authority::Suffix,
                pub allocation: add_username_authority::Allocation,
            }
            pub mod add_username_authority {
                use super::runtime_types;
                pub type Authority = ::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()>;
                pub type Suffix = ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>;
                pub type Allocation = ::core::primitive::u32;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for AddUsernameAuthority {
                const PALLET: &'static str = "Identity";
                const CALL: &'static str = "add_username_authority";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct RemoveUsernameAuthority {
                pub authority: remove_username_authority::Authority,
            }
            pub mod remove_username_authority {
                use super::runtime_types;
                pub type Authority = ::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()>;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for RemoveUsernameAuthority {
                const PALLET: &'static str = "Identity";
                const CALL: &'static str = "remove_username_authority";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct SetUsernameFor {
                pub who: set_username_for::Who,
                pub username: set_username_for::Username,
                pub signature: set_username_for::Signature,
            }
            pub mod set_username_for {
                use super::runtime_types;
                pub type Who = ::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()>;
                pub type Username = ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>;
                pub type Signature = ::core::option::Option<runtime_types::sp_runtime::MultiSignature>;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for SetUsernameFor {
                const PALLET: &'static str = "Identity";
                const CALL: &'static str = "set_username_for";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct AcceptUsername {
                pub username: accept_username::Username,
            }
            pub mod accept_username {
                use super::runtime_types;
                pub type Username = runtime_types::bounded_collections::bounded_vec::BoundedVec<::core::primitive::u8>;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for AcceptUsername {
                const PALLET: &'static str = "Identity";
                const CALL: &'static str = "accept_username";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct RemoveExpiredApproval {
                pub username: remove_expired_approval::Username,
            }
            pub mod remove_expired_approval {
                use super::runtime_types;
                pub type Username = runtime_types::bounded_collections::bounded_vec::BoundedVec<::core::primitive::u8>;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for RemoveExpiredApproval {
                const PALLET: &'static str = "Identity";
                const CALL: &'static str = "remove_expired_approval";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct SetPrimaryUsername {
                pub username: set_primary_username::Username,
            }
            pub mod set_primary_username {
                use super::runtime_types;
                pub type Username = runtime_types::bounded_collections::bounded_vec::BoundedVec<::core::primitive::u8>;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for SetPrimaryUsername {
                const PALLET: &'static str = "Identity";
                const CALL: &'static str = "set_primary_username";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct RemoveDanglingUsername {
                pub username: remove_dangling_username::Username,
            }
            pub mod remove_dangling_username {
                use super::runtime_types;
                pub type Username = runtime_types::bounded_collections::bounded_vec::BoundedVec<::core::primitive::u8>;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for RemoveDanglingUsername {
                const PALLET: &'static str = "Identity";
                const CALL: &'static str = "remove_dangling_username";
            }
        }
        pub struct TransactionApi;
        impl TransactionApi {
            pub fn add_registrar(&self, account: types::add_registrar::Account) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::AddRegistrar> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Identity", "add_registrar", types::AddRegistrar { account }, [6u8, 131u8, 82u8, 191u8, 37u8, 240u8, 158u8, 187u8, 247u8, 98u8, 175u8, 200u8, 147u8, 78u8, 88u8, 176u8, 227u8, 179u8, 184u8, 194u8, 91u8, 1u8, 1u8, 20u8, 121u8, 4u8, 96u8, 94u8, 103u8, 140u8, 247u8, 253u8, ]) }
            pub fn set_identity(&self, info: types::set_identity::Info) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::SetIdentity> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Identity", "set_identity", types::SetIdentity { info: ::subxt::ext::subxt_core::alloc::boxed::Box::new(info) }, [221u8, 212u8, 75u8, 9u8, 151u8, 97u8, 240u8, 192u8, 158u8, 89u8, 89u8, 217u8, 174u8, 120u8, 237u8, 10u8, 38u8, 240u8, 205u8, 139u8, 9u8, 229u8, 12u8, 151u8, 201u8, 173u8, 149u8, 146u8, 2u8, 20u8, 187u8, 145u8, ]) }
            pub fn set_subs(&self, subs: types::set_subs::Subs) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::SetSubs> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Identity", "set_subs", types::SetSubs { subs }, [34u8, 184u8, 18u8, 155u8, 112u8, 247u8, 235u8, 75u8, 209u8, 236u8, 21u8, 238u8, 43u8, 237u8, 223u8, 147u8, 48u8, 6u8, 39u8, 231u8, 174u8, 164u8, 243u8, 184u8, 220u8, 151u8, 165u8, 69u8, 219u8, 122u8, 234u8, 100u8, ]) }
            pub fn clear_identity(&self) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::ClearIdentity> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Identity", "clear_identity", types::ClearIdentity {}, [43u8, 115u8, 205u8, 44u8, 24u8, 130u8, 220u8, 69u8, 247u8, 176u8, 200u8, 175u8, 67u8, 183u8, 36u8, 200u8, 162u8, 132u8, 242u8, 25u8, 21u8, 106u8, 197u8, 219u8, 141u8, 51u8, 204u8, 13u8, 191u8, 201u8, 31u8, 31u8, ]) }
            pub fn request_judgement(&self, reg_index: types::request_judgement::RegIndex, max_fee: types::request_judgement::MaxFee) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::RequestJudgement> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Identity", "request_judgement", types::RequestJudgement { reg_index, max_fee }, [83u8, 85u8, 55u8, 184u8, 14u8, 54u8, 49u8, 212u8, 26u8, 148u8, 33u8, 147u8, 182u8, 54u8, 180u8, 12u8, 61u8, 179u8, 216u8, 157u8, 103u8, 52u8, 120u8, 252u8, 83u8, 203u8, 144u8, 65u8, 15u8, 3u8, 21u8, 33u8, ]) }
            pub fn cancel_request(&self, reg_index: types::cancel_request::RegIndex) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::CancelRequest> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Identity", "cancel_request", types::CancelRequest { reg_index }, [81u8, 14u8, 133u8, 219u8, 43u8, 84u8, 163u8, 208u8, 21u8, 185u8, 75u8, 117u8, 126u8, 33u8, 210u8, 106u8, 122u8, 210u8, 35u8, 207u8, 104u8, 206u8, 41u8, 117u8, 247u8, 108u8, 56u8, 23u8, 123u8, 169u8, 169u8, 61u8, ]) }
            pub fn set_fee(&self, index: types::set_fee::Index, fee: types::set_fee::Fee) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::SetFee> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Identity", "set_fee", types::SetFee { index, fee }, [131u8, 20u8, 17u8, 127u8, 180u8, 65u8, 225u8, 144u8, 193u8, 60u8, 131u8, 241u8, 30u8, 149u8, 8u8, 76u8, 29u8, 52u8, 102u8, 108u8, 127u8, 130u8, 70u8, 18u8, 94u8, 145u8, 179u8, 109u8, 252u8, 219u8, 58u8, 163u8, ]) }
            pub fn set_account_id(&self, index: types::set_account_id::Index, new: types::set_account_id::New) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::SetAccountId> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Identity", "set_account_id", types::SetAccountId { index, new }, [68u8, 57u8, 39u8, 134u8, 39u8, 82u8, 156u8, 107u8, 113u8, 99u8, 9u8, 163u8, 58u8, 249u8, 247u8, 208u8, 38u8, 203u8, 54u8, 153u8, 116u8, 143u8, 81u8, 46u8, 228u8, 149u8, 127u8, 115u8, 252u8, 83u8, 33u8, 101u8, ]) }
            pub fn set_fields(&self, index: types::set_fields::Index, fields: types::set_fields::Fields) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::SetFields> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Identity", "set_fields", types::SetFields { index, fields }, [75u8, 38u8, 58u8, 93u8, 92u8, 164u8, 146u8, 146u8, 183u8, 245u8, 135u8, 235u8, 12u8, 148u8, 37u8, 193u8, 58u8, 66u8, 173u8, 223u8, 166u8, 169u8, 54u8, 159u8, 141u8, 36u8, 25u8, 231u8, 190u8, 211u8, 254u8, 38u8, ]) }
            pub fn provide_judgement(&self, reg_index: types::provide_judgement::RegIndex, target: types::provide_judgement::Target, judgement: types::provide_judgement::Judgement, identity: types::provide_judgement::Identity) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::ProvideJudgement> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Identity", "provide_judgement", types::ProvideJudgement { reg_index, target, judgement, identity }, [145u8, 188u8, 61u8, 236u8, 183u8, 49u8, 49u8, 149u8, 240u8, 184u8, 202u8, 75u8, 69u8, 0u8, 95u8, 103u8, 132u8, 24u8, 107u8, 221u8, 236u8, 75u8, 231u8, 125u8, 39u8, 189u8, 45u8, 202u8, 116u8, 123u8, 236u8, 96u8, ]) }
            pub fn kill_identity(&self, target: types::kill_identity::Target) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::KillIdentity> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Identity", "kill_identity", types::KillIdentity { target }, [114u8, 249u8, 102u8, 62u8, 118u8, 105u8, 185u8, 61u8, 173u8, 52u8, 57u8, 190u8, 102u8, 74u8, 108u8, 239u8, 142u8, 176u8, 116u8, 51u8, 49u8, 197u8, 6u8, 183u8, 248u8, 202u8, 202u8, 140u8, 134u8, 59u8, 103u8, 182u8, ]) }
            pub fn add_sub(&self, sub: types::add_sub::Sub, data: types::add_sub::Data) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::AddSub> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Identity", "add_sub", types::AddSub { sub, data }, [3u8, 65u8, 137u8, 35u8, 238u8, 133u8, 56u8, 233u8, 37u8, 125u8, 221u8, 186u8, 153u8, 74u8, 69u8, 196u8, 244u8, 82u8, 51u8, 7u8, 216u8, 29u8, 18u8, 16u8, 198u8, 184u8, 0u8, 181u8, 71u8, 227u8, 144u8, 33u8, ]) }
            pub fn rename_sub(&self, sub: types::rename_sub::Sub, data: types::rename_sub::Data) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::RenameSub> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Identity", "rename_sub", types::RenameSub { sub, data }, [252u8, 50u8, 201u8, 112u8, 49u8, 248u8, 223u8, 239u8, 219u8, 226u8, 64u8, 68u8, 227u8, 20u8, 30u8, 24u8, 36u8, 77u8, 26u8, 235u8, 144u8, 240u8, 11u8, 111u8, 145u8, 167u8, 184u8, 207u8, 173u8, 58u8, 152u8, 202u8, ]) }
            pub fn remove_sub(&self, sub: types::remove_sub::Sub) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::RemoveSub> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Identity", "remove_sub", types::RemoveSub { sub }, [95u8, 249u8, 171u8, 27u8, 100u8, 186u8, 67u8, 214u8, 226u8, 6u8, 118u8, 39u8, 91u8, 122u8, 1u8, 87u8, 1u8, 226u8, 101u8, 9u8, 199u8, 167u8, 84u8, 202u8, 141u8, 196u8, 80u8, 195u8, 15u8, 114u8, 140u8, 144u8, ]) }
            pub fn quit_sub(&self) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::QuitSub> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Identity", "quit_sub", types::QuitSub {}, [147u8, 131u8, 175u8, 171u8, 187u8, 201u8, 240u8, 26u8, 146u8, 224u8, 74u8, 166u8, 242u8, 193u8, 204u8, 247u8, 168u8, 93u8, 18u8, 32u8, 27u8, 208u8, 149u8, 146u8, 179u8, 172u8, 75u8, 112u8, 84u8, 141u8, 233u8, 223u8, ]) }
            pub fn add_username_authority(&self, authority: types::add_username_authority::Authority, suffix: types::add_username_authority::Suffix, allocation: types::add_username_authority::Allocation) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::AddUsernameAuthority> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Identity", "add_username_authority", types::AddUsernameAuthority { authority, suffix, allocation }, [225u8, 197u8, 122u8, 209u8, 206u8, 241u8, 247u8, 232u8, 196u8, 110u8, 75u8, 157u8, 44u8, 181u8, 35u8, 75u8, 182u8, 219u8, 100u8, 64u8, 208u8, 112u8, 120u8, 229u8, 211u8, 69u8, 193u8, 214u8, 195u8, 98u8, 10u8, 25u8, ]) }
            pub fn remove_username_authority(&self, authority: types::remove_username_authority::Authority) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::RemoveUsernameAuthority> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Identity", "remove_username_authority", types::RemoveUsernameAuthority { authority }, [4u8, 182u8, 89u8, 1u8, 183u8, 15u8, 215u8, 48u8, 165u8, 97u8, 252u8, 54u8, 223u8, 18u8, 211u8, 227u8, 226u8, 230u8, 185u8, 71u8, 202u8, 95u8, 191u8, 6u8, 118u8, 144u8, 92u8, 98u8, 64u8, 243u8, 2u8, 137u8, ]) }
            pub fn set_username_for(&self, who: types::set_username_for::Who, username: types::set_username_for::Username, signature: types::set_username_for::Signature) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::SetUsernameFor> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Identity", "set_username_for", types::SetUsernameFor { who, username, signature }, [208u8, 124u8, 47u8, 129u8, 27u8, 182u8, 185u8, 76u8, 173u8, 187u8, 193u8, 4u8, 252u8, 195u8, 204u8, 101u8, 233u8, 33u8, 62u8, 6u8, 50u8, 20u8, 224u8, 26u8, 125u8, 192u8, 220u8, 56u8, 255u8, 249u8, 85u8, 50u8, ]) }
            pub fn accept_username(&self, username: types::accept_username::Username) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::AcceptUsername> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Identity", "accept_username", types::AcceptUsername { username }, [247u8, 162u8, 83u8, 250u8, 214u8, 7u8, 12u8, 253u8, 227u8, 4u8, 95u8, 71u8, 150u8, 218u8, 216u8, 86u8, 137u8, 37u8, 114u8, 188u8, 18u8, 232u8, 229u8, 179u8, 172u8, 251u8, 70u8, 29u8, 18u8, 86u8, 33u8, 129u8, ]) }
            pub fn remove_expired_approval(&self, username: types::remove_expired_approval::Username) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::RemoveExpiredApproval> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Identity", "remove_expired_approval", types::RemoveExpiredApproval { username }, [159u8, 171u8, 27u8, 97u8, 224u8, 171u8, 14u8, 89u8, 65u8, 213u8, 208u8, 67u8, 118u8, 146u8, 0u8, 131u8, 82u8, 186u8, 142u8, 52u8, 173u8, 90u8, 104u8, 107u8, 114u8, 202u8, 123u8, 222u8, 49u8, 53u8, 59u8, 61u8, ]) }
            pub fn set_primary_username(&self, username: types::set_primary_username::Username) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::SetPrimaryUsername> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Identity", "set_primary_username", types::SetPrimaryUsername { username }, [3u8, 25u8, 56u8, 26u8, 108u8, 165u8, 84u8, 231u8, 16u8, 4u8, 6u8, 232u8, 141u8, 7u8, 254u8, 50u8, 26u8, 230u8, 66u8, 245u8, 255u8, 101u8, 183u8, 234u8, 197u8, 186u8, 132u8, 197u8, 251u8, 84u8, 212u8, 162u8, ]) }
            pub fn remove_dangling_username(&self, username: types::remove_dangling_username::Username) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::RemoveDanglingUsername> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("Identity", "remove_dangling_username", types::RemoveDanglingUsername { username }, [220u8, 67u8, 52u8, 223u8, 169u8, 81u8, 202u8, 74u8, 199u8, 169u8, 89u8, 60u8, 57u8, 153u8, 240u8, 105u8, 188u8, 222u8, 250u8, 247u8, 91u8, 137u8, 37u8, 212u8, 10u8, 51u8, 9u8, 202u8, 165u8, 155u8, 222u8, 29u8, ]) }
        }
    }
    pub type Event = runtime_types::pallet_identity::pallet::Event;
    pub mod events {
        use super::runtime_types;
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct IdentitySet {
            pub who: identity_set::Who,
        }
        pub mod identity_set {
            use super::runtime_types;
            pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for IdentitySet {
            const PALLET: &'static str = "Identity";
            const EVENT: &'static str = "IdentitySet";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct IdentityCleared {
            pub who: identity_cleared::Who,
            pub deposit: identity_cleared::Deposit,
        }
        pub mod identity_cleared {
            use super::runtime_types;
            pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type Deposit = ::core::primitive::u128;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for IdentityCleared {
            const PALLET: &'static str = "Identity";
            const EVENT: &'static str = "IdentityCleared";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct IdentityKilled {
            pub who: identity_killed::Who,
            pub deposit: identity_killed::Deposit,
        }
        pub mod identity_killed {
            use super::runtime_types;
            pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type Deposit = ::core::primitive::u128;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for IdentityKilled {
            const PALLET: &'static str = "Identity";
            const EVENT: &'static str = "IdentityKilled";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct JudgementRequested {
            pub who: judgement_requested::Who,
            pub registrar_index: judgement_requested::RegistrarIndex,
        }
        pub mod judgement_requested {
            use super::runtime_types;
            pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type RegistrarIndex = ::core::primitive::u32;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for JudgementRequested {
            const PALLET: &'static str = "Identity";
            const EVENT: &'static str = "JudgementRequested";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct JudgementUnrequested {
            pub who: judgement_unrequested::Who,
            pub registrar_index: judgement_unrequested::RegistrarIndex,
        }
        pub mod judgement_unrequested {
            use super::runtime_types;
            pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type RegistrarIndex = ::core::primitive::u32;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for JudgementUnrequested {
            const PALLET: &'static str = "Identity";
            const EVENT: &'static str = "JudgementUnrequested";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct JudgementGiven {
            pub target: judgement_given::Target,
            pub registrar_index: judgement_given::RegistrarIndex,
        }
        pub mod judgement_given {
            use super::runtime_types;
            pub type Target = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type RegistrarIndex = ::core::primitive::u32;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for JudgementGiven {
            const PALLET: &'static str = "Identity";
            const EVENT: &'static str = "JudgementGiven";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct RegistrarAdded {
            pub registrar_index: registrar_added::RegistrarIndex,
        }
        pub mod registrar_added {
            use super::runtime_types;
            pub type RegistrarIndex = ::core::primitive::u32;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for RegistrarAdded {
            const PALLET: &'static str = "Identity";
            const EVENT: &'static str = "RegistrarAdded";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct SubIdentityAdded {
            pub sub: sub_identity_added::Sub,
            pub main: sub_identity_added::Main,
            pub deposit: sub_identity_added::Deposit,
        }
        pub mod sub_identity_added {
            use super::runtime_types;
            pub type Sub = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type Main = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type Deposit = ::core::primitive::u128;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for SubIdentityAdded {
            const PALLET: &'static str = "Identity";
            const EVENT: &'static str = "SubIdentityAdded";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct SubIdentityRemoved {
            pub sub: sub_identity_removed::Sub,
            pub main: sub_identity_removed::Main,
            pub deposit: sub_identity_removed::Deposit,
        }
        pub mod sub_identity_removed {
            use super::runtime_types;
            pub type Sub = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type Main = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type Deposit = ::core::primitive::u128;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for SubIdentityRemoved {
            const PALLET: &'static str = "Identity";
            const EVENT: &'static str = "SubIdentityRemoved";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct SubIdentityRevoked {
            pub sub: sub_identity_revoked::Sub,
            pub main: sub_identity_revoked::Main,
            pub deposit: sub_identity_revoked::Deposit,
        }
        pub mod sub_identity_revoked {
            use super::runtime_types;
            pub type Sub = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type Main = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type Deposit = ::core::primitive::u128;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for SubIdentityRevoked {
            const PALLET: &'static str = "Identity";
            const EVENT: &'static str = "SubIdentityRevoked";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct AuthorityAdded {
            pub authority: authority_added::Authority,
        }
        pub mod authority_added {
            use super::runtime_types;
            pub type Authority = ::subxt::ext::subxt_core::utils::AccountId32;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for AuthorityAdded {
            const PALLET: &'static str = "Identity";
            const EVENT: &'static str = "AuthorityAdded";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct AuthorityRemoved {
            pub authority: authority_removed::Authority,
        }
        pub mod authority_removed {
            use super::runtime_types;
            pub type Authority = ::subxt::ext::subxt_core::utils::AccountId32;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for AuthorityRemoved {
            const PALLET: &'static str = "Identity";
            const EVENT: &'static str = "AuthorityRemoved";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct UsernameSet {
            pub who: username_set::Who,
            pub username: username_set::Username,
        }
        pub mod username_set {
            use super::runtime_types;
            pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type Username = runtime_types::bounded_collections::bounded_vec::BoundedVec<::core::primitive::u8>;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for UsernameSet {
            const PALLET: &'static str = "Identity";
            const EVENT: &'static str = "UsernameSet";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct UsernameQueued {
            pub who: username_queued::Who,
            pub username: username_queued::Username,
            pub expiration: username_queued::Expiration,
        }
        pub mod username_queued {
            use super::runtime_types;
            pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type Username = runtime_types::bounded_collections::bounded_vec::BoundedVec<::core::primitive::u8>;
            pub type Expiration = ::core::primitive::u32;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for UsernameQueued {
            const PALLET: &'static str = "Identity";
            const EVENT: &'static str = "UsernameQueued";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct PreapprovalExpired {
            pub whose: preapproval_expired::Whose,
        }
        pub mod preapproval_expired {
            use super::runtime_types;
            pub type Whose = ::subxt::ext::subxt_core::utils::AccountId32;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for PreapprovalExpired {
            const PALLET: &'static str = "Identity";
            const EVENT: &'static str = "PreapprovalExpired";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct PrimaryUsernameSet {
            pub who: primary_username_set::Who,
            pub username: primary_username_set::Username,
        }
        pub mod primary_username_set {
            use super::runtime_types;
            pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type Username = runtime_types::bounded_collections::bounded_vec::BoundedVec<::core::primitive::u8>;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for PrimaryUsernameSet {
            const PALLET: &'static str = "Identity";
            const EVENT: &'static str = "PrimaryUsernameSet";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct DanglingUsernameRemoved {
            pub who: dangling_username_removed::Who,
            pub username: dangling_username_removed::Username,
        }
        pub mod dangling_username_removed {
            use super::runtime_types;
            pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type Username = runtime_types::bounded_collections::bounded_vec::BoundedVec<::core::primitive::u8>;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for DanglingUsernameRemoved {
            const PALLET: &'static str = "Identity";
            const EVENT: &'static str = "DanglingUsernameRemoved";
        }
    }
    pub mod storage {
        use super::runtime_types;
        pub mod types {
            use super::runtime_types;
            pub mod identity_of {
                use super::runtime_types;
                pub type IdentityOf = (runtime_types::pallet_identity::types::Registration<::core::primitive::u128, runtime_types::people_rococo_runtime::people::IdentityInfo>, ::core::option::Option<runtime_types::bounded_collections::bounded_vec::BoundedVec<::core::primitive::u8>>,);
                pub type Param0 = ::subxt::ext::subxt_core::utils::AccountId32;
            }
            pub mod super_of {
                use super::runtime_types;
                pub type SuperOf = (::subxt::ext::subxt_core::utils::AccountId32, runtime_types::pallet_identity::types::Data,);
                pub type Param0 = ::subxt::ext::subxt_core::utils::AccountId32;
            }
            pub mod subs_of {
                use super::runtime_types;
                pub type SubsOf = (::core::primitive::u128, runtime_types::bounded_collections::bounded_vec::BoundedVec<::subxt::ext::subxt_core::utils::AccountId32>,);
                pub type Param0 = ::subxt::ext::subxt_core::utils::AccountId32;
            }
            pub mod registrars {
                use super::runtime_types;
                pub type Registrars = runtime_types::bounded_collections::bounded_vec::BoundedVec<::core::option::Option<runtime_types::pallet_identity::types::RegistrarInfo<::core::primitive::u128, ::subxt::ext::subxt_core::utils::AccountId32, ::core::primitive::u64>>>;
            }
            pub mod username_authorities {
                use super::runtime_types;
                pub type UsernameAuthorities = runtime_types::pallet_identity::types::AuthorityProperties<runtime_types::bounded_collections::bounded_vec::BoundedVec<::core::primitive::u8>>;
                pub type Param0 = ::subxt::ext::subxt_core::utils::AccountId32;
            }
            pub mod account_of_username {
                use super::runtime_types;
                pub type AccountOfUsername = ::subxt::ext::subxt_core::utils::AccountId32;
                pub type Param0 = runtime_types::bounded_collections::bounded_vec::BoundedVec<::core::primitive::u8>;
            }
            pub mod pending_usernames {
                use super::runtime_types;
                pub type PendingUsernames = (::subxt::ext::subxt_core::utils::AccountId32, ::core::primitive::u32,);
                pub type Param0 = runtime_types::bounded_collections::bounded_vec::BoundedVec<::core::primitive::u8>;
            }
        }
        pub struct StorageApi;
        impl StorageApi {
            pub fn identity_of_iter(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::identity_of::IdentityOf, (), (), ::subxt::ext::subxt_core::utils::Yes> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Identity", "IdentityOf", (), [150u8, 8u8, 52u8, 88u8, 246u8, 82u8, 229u8, 62u8, 172u8, 30u8, 102u8, 182u8, 49u8, 76u8, 106u8, 226u8, 159u8, 217u8, 16u8, 1u8, 8u8, 216u8, 84u8, 165u8, 172u8, 100u8, 113u8, 137u8, 181u8, 6u8, 201u8, 245u8, ]) }
            pub fn identity_of(&self, _0: impl ::core::borrow::Borrow<types::identity_of::Param0>) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::identity_of::Param0>, types::identity_of::IdentityOf, ::subxt::ext::subxt_core::utils::Yes, (), ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Identity", "IdentityOf", ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0.borrow()), [150u8, 8u8, 52u8, 88u8, 246u8, 82u8, 229u8, 62u8, 172u8, 30u8, 102u8, 182u8, 49u8, 76u8, 106u8, 226u8, 159u8, 217u8, 16u8, 1u8, 8u8, 216u8, 84u8, 165u8, 172u8, 100u8, 113u8, 137u8, 181u8, 6u8, 201u8, 245u8, ]) }
            pub fn super_of_iter(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::super_of::SuperOf, (), (), ::subxt::ext::subxt_core::utils::Yes> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Identity", "SuperOf", (), [84u8, 72u8, 64u8, 14u8, 56u8, 9u8, 143u8, 100u8, 141u8, 163u8, 36u8, 55u8, 38u8, 254u8, 164u8, 17u8, 3u8, 110u8, 88u8, 175u8, 161u8, 65u8, 159u8, 40u8, 46u8, 8u8, 177u8, 81u8, 130u8, 38u8, 193u8, 28u8, ]) }
            pub fn super_of(&self, _0: impl ::core::borrow::Borrow<types::super_of::Param0>) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::super_of::Param0>, types::super_of::SuperOf, ::subxt::ext::subxt_core::utils::Yes, (), ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Identity", "SuperOf", ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0.borrow()), [84u8, 72u8, 64u8, 14u8, 56u8, 9u8, 143u8, 100u8, 141u8, 163u8, 36u8, 55u8, 38u8, 254u8, 164u8, 17u8, 3u8, 110u8, 88u8, 175u8, 161u8, 65u8, 159u8, 40u8, 46u8, 8u8, 177u8, 81u8, 130u8, 38u8, 193u8, 28u8, ]) }
            pub fn subs_of_iter(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::subs_of::SubsOf, (), ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Identity", "SubsOf", (), [164u8, 140u8, 52u8, 123u8, 220u8, 118u8, 147u8, 3u8, 67u8, 22u8, 191u8, 18u8, 186u8, 21u8, 154u8, 8u8, 205u8, 224u8, 163u8, 173u8, 174u8, 107u8, 144u8, 215u8, 116u8, 64u8, 159u8, 115u8, 159u8, 205u8, 91u8, 28u8, ]) }
            pub fn subs_of(&self, _0: impl ::core::borrow::Borrow<types::subs_of::Param0>) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::subs_of::Param0>, types::subs_of::SubsOf, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Identity", "SubsOf", ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0.borrow()), [164u8, 140u8, 52u8, 123u8, 220u8, 118u8, 147u8, 3u8, 67u8, 22u8, 191u8, 18u8, 186u8, 21u8, 154u8, 8u8, 205u8, 224u8, 163u8, 173u8, 174u8, 107u8, 144u8, 215u8, 116u8, 64u8, 159u8, 115u8, 159u8, 205u8, 91u8, 28u8, ]) }
            pub fn registrars(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::registrars::Registrars, ::subxt::ext::subxt_core::utils::Yes, ::subxt::ext::subxt_core::utils::Yes, ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Identity", "Registrars", (), [167u8, 99u8, 159u8, 117u8, 103u8, 243u8, 208u8, 113u8, 57u8, 225u8, 27u8, 25u8, 188u8, 120u8, 15u8, 40u8, 134u8, 169u8, 108u8, 134u8, 83u8, 184u8, 223u8, 170u8, 194u8, 19u8, 168u8, 43u8, 119u8, 76u8, 94u8, 154u8, ]) }
            pub fn username_authorities_iter(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::username_authorities::UsernameAuthorities, (), (), ::subxt::ext::subxt_core::utils::Yes> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Identity", "UsernameAuthorities", (), [89u8, 102u8, 60u8, 184u8, 127u8, 244u8, 3u8, 61u8, 209u8, 78u8, 178u8, 44u8, 159u8, 27u8, 7u8, 0u8, 22u8, 116u8, 42u8, 240u8, 130u8, 93u8, 214u8, 182u8, 79u8, 222u8, 19u8, 20u8, 34u8, 198u8, 164u8, 146u8, ]) }
            pub fn username_authorities(&self, _0: impl ::core::borrow::Borrow<types::username_authorities::Param0>) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::username_authorities::Param0>, types::username_authorities::UsernameAuthorities, ::subxt::ext::subxt_core::utils::Yes, (), ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Identity", "UsernameAuthorities", ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0.borrow()), [89u8, 102u8, 60u8, 184u8, 127u8, 244u8, 3u8, 61u8, 209u8, 78u8, 178u8, 44u8, 159u8, 27u8, 7u8, 0u8, 22u8, 116u8, 42u8, 240u8, 130u8, 93u8, 214u8, 182u8, 79u8, 222u8, 19u8, 20u8, 34u8, 198u8, 164u8, 146u8, ]) }
            pub fn account_of_username_iter(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::account_of_username::AccountOfUsername, (), (), ::subxt::ext::subxt_core::utils::Yes> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Identity", "AccountOfUsername", (), [131u8, 96u8, 207u8, 217u8, 223u8, 54u8, 51u8, 156u8, 8u8, 238u8, 134u8, 57u8, 42u8, 110u8, 180u8, 107u8, 30u8, 109u8, 162u8, 110u8, 178u8, 127u8, 151u8, 163u8, 89u8, 127u8, 181u8, 213u8, 74u8, 129u8, 207u8, 15u8, ]) }
            pub fn account_of_username(&self, _0: impl ::core::borrow::Borrow<types::account_of_username::Param0>) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::account_of_username::Param0>, types::account_of_username::AccountOfUsername, ::subxt::ext::subxt_core::utils::Yes, (), ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Identity", "AccountOfUsername", ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0.borrow()), [131u8, 96u8, 207u8, 217u8, 223u8, 54u8, 51u8, 156u8, 8u8, 238u8, 134u8, 57u8, 42u8, 110u8, 180u8, 107u8, 30u8, 109u8, 162u8, 110u8, 178u8, 127u8, 151u8, 163u8, 89u8, 127u8, 181u8, 213u8, 74u8, 129u8, 207u8, 15u8, ]) }
            pub fn pending_usernames_iter(&self) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<(), types::pending_usernames::PendingUsernames, (), (), ::subxt::ext::subxt_core::utils::Yes> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Identity", "PendingUsernames", (), [237u8, 213u8, 92u8, 249u8, 11u8, 169u8, 104u8, 7u8, 201u8, 133u8, 164u8, 64u8, 191u8, 172u8, 169u8, 229u8, 206u8, 105u8, 190u8, 113u8, 21u8, 13u8, 70u8, 74u8, 140u8, 125u8, 123u8, 48u8, 183u8, 181u8, 170u8, 147u8, ]) }
            pub fn pending_usernames(&self, _0: impl ::core::borrow::Borrow<types::pending_usernames::Param0>) -> ::subxt::ext::subxt_core::storage::address::StaticAddress::<::subxt::ext::subxt_core::storage::address::StaticStorageKey<types::pending_usernames::Param0>, types::pending_usernames::PendingUsernames, ::subxt::ext::subxt_core::utils::Yes, (), ()> { ::subxt::ext::subxt_core::storage::address::StaticAddress::new_static("Identity", "PendingUsernames", ::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0.borrow()), [237u8, 213u8, 92u8, 249u8, 11u8, 169u8, 104u8, 7u8, 201u8, 133u8, 164u8, 64u8, 191u8, 172u8, 169u8, 229u8, 206u8, 105u8, 190u8, 113u8, 21u8, 13u8, 70u8, 74u8, 140u8, 125u8, 123u8, 48u8, 183u8, 181u8, 170u8, 147u8, ]) }
        }
    }
    pub mod constants {
        use super::runtime_types;
        pub struct ConstantsApi;
        impl ConstantsApi {
            pub fn basic_deposit(&self) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<::core::primitive::u128> { ::subxt::ext::subxt_core::constants::address::StaticAddress::new_static("Identity", "BasicDeposit", [84u8, 157u8, 140u8, 4u8, 93u8, 57u8, 29u8, 133u8, 105u8, 200u8, 214u8, 27u8, 144u8, 208u8, 218u8, 160u8, 130u8, 109u8, 101u8, 54u8, 210u8, 136u8, 71u8, 63u8, 49u8, 237u8, 234u8, 15u8, 178u8, 98u8, 148u8, 156u8, ]) }
            pub fn byte_deposit(&self) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<::core::primitive::u128> { ::subxt::ext::subxt_core::constants::address::StaticAddress::new_static("Identity", "ByteDeposit", [84u8, 157u8, 140u8, 4u8, 93u8, 57u8, 29u8, 133u8, 105u8, 200u8, 214u8, 27u8, 144u8, 208u8, 218u8, 160u8, 130u8, 109u8, 101u8, 54u8, 210u8, 136u8, 71u8, 63u8, 49u8, 237u8, 234u8, 15u8, 178u8, 98u8, 148u8, 156u8, ]) }
            pub fn sub_account_deposit(&self) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<::core::primitive::u128> { ::subxt::ext::subxt_core::constants::address::StaticAddress::new_static("Identity", "SubAccountDeposit", [84u8, 157u8, 140u8, 4u8, 93u8, 57u8, 29u8, 133u8, 105u8, 200u8, 214u8, 27u8, 144u8, 208u8, 218u8, 160u8, 130u8, 109u8, 101u8, 54u8, 210u8, 136u8, 71u8, 63u8, 49u8, 237u8, 234u8, 15u8, 178u8, 98u8, 148u8, 156u8, ]) }
            pub fn max_sub_accounts(&self) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<::core::primitive::u32> { ::subxt::ext::subxt_core::constants::address::StaticAddress::new_static("Identity", "MaxSubAccounts", [98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8, 125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8, 178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8, 145u8, ]) }
            pub fn max_registrars(&self) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<::core::primitive::u32> { ::subxt::ext::subxt_core::constants::address::StaticAddress::new_static("Identity", "MaxRegistrars", [98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8, 125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8, 178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8, 145u8, ]) }
            pub fn pending_username_expiration(&self) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<::core::primitive::u32> { ::subxt::ext::subxt_core::constants::address::StaticAddress::new_static("Identity", "PendingUsernameExpiration", [98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8, 125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8, 178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8, 145u8, ]) }
            pub fn max_suffix_length(&self) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<::core::primitive::u32> { ::subxt::ext::subxt_core::constants::address::StaticAddress::new_static("Identity", "MaxSuffixLength", [98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8, 125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8, 178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8, 145u8, ]) }
            pub fn max_username_length(&self) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<::core::primitive::u32> { ::subxt::ext::subxt_core::constants::address::StaticAddress::new_static("Identity", "MaxUsernameLength", [98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8, 125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8, 178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8, 145u8, ]) }
        }
    }
}
pub mod identity_migrator {
    use super::root_mod;
    use super::runtime_types;
    pub type Call = runtime_types::polkadot_runtime_common::identity_migrator::pallet::Call;
    pub mod calls {
        use super::root_mod;
        use super::runtime_types;
        type DispatchError = runtime_types::sp_runtime::DispatchError;
        pub mod types {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct ReapIdentity {
                pub who: reap_identity::Who,
            }
            pub mod reap_identity {
                use super::runtime_types;
                pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for ReapIdentity {
                const PALLET: &'static str = "IdentityMigrator";
                const CALL: &'static str = "reap_identity";
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct PokeDeposit {
                pub who: poke_deposit::Who,
            }
            pub mod poke_deposit {
                use super::runtime_types;
                pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
            }
            impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for PokeDeposit {
                const PALLET: &'static str = "IdentityMigrator";
                const CALL: &'static str = "poke_deposit";
            }
        }
        pub struct TransactionApi;
        impl TransactionApi {
            pub fn reap_identity(&self, who: types::reap_identity::Who) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::ReapIdentity> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("IdentityMigrator", "reap_identity", types::ReapIdentity { who }, [187u8, 110u8, 202u8, 220u8, 54u8, 240u8, 242u8, 171u8, 5u8, 83u8, 129u8, 93u8, 213u8, 208u8, 21u8, 236u8, 121u8, 128u8, 127u8, 121u8, 153u8, 118u8, 232u8, 44u8, 20u8, 124u8, 214u8, 185u8, 249u8, 182u8, 136u8, 96u8, ]) }
            pub fn poke_deposit(&self, who: types::poke_deposit::Who) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::PokeDeposit> { ::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static("IdentityMigrator", "poke_deposit", types::PokeDeposit { who }, [42u8, 67u8, 168u8, 124u8, 75u8, 32u8, 143u8, 173u8, 14u8, 28u8, 76u8, 35u8, 196u8, 255u8, 250u8, 33u8, 128u8, 159u8, 132u8, 124u8, 51u8, 243u8, 166u8, 55u8, 208u8, 101u8, 188u8, 133u8, 36u8, 18u8, 119u8, 146u8, ]) }
        }
    }
    pub type Event = runtime_types::polkadot_runtime_common::identity_migrator::pallet::Event;
    pub mod events {
        use super::runtime_types;
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct IdentityReaped {
            pub who: identity_reaped::Who,
        }
        pub mod identity_reaped {
            use super::runtime_types;
            pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for IdentityReaped {
            const PALLET: &'static str = "IdentityMigrator";
            const EVENT: &'static str = "IdentityReaped";
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct DepositUpdated {
            pub who: deposit_updated::Who,
            pub identity: deposit_updated::Identity,
            pub subs: deposit_updated::Subs,
        }
        pub mod deposit_updated {
            use super::runtime_types;
            pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
            pub type Identity = ::core::primitive::u128;
            pub type Subs = ::core::primitive::u128;
        }
        impl ::subxt::ext::subxt_core::events::StaticEvent for DepositUpdated {
            const PALLET: &'static str = "IdentityMigrator";
            const EVENT: &'static str = "DepositUpdated";
        }
    }
}
pub mod runtime_types {
    use super::runtime_types;
    pub mod bounded_collections {
        use super::runtime_types;
        pub mod bounded_btree_set {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct BoundedBTreeSet<_0>   (pub ::subxt::ext::subxt_core::alloc::vec::Vec<_0>);
        }
        pub mod bounded_vec {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct BoundedVec<_0>   (pub ::subxt::ext::subxt_core::alloc::vec::Vec<_0>);
        }
        pub mod weak_bounded_vec {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct WeakBoundedVec<_0>   (pub ::subxt::ext::subxt_core::alloc::vec::Vec<_0>);
        }
    }
    pub mod cumulus_pallet_parachain_system {
        use super::runtime_types;
        pub mod pallet {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Call {
                #[codec(
                    index = 0
                )] set_validation_data { data: runtime_types::cumulus_primitives_parachain_inherent::ParachainInherentData },
                #[codec(
                    index = 1
                )] sudo_send_upward_message { message: ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8> },
                #[codec(
                    index = 2
                )] authorize_upgrade { code_hash: ::subxt::ext::subxt_core::utils::H256, check_version: ::core::primitive::bool },
                #[codec(
                    index = 3
                )] enact_authorized_upgrade { code: ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8> },
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Error {
                #[codec(index = 0)] OverlappingUpgrades,
                #[codec(
                    index = 1
                )] ProhibitedByPolkadot,
                #[codec(index = 2)] TooBig,
                #[codec(index = 3)] ValidationDataNotAvailable,
                #[codec(index = 4)] HostConfigurationNotAvailable,
                #[codec(index = 5)] NotScheduled,
                #[codec(index = 6)] NothingAuthorized,
                #[codec(index = 7)] Unauthorized,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Event {
                #[codec(index = 0)] ValidationFunctionStored,
                #[codec(
                    index = 1
                )] ValidationFunctionApplied { relay_chain_block_num: ::core::primitive::u32 },
                #[codec(index = 2)] ValidationFunctionDiscarded,
                #[codec(index = 3)] DownwardMessagesReceived { count: ::core::primitive::u32 },
                #[codec(
                    index = 4
                )] DownwardMessagesProcessed { weight_used: runtime_types::sp_weights::weight_v2::Weight, dmq_head: ::subxt::ext::subxt_core::utils::H256 },
                #[codec(
                    index = 5
                )] UpwardMessageSent { message_hash: ::core::option::Option<[::core::primitive::u8; 32usize]> },
            }
        }
        pub mod relay_state_snapshot {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct MessagingStateSnapshot {
                pub dmq_mqc_head: ::subxt::ext::subxt_core::utils::H256,
                pub relay_dispatch_queue_remaining_capacity: runtime_types::cumulus_pallet_parachain_system::relay_state_snapshot::RelayDispatchQueueRemainingCapacity,
                pub ingress_channels: ::subxt::ext::subxt_core::alloc::vec::Vec<(runtime_types::polkadot_parachain_primitives::primitives::Id, runtime_types::polkadot_primitives::v7::AbridgedHrmpChannel,)>,
                pub egress_channels: ::subxt::ext::subxt_core::alloc::vec::Vec<(runtime_types::polkadot_parachain_primitives::primitives::Id, runtime_types::polkadot_primitives::v7::AbridgedHrmpChannel,)>,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct RelayDispatchQueueRemainingCapacity {
                pub remaining_count: ::core::primitive::u32,
                pub remaining_size: ::core::primitive::u32,
            }
        }
        pub mod unincluded_segment {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct Ancestor<_0> {
                pub used_bandwidth: runtime_types::cumulus_pallet_parachain_system::unincluded_segment::UsedBandwidth,
                pub para_head_hash: ::core::option::Option<_0>,
                pub consumed_go_ahead_signal: ::core::option::Option<runtime_types::polkadot_primitives::v7::UpgradeGoAhead>,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct HrmpChannelUpdate {
                pub msg_count: ::core::primitive::u32,
                pub total_bytes: ::core::primitive::u32,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct SegmentTracker<_0> {
                pub used_bandwidth: runtime_types::cumulus_pallet_parachain_system::unincluded_segment::UsedBandwidth,
                pub hrmp_watermark: ::core::option::Option<::core::primitive::u32>,
                pub consumed_go_ahead_signal: ::core::option::Option<runtime_types::polkadot_primitives::v7::UpgradeGoAhead>,
                #[codec(skip)] pub __ignore: ::core::marker::PhantomData<_0>,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct UsedBandwidth {
                pub ump_msg_count: ::core::primitive::u32,
                pub ump_total_bytes: ::core::primitive::u32,
                pub hrmp_outgoing: ::subxt::ext::subxt_core::utils::KeyedVec<runtime_types::polkadot_parachain_primitives::primitives::Id, runtime_types::cumulus_pallet_parachain_system::unincluded_segment::HrmpChannelUpdate>,
            }
        }
    }
    pub mod cumulus_pallet_xcm {
        use super::runtime_types;
        pub mod pallet {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Call {}
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Event {
                #[codec(
                    index = 0
                )] InvalidFormat([::core::primitive::u8; 32usize]),
                #[codec(index = 1)] UnsupportedVersion([::core::primitive::u8; 32usize]),
                #[codec(
                    index = 2
                )] ExecutedDownward([::core::primitive::u8; 32usize], runtime_types::staging_xcm::v4::traits::Outcome),
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Origin {
                #[codec(index = 0)] Relay,
                #[codec(
                    index = 1
                )] SiblingParachain(runtime_types::polkadot_parachain_primitives::primitives::Id),
            }
        }
    }
    pub mod cumulus_pallet_xcmp_queue {
        use super::runtime_types;
        pub mod pallet {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Call {
                #[codec(index = 1)] suspend_xcm_execution,
                #[codec(
                    index = 2
                )] resume_xcm_execution,
                #[codec(index = 3)] update_suspend_threshold { new: ::core::primitive::u32 },
                #[codec(index = 4)] update_drop_threshold { new: ::core::primitive::u32 },
                #[codec(index = 5)] update_resume_threshold { new: ::core::primitive::u32 },
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Error {
                #[codec(index = 0)] BadQueueConfig,
                #[codec(
                    index = 1
                )] AlreadySuspended,
                #[codec(index = 2)] AlreadyResumed,
                #[codec(index = 3)] TooManyActiveOutboundChannels,
                #[codec(index = 4)] TooBig,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Event {
                #[codec(
                    index = 0
                )] XcmpMessageSent { message_hash: [::core::primitive::u8; 32usize] },
            }
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct OutboundChannelDetails {
            pub recipient: runtime_types::polkadot_parachain_primitives::primitives::Id,
            pub state: runtime_types::cumulus_pallet_xcmp_queue::OutboundState,
            pub signals_exist: ::core::primitive::bool,
            pub first_index: ::core::primitive::u16,
            pub last_index: ::core::primitive::u16,
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub enum OutboundState { #[codec(index = 0)] Ok, #[codec(index = 1)] Suspended }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct QueueConfigData {
            pub suspend_threshold: ::core::primitive::u32,
            pub drop_threshold: ::core::primitive::u32,
            pub resume_threshold: ::core::primitive::u32,
        }
    }
    pub mod cumulus_primitives_core {
        use super::runtime_types;
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub enum AggregateMessageOrigin {
            #[codec(index = 0)] Here,
            #[codec(
                index = 1
            )] Parent,
            #[codec(
                index = 2
            )] Sibling(runtime_types::polkadot_parachain_primitives::primitives::Id),
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct CollationInfo {
            pub upward_messages: ::subxt::ext::subxt_core::alloc::vec::Vec<::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>>,
            pub horizontal_messages: ::subxt::ext::subxt_core::alloc::vec::Vec<runtime_types::polkadot_core_primitives::OutboundHrmpMessage<runtime_types::polkadot_parachain_primitives::primitives::Id>>,
            pub new_validation_code: ::core::option::Option<runtime_types::polkadot_parachain_primitives::primitives::ValidationCode>,
            pub processed_downward_messages: ::core::primitive::u32,
            pub hrmp_watermark: ::core::primitive::u32,
            pub head_data: runtime_types::polkadot_parachain_primitives::primitives::HeadData,
        }
    }
    pub mod cumulus_primitives_parachain_inherent {
        use super::runtime_types;
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct MessageQueueChain(pub ::subxt::ext::subxt_core::utils::H256);
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct ParachainInherentData {
            pub validation_data: runtime_types::polkadot_primitives::v7::PersistedValidationData<::subxt::ext::subxt_core::utils::H256, ::core::primitive::u32>,
            pub relay_chain_state: runtime_types::sp_trie::storage_proof::StorageProof,
            pub downward_messages: ::subxt::ext::subxt_core::alloc::vec::Vec<runtime_types::polkadot_core_primitives::InboundDownwardMessage<::core::primitive::u32>>,
            pub horizontal_messages: ::subxt::ext::subxt_core::utils::KeyedVec<runtime_types::polkadot_parachain_primitives::primitives::Id, ::subxt::ext::subxt_core::alloc::vec::Vec<runtime_types::polkadot_core_primitives::InboundHrmpMessage<::core::primitive::u32>>>,
        }
    }
    pub mod cumulus_primitives_storage_weight_reclaim {
        use super::runtime_types;
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct StorageWeightReclaim;
    }
    pub mod frame_support {
        use super::runtime_types;
        pub mod dispatch {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum DispatchClass {
                #[codec(index = 0)] Normal,
                #[codec(
                    index = 1
                )] Operational,
                #[codec(index = 2)] Mandatory,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct DispatchInfo {
                pub weight: runtime_types::sp_weights::weight_v2::Weight,
                pub class: runtime_types::frame_support::dispatch::DispatchClass,
                pub pays_fee: runtime_types::frame_support::dispatch::Pays,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Pays { #[codec(index = 0)] Yes, #[codec(index = 1)] No }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct PerDispatchClass<_0> {
                pub normal: _0,
                pub operational: _0,
                pub mandatory: _0,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct PostDispatchInfo {
                pub actual_weight: ::core::option::Option<runtime_types::sp_weights::weight_v2::Weight>,
                pub pays_fee: runtime_types::frame_support::dispatch::Pays,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum RawOrigin<_0> {
                #[codec(index = 0)] Root,
                #[codec(
                    index = 1
                )] Signed(_0),
                #[codec(index = 2)] None,
            }
        }
        pub mod traits {
            use super::runtime_types;
            pub mod messages {
                use super::runtime_types;
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub enum ProcessMessageError {
                    #[codec(index = 0)] BadFormat,
                    #[codec(
                        index = 1
                    )] Corrupt,
                    #[codec(index = 2)] Unsupported,
                    #[codec(
                        index = 3
                    )] Overweight(runtime_types::sp_weights::weight_v2::Weight),
                    #[codec(index = 4)] Yield,
                    #[codec(index = 5)] StackLimitReached,
                }
            }
            pub mod tokens {
                use super::runtime_types;
                pub mod misc {
                    use super::runtime_types;
                    #[derive(
                        ::subxt::ext::subxt_core::ext::codec::Decode,
                        ::subxt::ext::subxt_core::ext::codec::Encode,
                        ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                        ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                        Debug
                    )]
                    #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                    )]
                    #[decode_as_type(
                        crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                    )]
                    #[encode_as_type(
                        crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                    )]
                    pub enum BalanceStatus {
                        #[codec(index = 0)] Free,
                        #[codec(
                            index = 1
                        )] Reserved,
                    }
                }
            }
        }
    }
    pub mod frame_system {
        use super::runtime_types;
        pub mod extensions {
            use super::runtime_types;
            pub mod check_genesis {
                use super::runtime_types;
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub struct CheckGenesis;
            }
            pub mod check_mortality {
                use super::runtime_types;
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub struct CheckMortality(pub runtime_types::sp_runtime::generic::era::Era);
            }
            pub mod check_non_zero_sender {
                use super::runtime_types;
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub struct CheckNonZeroSender;
            }
            pub mod check_nonce {
                use super::runtime_types;
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub struct CheckNonce(#[codec(compact)] pub ::core::primitive::u32);
            }
            pub mod check_spec_version {
                use super::runtime_types;
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub struct CheckSpecVersion;
            }
            pub mod check_tx_version {
                use super::runtime_types;
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub struct CheckTxVersion;
            }
            pub mod check_weight {
                use super::runtime_types;
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub struct CheckWeight;
            }
        }
        pub mod limits {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct BlockLength {
                pub max: runtime_types::frame_support::dispatch::PerDispatchClass<::core::primitive::u32>,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct BlockWeights {
                pub base_block: runtime_types::sp_weights::weight_v2::Weight,
                pub max_block: runtime_types::sp_weights::weight_v2::Weight,
                pub per_class: runtime_types::frame_support::dispatch::PerDispatchClass<runtime_types::frame_system::limits::WeightsPerClass>,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct WeightsPerClass {
                pub base_extrinsic: runtime_types::sp_weights::weight_v2::Weight,
                pub max_extrinsic: ::core::option::Option<runtime_types::sp_weights::weight_v2::Weight>,
                pub max_total: ::core::option::Option<runtime_types::sp_weights::weight_v2::Weight>,
                pub reserved: ::core::option::Option<runtime_types::sp_weights::weight_v2::Weight>,
            }
        }
        pub mod pallet {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Call {
                #[codec(
                    index = 0
                )] remark { remark: ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8> },
                #[codec(index = 1)] set_heap_pages { pages: ::core::primitive::u64 },
                #[codec(
                    index = 2
                )] set_code { code: ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8> },
                #[codec(
                    index = 3
                )] set_code_without_checks { code: ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8> },
                #[codec(
                    index = 4
                )] set_storage { items: ::subxt::ext::subxt_core::alloc::vec::Vec<(::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>, ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>,)> },
                #[codec(
                    index = 5
                )] kill_storage { keys: ::subxt::ext::subxt_core::alloc::vec::Vec<::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>> },
                #[codec(
                    index = 6
                )] kill_prefix { prefix: ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>, subkeys: ::core::primitive::u32 },
                #[codec(
                    index = 7
                )] remark_with_event { remark: ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8> },
                #[codec(
                    index = 9
                )] authorize_upgrade { code_hash: ::subxt::ext::subxt_core::utils::H256 },
                #[codec(
                    index = 10
                )] authorize_upgrade_without_checks { code_hash: ::subxt::ext::subxt_core::utils::H256 },
                #[codec(
                    index = 11
                )] apply_authorized_upgrade { code: ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8> },
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Error {
                #[codec(index = 0)] InvalidSpecName,
                #[codec(
                    index = 1
                )] SpecVersionNeedsToIncrease,
                #[codec(index = 2)] FailedToExtractRuntimeVersion,
                #[codec(index = 3)] NonDefaultComposite,
                #[codec(index = 4)] NonZeroRefCount,
                #[codec(index = 5)] CallFiltered,
                #[codec(index = 6)] MultiBlockMigrationsOngoing,
                #[codec(index = 7)] NothingAuthorized,
                #[codec(index = 8)] Unauthorized,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Event {
                #[codec(
                    index = 0
                )] ExtrinsicSuccess { dispatch_info: runtime_types::frame_support::dispatch::DispatchInfo },
                #[codec(
                    index = 1
                )] ExtrinsicFailed { dispatch_error: runtime_types::sp_runtime::DispatchError, dispatch_info: runtime_types::frame_support::dispatch::DispatchInfo },
                #[codec(index = 2)] CodeUpdated,
                #[codec(
                    index = 3
                )] NewAccount { account: ::subxt::ext::subxt_core::utils::AccountId32 },
                #[codec(
                    index = 4
                )] KilledAccount { account: ::subxt::ext::subxt_core::utils::AccountId32 },
                #[codec(
                    index = 5
                )] Remarked { sender: ::subxt::ext::subxt_core::utils::AccountId32, hash: ::subxt::ext::subxt_core::utils::H256 },
                #[codec(
                    index = 6
                )] UpgradeAuthorized { code_hash: ::subxt::ext::subxt_core::utils::H256, check_version: ::core::primitive::bool },
            }
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct AccountInfo<_0, _1> {
            pub nonce: _0,
            pub consumers: ::core::primitive::u32,
            pub providers: ::core::primitive::u32,
            pub sufficients: ::core::primitive::u32,
            pub data: _1,
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct CodeUpgradeAuthorization {
            pub code_hash: ::subxt::ext::subxt_core::utils::H256,
            pub check_version: ::core::primitive::bool,
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct EventRecord<_0, _1> {
            pub phase: runtime_types::frame_system::Phase,
            pub event: _0,
            pub topics: ::subxt::ext::subxt_core::alloc::vec::Vec<_1>,
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct LastRuntimeUpgradeInfo {
            #[codec(compact)] pub spec_version: ::core::primitive::u32,
            pub spec_name: ::subxt::ext::subxt_core::alloc::string::String,
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub enum Phase {
            #[codec(index = 0)] ApplyExtrinsic(::core::primitive::u32),
            #[codec(
                index = 1
            )] Finalization,
            #[codec(index = 2)] Initialization,
        }
    }
    pub mod pallet_balances {
        use super::runtime_types;
        pub mod pallet {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Call {
                #[codec(
                    index = 0
                )] transfer_allow_death {
                    dest: ::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()>,
                    #[codec(
                        compact
                    )] value: ::core::primitive::u128,
                },
                #[codec(
                    index = 2
                )] force_transfer {
                    source: ::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()>,
                    dest: ::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()>,
                    #[codec(
                        compact
                    )] value: ::core::primitive::u128,
                },
                #[codec(
                    index = 3
                )] transfer_keep_alive {
                    dest: ::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()>,
                    #[codec(
                        compact
                    )] value: ::core::primitive::u128,
                },
                #[codec(
                    index = 4
                )] transfer_all { dest: ::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()>, keep_alive: ::core::primitive::bool },
                #[codec(
                    index = 5
                )] force_unreserve { who: ::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()>, amount: ::core::primitive::u128 },
                #[codec(
                    index = 6
                )] upgrade_accounts { who: ::subxt::ext::subxt_core::alloc::vec::Vec<::subxt::ext::subxt_core::utils::AccountId32> },
                #[codec(
                    index = 8
                )] force_set_balance {
                    who: ::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()>,
                    #[codec(
                        compact
                    )] new_free: ::core::primitive::u128,
                },
                #[codec(
                    index = 9
                )] force_adjust_total_issuance {
                    direction: runtime_types::pallet_balances::types::AdjustmentDirection,
                    #[codec(
                        compact
                    )] delta: ::core::primitive::u128,
                },
                #[codec(index = 10)] burn {
                    #[codec(
                        compact
                    )] value: ::core::primitive::u128,
                    keep_alive: ::core::primitive::bool,
                },
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Error {
                #[codec(index = 0)] VestingBalance,
                #[codec(
                    index = 1
                )] LiquidityRestrictions,
                #[codec(index = 2)] InsufficientBalance,
                #[codec(index = 3)] ExistentialDeposit,
                #[codec(index = 4)] Expendability,
                #[codec(index = 5)] ExistingVestingSchedule,
                #[codec(index = 6)] DeadAccount,
                #[codec(index = 7)] TooManyReserves,
                #[codec(index = 8)] TooManyHolds,
                #[codec(index = 9)] TooManyFreezes,
                #[codec(index = 10)] IssuanceDeactivated,
                #[codec(index = 11)] DeltaZero,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Event {
                #[codec(
                    index = 0
                )] Endowed { account: ::subxt::ext::subxt_core::utils::AccountId32, free_balance: ::core::primitive::u128 },
                #[codec(
                    index = 1
                )] DustLost { account: ::subxt::ext::subxt_core::utils::AccountId32, amount: ::core::primitive::u128 },
                #[codec(
                    index = 2
                )] Transfer { from: ::subxt::ext::subxt_core::utils::AccountId32, to: ::subxt::ext::subxt_core::utils::AccountId32, amount: ::core::primitive::u128 },
                #[codec(
                    index = 3
                )] BalanceSet { who: ::subxt::ext::subxt_core::utils::AccountId32, free: ::core::primitive::u128 },
                #[codec(
                    index = 4
                )] Reserved { who: ::subxt::ext::subxt_core::utils::AccountId32, amount: ::core::primitive::u128 },
                #[codec(
                    index = 5
                )] Unreserved { who: ::subxt::ext::subxt_core::utils::AccountId32, amount: ::core::primitive::u128 },
                #[codec(
                    index = 6
                )] ReserveRepatriated { from: ::subxt::ext::subxt_core::utils::AccountId32, to: ::subxt::ext::subxt_core::utils::AccountId32, amount: ::core::primitive::u128, destination_status: runtime_types::frame_support::traits::tokens::misc::BalanceStatus },
                #[codec(
                    index = 7
                )] Deposit { who: ::subxt::ext::subxt_core::utils::AccountId32, amount: ::core::primitive::u128 },
                #[codec(
                    index = 8
                )] Withdraw { who: ::subxt::ext::subxt_core::utils::AccountId32, amount: ::core::primitive::u128 },
                #[codec(
                    index = 9
                )] Slashed { who: ::subxt::ext::subxt_core::utils::AccountId32, amount: ::core::primitive::u128 },
                #[codec(
                    index = 10
                )] Minted { who: ::subxt::ext::subxt_core::utils::AccountId32, amount: ::core::primitive::u128 },
                #[codec(
                    index = 11
                )] Burned { who: ::subxt::ext::subxt_core::utils::AccountId32, amount: ::core::primitive::u128 },
                #[codec(
                    index = 12
                )] Suspended { who: ::subxt::ext::subxt_core::utils::AccountId32, amount: ::core::primitive::u128 },
                #[codec(
                    index = 13
                )] Restored { who: ::subxt::ext::subxt_core::utils::AccountId32, amount: ::core::primitive::u128 },
                #[codec(
                    index = 14
                )] Upgraded { who: ::subxt::ext::subxt_core::utils::AccountId32 },
                #[codec(index = 15)] Issued { amount: ::core::primitive::u128 },
                #[codec(index = 16)] Rescinded { amount: ::core::primitive::u128 },
                #[codec(
                    index = 17
                )] Locked { who: ::subxt::ext::subxt_core::utils::AccountId32, amount: ::core::primitive::u128 },
                #[codec(
                    index = 18
                )] Unlocked { who: ::subxt::ext::subxt_core::utils::AccountId32, amount: ::core::primitive::u128 },
                #[codec(
                    index = 19
                )] Frozen { who: ::subxt::ext::subxt_core::utils::AccountId32, amount: ::core::primitive::u128 },
                #[codec(
                    index = 20
                )] Thawed { who: ::subxt::ext::subxt_core::utils::AccountId32, amount: ::core::primitive::u128 },
                #[codec(
                    index = 21
                )] TotalIssuanceForced { old: ::core::primitive::u128, new: ::core::primitive::u128 },
            }
        }
        pub mod types {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct AccountData<_0> {
                pub free: _0,
                pub reserved: _0,
                pub frozen: _0,
                pub flags: runtime_types::pallet_balances::types::ExtraFlags,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum AdjustmentDirection {
                #[codec(index = 0)] Increase,
                #[codec(
                    index = 1
                )] Decrease,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct BalanceLock<_0> {
                pub id: [::core::primitive::u8; 8usize],
                pub amount: _0,
                pub reasons: runtime_types::pallet_balances::types::Reasons,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::CompactAs,
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct ExtraFlags(pub ::core::primitive::u128);
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct IdAmount<_0, _1> {
                pub id: _0,
                pub amount: _1,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Reasons {
                #[codec(index = 0)] Fee,
                #[codec(index = 1)] Misc,
                #[codec(
                    index = 2
                )] All,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct ReserveData<_0, _1> {
                pub id: _0,
                pub amount: _1,
            }
        }
    }
    pub mod pallet_collator_selection {
        use super::runtime_types;
        pub mod pallet {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Call {
                #[codec(
                    index = 0
                )] set_invulnerables { new: ::subxt::ext::subxt_core::alloc::vec::Vec<::subxt::ext::subxt_core::utils::AccountId32> },
                #[codec(index = 1)] set_desired_candidates { max: ::core::primitive::u32 },
                #[codec(index = 2)] set_candidacy_bond { bond: ::core::primitive::u128 },
                #[codec(index = 3)] register_as_candidate,
                #[codec(index = 4)] leave_intent,
                #[codec(
                    index = 5
                )] add_invulnerable { who: ::subxt::ext::subxt_core::utils::AccountId32 },
                #[codec(
                    index = 6
                )] remove_invulnerable { who: ::subxt::ext::subxt_core::utils::AccountId32 },
                #[codec(index = 7)] update_bond { new_deposit: ::core::primitive::u128 },
                #[codec(
                    index = 8
                )] take_candidate_slot { deposit: ::core::primitive::u128, target: ::subxt::ext::subxt_core::utils::AccountId32 },
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct CandidateInfo<_0, _1> {
                pub who: _0,
                pub deposit: _1,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Error {
                #[codec(index = 0)] TooManyCandidates,
                #[codec(index = 1)] TooFewEligibleCollators,
                #[codec(index = 2)] AlreadyCandidate,
                #[codec(index = 3)] NotCandidate,
                #[codec(index = 4)] TooManyInvulnerables,
                #[codec(index = 5)] AlreadyInvulnerable,
                #[codec(index = 6)] NotInvulnerable,
                #[codec(index = 7)] NoAssociatedValidatorId,
                #[codec(index = 8)] ValidatorNotRegistered,
                #[codec(index = 9)] InsertToCandidateListFailed,
                #[codec(index = 10)] RemoveFromCandidateListFailed,
                #[codec(index = 11)] DepositTooLow,
                #[codec(index = 12)] UpdateCandidateListFailed,
                #[codec(index = 13)] InsufficientBond,
                #[codec(index = 14)] TargetIsNotCandidate,
                #[codec(index = 15)] IdenticalDeposit,
                #[codec(index = 16)] InvalidUnreserve,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Event {
                #[codec(
                    index = 0
                )] NewInvulnerables { invulnerables: ::subxt::ext::subxt_core::alloc::vec::Vec<::subxt::ext::subxt_core::utils::AccountId32> },
                #[codec(
                    index = 1
                )] InvulnerableAdded { account_id: ::subxt::ext::subxt_core::utils::AccountId32 },
                #[codec(
                    index = 2
                )] InvulnerableRemoved { account_id: ::subxt::ext::subxt_core::utils::AccountId32 },
                #[codec(
                    index = 3
                )] NewDesiredCandidates { desired_candidates: ::core::primitive::u32 },
                #[codec(index = 4)] NewCandidacyBond { bond_amount: ::core::primitive::u128 },
                #[codec(
                    index = 5
                )] CandidateAdded { account_id: ::subxt::ext::subxt_core::utils::AccountId32, deposit: ::core::primitive::u128 },
                #[codec(
                    index = 6
                )] CandidateBondUpdated { account_id: ::subxt::ext::subxt_core::utils::AccountId32, deposit: ::core::primitive::u128 },
                #[codec(
                    index = 7
                )] CandidateRemoved { account_id: ::subxt::ext::subxt_core::utils::AccountId32 },
                #[codec(
                    index = 8
                )] CandidateReplaced { old: ::subxt::ext::subxt_core::utils::AccountId32, new: ::subxt::ext::subxt_core::utils::AccountId32, deposit: ::core::primitive::u128 },
                #[codec(
                    index = 9
                )] InvalidInvulnerableSkipped { account_id: ::subxt::ext::subxt_core::utils::AccountId32 },
            }
        }
    }
    pub mod pallet_identity {
        use super::runtime_types;
        pub mod pallet {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Call {
                #[codec(
                    index = 0
                )] add_registrar { account: ::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()> },
                #[codec(
                    index = 1
                )] set_identity { info: ::subxt::ext::subxt_core::alloc::boxed::Box<runtime_types::people_rococo_runtime::people::IdentityInfo> },
                #[codec(
                    index = 2
                )] set_subs { subs: ::subxt::ext::subxt_core::alloc::vec::Vec<(::subxt::ext::subxt_core::utils::AccountId32, runtime_types::pallet_identity::types::Data,)> },
                #[codec(index = 3)] clear_identity,
                #[codec(index = 4)] request_judgement {
                    #[codec(
                        compact
                    )] reg_index: ::core::primitive::u32,
                    #[codec(compact)] max_fee: ::core::primitive::u128,
                },
                #[codec(index = 5)] cancel_request { reg_index: ::core::primitive::u32 },
                #[codec(index = 6)] set_fee {
                    #[codec(
                        compact
                    )] index: ::core::primitive::u32,
                    #[codec(compact)] fee: ::core::primitive::u128,
                },
                #[codec(index = 7)] set_account_id {
                    #[codec(
                        compact
                    )] index: ::core::primitive::u32,
                    new: ::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()>,
                },
                #[codec(index = 8)] set_fields {
                    #[codec(
                        compact
                    )] index: ::core::primitive::u32,
                    fields: ::core::primitive::u64,
                },
                #[codec(index = 9)] provide_judgement {
                    #[codec(
                        compact
                    )] reg_index: ::core::primitive::u32,
                    target: ::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()>,
                    judgement: runtime_types::pallet_identity::types::Judgement<::core::primitive::u128>,
                    identity: ::subxt::ext::subxt_core::utils::H256,
                },
                #[codec(
                    index = 10
                )] kill_identity { target: ::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()> },
                #[codec(
                    index = 11
                )] add_sub { sub: ::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()>, data: runtime_types::pallet_identity::types::Data },
                #[codec(
                    index = 12
                )] rename_sub { sub: ::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()>, data: runtime_types::pallet_identity::types::Data },
                #[codec(
                    index = 13
                )] remove_sub { sub: ::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()> },
                #[codec(index = 14)] quit_sub,
                #[codec(
                    index = 15
                )] add_username_authority { authority: ::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()>, suffix: ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>, allocation: ::core::primitive::u32 },
                #[codec(
                    index = 16
                )] remove_username_authority { authority: ::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()> },
                #[codec(
                    index = 17
                )] set_username_for { who: ::subxt::ext::subxt_core::utils::MultiAddress<::subxt::ext::subxt_core::utils::AccountId32, ()>, username: ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>, signature: ::core::option::Option<runtime_types::sp_runtime::MultiSignature> },
                #[codec(
                    index = 18
                )] accept_username { username: runtime_types::bounded_collections::bounded_vec::BoundedVec<::core::primitive::u8> },
                #[codec(
                    index = 19
                )] remove_expired_approval { username: runtime_types::bounded_collections::bounded_vec::BoundedVec<::core::primitive::u8> },
                #[codec(
                    index = 20
                )] set_primary_username { username: runtime_types::bounded_collections::bounded_vec::BoundedVec<::core::primitive::u8> },
                #[codec(
                    index = 21
                )] remove_dangling_username { username: runtime_types::bounded_collections::bounded_vec::BoundedVec<::core::primitive::u8> },
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Error {
                #[codec(index = 0)] TooManySubAccounts,
                #[codec(index = 1)] NotFound,
                #[codec(index = 2)] NotNamed,
                #[codec(index = 3)] EmptyIndex,
                #[codec(index = 4)] FeeChanged,
                #[codec(index = 5)] NoIdentity,
                #[codec(index = 6)] StickyJudgement,
                #[codec(index = 7)] JudgementGiven,
                #[codec(index = 8)] InvalidJudgement,
                #[codec(index = 9)] InvalidIndex,
                #[codec(index = 10)] InvalidTarget,
                #[codec(index = 11)] TooManyRegistrars,
                #[codec(index = 12)] AlreadyClaimed,
                #[codec(index = 13)] NotSub,
                #[codec(index = 14)] NotOwned,
                #[codec(index = 15)] JudgementForDifferentIdentity,
                #[codec(index = 16)] JudgementPaymentFailed,
                #[codec(index = 17)] InvalidSuffix,
                #[codec(index = 18)] NotUsernameAuthority,
                #[codec(index = 19)] NoAllocation,
                #[codec(index = 20)] InvalidSignature,
                #[codec(index = 21)] RequiresSignature,
                #[codec(index = 22)] InvalidUsername,
                #[codec(index = 23)] UsernameTaken,
                #[codec(index = 24)] NoUsername,
                #[codec(index = 25)] NotExpired,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Event {
                #[codec(
                    index = 0
                )] IdentitySet { who: ::subxt::ext::subxt_core::utils::AccountId32 },
                #[codec(
                    index = 1
                )] IdentityCleared { who: ::subxt::ext::subxt_core::utils::AccountId32, deposit: ::core::primitive::u128 },
                #[codec(
                    index = 2
                )] IdentityKilled { who: ::subxt::ext::subxt_core::utils::AccountId32, deposit: ::core::primitive::u128 },
                #[codec(
                    index = 3
                )] JudgementRequested { who: ::subxt::ext::subxt_core::utils::AccountId32, registrar_index: ::core::primitive::u32 },
                #[codec(
                    index = 4
                )] JudgementUnrequested { who: ::subxt::ext::subxt_core::utils::AccountId32, registrar_index: ::core::primitive::u32 },
                #[codec(
                    index = 5
                )] JudgementGiven { target: ::subxt::ext::subxt_core::utils::AccountId32, registrar_index: ::core::primitive::u32 },
                #[codec(index = 6)] RegistrarAdded { registrar_index: ::core::primitive::u32 },
                #[codec(
                    index = 7
                )] SubIdentityAdded { sub: ::subxt::ext::subxt_core::utils::AccountId32, main: ::subxt::ext::subxt_core::utils::AccountId32, deposit: ::core::primitive::u128 },
                #[codec(
                    index = 8
                )] SubIdentityRemoved { sub: ::subxt::ext::subxt_core::utils::AccountId32, main: ::subxt::ext::subxt_core::utils::AccountId32, deposit: ::core::primitive::u128 },
                #[codec(
                    index = 9
                )] SubIdentityRevoked { sub: ::subxt::ext::subxt_core::utils::AccountId32, main: ::subxt::ext::subxt_core::utils::AccountId32, deposit: ::core::primitive::u128 },
                #[codec(
                    index = 10
                )] AuthorityAdded { authority: ::subxt::ext::subxt_core::utils::AccountId32 },
                #[codec(
                    index = 11
                )] AuthorityRemoved { authority: ::subxt::ext::subxt_core::utils::AccountId32 },
                #[codec(
                    index = 12
                )] UsernameSet { who: ::subxt::ext::subxt_core::utils::AccountId32, username: runtime_types::bounded_collections::bounded_vec::BoundedVec<::core::primitive::u8> },
                #[codec(
                    index = 13
                )] UsernameQueued { who: ::subxt::ext::subxt_core::utils::AccountId32, username: runtime_types::bounded_collections::bounded_vec::BoundedVec<::core::primitive::u8>, expiration: ::core::primitive::u32 },
                #[codec(
                    index = 14
                )] PreapprovalExpired { whose: ::subxt::ext::subxt_core::utils::AccountId32 },
                #[codec(
                    index = 15
                )] PrimaryUsernameSet { who: ::subxt::ext::subxt_core::utils::AccountId32, username: runtime_types::bounded_collections::bounded_vec::BoundedVec<::core::primitive::u8> },
                #[codec(
                    index = 16
                )] DanglingUsernameRemoved { who: ::subxt::ext::subxt_core::utils::AccountId32, username: runtime_types::bounded_collections::bounded_vec::BoundedVec<::core::primitive::u8> },
            }
        }
        pub mod types {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct AuthorityProperties<_0> {
                pub suffix: _0,
                pub allocation: ::core::primitive::u32,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Data {
                #[codec(index = 0)] None,
                #[codec(index = 1)] Raw0([::core::primitive::u8; 0usize]),
                #[codec(index = 2)] Raw1([::core::primitive::u8; 1usize]),
                #[codec(index = 3)] Raw2([::core::primitive::u8; 2usize]),
                #[codec(index = 4)] Raw3([::core::primitive::u8; 3usize]),
                #[codec(index = 5)] Raw4([::core::primitive::u8; 4usize]),
                #[codec(index = 6)] Raw5([::core::primitive::u8; 5usize]),
                #[codec(index = 7)] Raw6([::core::primitive::u8; 6usize]),
                #[codec(index = 8)] Raw7([::core::primitive::u8; 7usize]),
                #[codec(index = 9)] Raw8([::core::primitive::u8; 8usize]),
                #[codec(index = 10)] Raw9([::core::primitive::u8; 9usize]),
                #[codec(index = 11)] Raw10([::core::primitive::u8; 10usize]),
                #[codec(index = 12)] Raw11([::core::primitive::u8; 11usize]),
                #[codec(index = 13)] Raw12([::core::primitive::u8; 12usize]),
                #[codec(index = 14)] Raw13([::core::primitive::u8; 13usize]),
                #[codec(index = 15)] Raw14([::core::primitive::u8; 14usize]),
                #[codec(index = 16)] Raw15([::core::primitive::u8; 15usize]),
                #[codec(index = 17)] Raw16([::core::primitive::u8; 16usize]),
                #[codec(index = 18)] Raw17([::core::primitive::u8; 17usize]),
                #[codec(index = 19)] Raw18([::core::primitive::u8; 18usize]),
                #[codec(index = 20)] Raw19([::core::primitive::u8; 19usize]),
                #[codec(index = 21)] Raw20([::core::primitive::u8; 20usize]),
                #[codec(index = 22)] Raw21([::core::primitive::u8; 21usize]),
                #[codec(index = 23)] Raw22([::core::primitive::u8; 22usize]),
                #[codec(index = 24)] Raw23([::core::primitive::u8; 23usize]),
                #[codec(index = 25)] Raw24([::core::primitive::u8; 24usize]),
                #[codec(index = 26)] Raw25([::core::primitive::u8; 25usize]),
                #[codec(index = 27)] Raw26([::core::primitive::u8; 26usize]),
                #[codec(index = 28)] Raw27([::core::primitive::u8; 27usize]),
                #[codec(index = 29)] Raw28([::core::primitive::u8; 28usize]),
                #[codec(index = 30)] Raw29([::core::primitive::u8; 29usize]),
                #[codec(index = 31)] Raw30([::core::primitive::u8; 30usize]),
                #[codec(index = 32)] Raw31([::core::primitive::u8; 31usize]),
                #[codec(index = 33)] Raw32([::core::primitive::u8; 32usize]),
                #[codec(index = 34)] BlakeTwo256([::core::primitive::u8; 32usize]),
                #[codec(index = 35)] Sha256([::core::primitive::u8; 32usize]),
                #[codec(index = 36)] Keccak256([::core::primitive::u8; 32usize]),
                #[codec(index = 37)] ShaThree256([::core::primitive::u8; 32usize]),
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Judgement<_0> {
                #[codec(index = 0)] Unknown,
                #[codec(
                    index = 1
                )] FeePaid(_0),
                #[codec(index = 2)] Reasonable,
                #[codec(index = 3)] KnownGood,
                #[codec(index = 4)] OutOfDate,
                #[codec(index = 5)] LowQuality,
                #[codec(index = 6)] Erroneous,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct RegistrarInfo<_0, _1, _2> {
                pub account: _1,
                pub fee: _0,
                pub fields: _2,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct Registration<_0, _2> {
                pub judgements: runtime_types::bounded_collections::bounded_vec::BoundedVec<(::core::primitive::u32, runtime_types::pallet_identity::types::Judgement<_0>,)>,
                pub deposit: _0,
                pub info: _2,
            }
        }
    }
    pub mod pallet_message_queue {
        use super::runtime_types;
        pub mod pallet {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Call {
                #[codec(
                    index = 0
                )] reap_page { message_origin: runtime_types::cumulus_primitives_core::AggregateMessageOrigin, page_index: ::core::primitive::u32 },
                #[codec(
                    index = 1
                )] execute_overweight { message_origin: runtime_types::cumulus_primitives_core::AggregateMessageOrigin, page: ::core::primitive::u32, index: ::core::primitive::u32, weight_limit: runtime_types::sp_weights::weight_v2::Weight },
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Error {
                #[codec(index = 0)] NotReapable,
                #[codec(
                    index = 1
                )] NoPage,
                #[codec(index = 2)] NoMessage,
                #[codec(index = 3)] AlreadyProcessed,
                #[codec(index = 4)] Queued,
                #[codec(index = 5)] InsufficientWeight,
                #[codec(index = 6)] TemporarilyUnprocessable,
                #[codec(index = 7)] QueuePaused,
                #[codec(index = 8)] RecursiveDisallowed,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Event {
                #[codec(
                    index = 0
                )] ProcessingFailed { id: ::subxt::ext::subxt_core::utils::H256, origin: runtime_types::cumulus_primitives_core::AggregateMessageOrigin, error: runtime_types::frame_support::traits::messages::ProcessMessageError },
                #[codec(
                    index = 1
                )] Processed { id: ::subxt::ext::subxt_core::utils::H256, origin: runtime_types::cumulus_primitives_core::AggregateMessageOrigin, weight_used: runtime_types::sp_weights::weight_v2::Weight, success: ::core::primitive::bool },
                #[codec(
                    index = 2
                )] OverweightEnqueued { id: [::core::primitive::u8; 32usize], origin: runtime_types::cumulus_primitives_core::AggregateMessageOrigin, page_index: ::core::primitive::u32, message_index: ::core::primitive::u32 },
                #[codec(
                    index = 3
                )] PageReaped { origin: runtime_types::cumulus_primitives_core::AggregateMessageOrigin, index: ::core::primitive::u32 },
            }
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct BookState<_0> {
            pub begin: ::core::primitive::u32,
            pub end: ::core::primitive::u32,
            pub count: ::core::primitive::u32,
            pub ready_neighbours: ::core::option::Option<runtime_types::pallet_message_queue::Neighbours<_0>>,
            pub message_count: ::core::primitive::u64,
            pub size: ::core::primitive::u64,
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct Neighbours<_0> {
            pub prev: _0,
            pub next: _0,
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct Page<_0> {
            pub remaining: _0,
            pub remaining_size: _0,
            pub first_index: _0,
            pub first: _0,
            pub last: _0,
            pub heap: runtime_types::bounded_collections::bounded_vec::BoundedVec<::core::primitive::u8>,
        }
    }
    pub mod pallet_multisig {
        use super::runtime_types;
        pub mod pallet {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Call {
                #[codec(
                    index = 0
                )] as_multi_threshold_1 { other_signatories: ::subxt::ext::subxt_core::alloc::vec::Vec<::subxt::ext::subxt_core::utils::AccountId32>, call: ::subxt::ext::subxt_core::alloc::boxed::Box<runtime_types::people_rococo_runtime::RuntimeCall> },
                #[codec(
                    index = 1
                )] as_multi { threshold: ::core::primitive::u16, other_signatories: ::subxt::ext::subxt_core::alloc::vec::Vec<::subxt::ext::subxt_core::utils::AccountId32>, maybe_timepoint: ::core::option::Option<runtime_types::pallet_multisig::Timepoint<::core::primitive::u32>>, call: ::subxt::ext::subxt_core::alloc::boxed::Box<runtime_types::people_rococo_runtime::RuntimeCall>, max_weight: runtime_types::sp_weights::weight_v2::Weight },
                #[codec(
                    index = 2
                )] approve_as_multi { threshold: ::core::primitive::u16, other_signatories: ::subxt::ext::subxt_core::alloc::vec::Vec<::subxt::ext::subxt_core::utils::AccountId32>, maybe_timepoint: ::core::option::Option<runtime_types::pallet_multisig::Timepoint<::core::primitive::u32>>, call_hash: [::core::primitive::u8; 32usize], max_weight: runtime_types::sp_weights::weight_v2::Weight },
                #[codec(
                    index = 3
                )] cancel_as_multi { threshold: ::core::primitive::u16, other_signatories: ::subxt::ext::subxt_core::alloc::vec::Vec<::subxt::ext::subxt_core::utils::AccountId32>, timepoint: runtime_types::pallet_multisig::Timepoint<::core::primitive::u32>, call_hash: [::core::primitive::u8; 32usize] },
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Error {
                #[codec(index = 0)] MinimumThreshold,
                #[codec(
                    index = 1
                )] AlreadyApproved,
                #[codec(index = 2)] NoApprovalsNeeded,
                #[codec(index = 3)] TooFewSignatories,
                #[codec(index = 4)] TooManySignatories,
                #[codec(index = 5)] SignatoriesOutOfOrder,
                #[codec(index = 6)] SenderInSignatories,
                #[codec(index = 7)] NotFound,
                #[codec(index = 8)] NotOwner,
                #[codec(index = 9)] NoTimepoint,
                #[codec(index = 10)] WrongTimepoint,
                #[codec(index = 11)] UnexpectedTimepoint,
                #[codec(index = 12)] MaxWeightTooLow,
                #[codec(index = 13)] AlreadyStored,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Event {
                #[codec(
                    index = 0
                )] NewMultisig { approving: ::subxt::ext::subxt_core::utils::AccountId32, multisig: ::subxt::ext::subxt_core::utils::AccountId32, call_hash: [::core::primitive::u8; 32usize] },
                #[codec(
                    index = 1
                )] MultisigApproval { approving: ::subxt::ext::subxt_core::utils::AccountId32, timepoint: runtime_types::pallet_multisig::Timepoint<::core::primitive::u32>, multisig: ::subxt::ext::subxt_core::utils::AccountId32, call_hash: [::core::primitive::u8; 32usize] },
                #[codec(
                    index = 2
                )] MultisigExecuted { approving: ::subxt::ext::subxt_core::utils::AccountId32, timepoint: runtime_types::pallet_multisig::Timepoint<::core::primitive::u32>, multisig: ::subxt::ext::subxt_core::utils::AccountId32, call_hash: [::core::primitive::u8; 32usize], result: ::core::result::Result<(), runtime_types::sp_runtime::DispatchError> },
                #[codec(
                    index = 3
                )] MultisigCancelled { cancelling: ::subxt::ext::subxt_core::utils::AccountId32, timepoint: runtime_types::pallet_multisig::Timepoint<::core::primitive::u32>, multisig: ::subxt::ext::subxt_core::utils::AccountId32, call_hash: [::core::primitive::u8; 32usize] },
            }
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct Multisig<_0, _1, _2> {
            pub when: runtime_types::pallet_multisig::Timepoint<_0>,
            pub deposit: _1,
            pub depositor: _2,
            pub approvals: runtime_types::bounded_collections::bounded_vec::BoundedVec<_2>,
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct Timepoint<_0> {
            pub height: _0,
            pub index: ::core::primitive::u32,
        }
    }
    pub mod pallet_session {
        use super::runtime_types;
        pub mod pallet {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Call {
                #[codec(
                    index = 0
                )] set_keys { keys: runtime_types::people_rococo_runtime::SessionKeys, proof: ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8> },
                #[codec(index = 1)] purge_keys,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Error {
                #[codec(index = 0)] InvalidProof,
                #[codec(
                    index = 1
                )] NoAssociatedValidatorId,
                #[codec(index = 2)] DuplicatedKey,
                #[codec(index = 3)] NoKeys,
                #[codec(index = 4)] NoAccount,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Event {
                #[codec(
                    index = 0
                )] NewSession { session_index: ::core::primitive::u32 },
            }
        }
    }
    pub mod pallet_timestamp {
        use super::runtime_types;
        pub mod pallet {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Call {
                #[codec(index = 0)] set {
                    #[codec(
                        compact
                    )] now: ::core::primitive::u64,
                },
            }
        }
    }
    pub mod pallet_transaction_payment {
        use super::runtime_types;
        pub mod pallet {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Event {
                #[codec(
                    index = 0
                )] TransactionFeePaid { who: ::subxt::ext::subxt_core::utils::AccountId32, actual_fee: ::core::primitive::u128, tip: ::core::primitive::u128 },
            }
        }
        pub mod types {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct FeeDetails<_0> {
                pub inclusion_fee: ::core::option::Option<runtime_types::pallet_transaction_payment::types::InclusionFee<_0>>,
                pub tip: _0,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct InclusionFee<_0> {
                pub base_fee: _0,
                pub len_fee: _0,
                pub adjusted_weight_fee: _0,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct RuntimeDispatchInfo<_0, _1> {
                pub weight: _1,
                pub class: runtime_types::frame_support::dispatch::DispatchClass,
                pub partial_fee: _0,
            }
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct ChargeTransactionPayment(#[codec(compact)] pub ::core::primitive::u128);
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub enum Releases { #[codec(index = 0)] V1Ancient, #[codec(index = 1)] V2 }
    }
    pub mod pallet_utility {
        use super::runtime_types;
        pub mod pallet {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Call {
                #[codec(
                    index = 0
                )] batch { calls: ::subxt::ext::subxt_core::alloc::vec::Vec<runtime_types::people_rococo_runtime::RuntimeCall> },
                #[codec(
                    index = 1
                )] as_derivative { index: ::core::primitive::u16, call: ::subxt::ext::subxt_core::alloc::boxed::Box<runtime_types::people_rococo_runtime::RuntimeCall> },
                #[codec(
                    index = 2
                )] batch_all { calls: ::subxt::ext::subxt_core::alloc::vec::Vec<runtime_types::people_rococo_runtime::RuntimeCall> },
                #[codec(
                    index = 3
                )] dispatch_as { as_origin: ::subxt::ext::subxt_core::alloc::boxed::Box<runtime_types::people_rococo_runtime::OriginCaller>, call: ::subxt::ext::subxt_core::alloc::boxed::Box<runtime_types::people_rococo_runtime::RuntimeCall> },
                #[codec(
                    index = 4
                )] force_batch { calls: ::subxt::ext::subxt_core::alloc::vec::Vec<runtime_types::people_rococo_runtime::RuntimeCall> },
                #[codec(
                    index = 5
                )] with_weight { call: ::subxt::ext::subxt_core::alloc::boxed::Box<runtime_types::people_rococo_runtime::RuntimeCall>, weight: runtime_types::sp_weights::weight_v2::Weight },
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Error { #[codec(index = 0)] TooManyCalls }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Event {
                #[codec(
                    index = 0
                )] BatchInterrupted { index: ::core::primitive::u32, error: runtime_types::sp_runtime::DispatchError },
                #[codec(index = 1)] BatchCompleted,
                #[codec(index = 2)] BatchCompletedWithErrors,
                #[codec(index = 3)] ItemCompleted,
                #[codec(
                    index = 4
                )] ItemFailed { error: runtime_types::sp_runtime::DispatchError },
                #[codec(
                    index = 5
                )] DispatchedAs { result: ::core::result::Result<(), runtime_types::sp_runtime::DispatchError> },
            }
        }
    }
    pub mod pallet_xcm {
        use super::runtime_types;
        pub mod pallet {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Call {
                #[codec(
                    index = 0
                )] send { dest: ::subxt::ext::subxt_core::alloc::boxed::Box<runtime_types::xcm::VersionedLocation>, message: ::subxt::ext::subxt_core::alloc::boxed::Box<runtime_types::xcm::VersionedXcm> },
                #[codec(
                    index = 1
                )] teleport_assets { dest: ::subxt::ext::subxt_core::alloc::boxed::Box<runtime_types::xcm::VersionedLocation>, beneficiary: ::subxt::ext::subxt_core::alloc::boxed::Box<runtime_types::xcm::VersionedLocation>, assets: ::subxt::ext::subxt_core::alloc::boxed::Box<runtime_types::xcm::VersionedAssets>, fee_asset_item: ::core::primitive::u32 },
                #[codec(
                    index = 2
                )] reserve_transfer_assets { dest: ::subxt::ext::subxt_core::alloc::boxed::Box<runtime_types::xcm::VersionedLocation>, beneficiary: ::subxt::ext::subxt_core::alloc::boxed::Box<runtime_types::xcm::VersionedLocation>, assets: ::subxt::ext::subxt_core::alloc::boxed::Box<runtime_types::xcm::VersionedAssets>, fee_asset_item: ::core::primitive::u32 },
                #[codec(
                    index = 3
                )] execute { message: ::subxt::ext::subxt_core::alloc::boxed::Box<runtime_types::xcm::VersionedXcm>, max_weight: runtime_types::sp_weights::weight_v2::Weight },
                #[codec(
                    index = 4
                )] force_xcm_version { location: ::subxt::ext::subxt_core::alloc::boxed::Box<runtime_types::staging_xcm::v4::location::Location>, version: ::core::primitive::u32 },
                #[codec(
                    index = 5
                )] force_default_xcm_version { maybe_xcm_version: ::core::option::Option<::core::primitive::u32> },
                #[codec(
                    index = 6
                )] force_subscribe_version_notify { location: ::subxt::ext::subxt_core::alloc::boxed::Box<runtime_types::xcm::VersionedLocation> },
                #[codec(
                    index = 7
                )] force_unsubscribe_version_notify { location: ::subxt::ext::subxt_core::alloc::boxed::Box<runtime_types::xcm::VersionedLocation> },
                #[codec(
                    index = 8
                )] limited_reserve_transfer_assets { dest: ::subxt::ext::subxt_core::alloc::boxed::Box<runtime_types::xcm::VersionedLocation>, beneficiary: ::subxt::ext::subxt_core::alloc::boxed::Box<runtime_types::xcm::VersionedLocation>, assets: ::subxt::ext::subxt_core::alloc::boxed::Box<runtime_types::xcm::VersionedAssets>, fee_asset_item: ::core::primitive::u32, weight_limit: runtime_types::xcm::v3::WeightLimit },
                #[codec(
                    index = 9
                )] limited_teleport_assets { dest: ::subxt::ext::subxt_core::alloc::boxed::Box<runtime_types::xcm::VersionedLocation>, beneficiary: ::subxt::ext::subxt_core::alloc::boxed::Box<runtime_types::xcm::VersionedLocation>, assets: ::subxt::ext::subxt_core::alloc::boxed::Box<runtime_types::xcm::VersionedAssets>, fee_asset_item: ::core::primitive::u32, weight_limit: runtime_types::xcm::v3::WeightLimit },
                #[codec(index = 10)] force_suspension { suspended: ::core::primitive::bool },
                #[codec(
                    index = 11
                )] transfer_assets { dest: ::subxt::ext::subxt_core::alloc::boxed::Box<runtime_types::xcm::VersionedLocation>, beneficiary: ::subxt::ext::subxt_core::alloc::boxed::Box<runtime_types::xcm::VersionedLocation>, assets: ::subxt::ext::subxt_core::alloc::boxed::Box<runtime_types::xcm::VersionedAssets>, fee_asset_item: ::core::primitive::u32, weight_limit: runtime_types::xcm::v3::WeightLimit },
                #[codec(
                    index = 12
                )] claim_assets { assets: ::subxt::ext::subxt_core::alloc::boxed::Box<runtime_types::xcm::VersionedAssets>, beneficiary: ::subxt::ext::subxt_core::alloc::boxed::Box<runtime_types::xcm::VersionedLocation> },
                #[codec(index = 13)] transfer_assets_using_type_and_then {
                    dest: ::subxt::ext::subxt_core::alloc::boxed::Box<runtime_types::xcm::VersionedLocation>,
                    assets: ::subxt::ext::subxt_core::alloc::boxed::Box<runtime_types::xcm::VersionedAssets>,
                    assets_transfer_type: ::subxt::ext::subxt_core::alloc::boxed::Box<runtime_types::staging_xcm_executor::traits::asset_transfer::TransferType>,
                    remote_fees_id: ::subxt::ext::subxt_core::alloc::boxed::Box<runtime_types::xcm::VersionedAssetId>,
                    fees_transfer_type: ::subxt::ext::subxt_core::alloc::boxed::Box<runtime_types::staging_xcm_executor::traits::asset_transfer::TransferType>,
                    custom_xcm_on_dest: ::subxt::ext::subxt_core::alloc::boxed::Box<runtime_types::xcm::VersionedXcm>,
                    weight_limit: runtime_types::xcm::v3::WeightLimit,
                },
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Error {
                #[codec(index = 0)] Unreachable,
                #[codec(index = 1)] SendFailure,
                #[codec(index = 2)] Filtered,
                #[codec(index = 3)] UnweighableMessage,
                #[codec(index = 4)] DestinationNotInvertible,
                #[codec(index = 5)] Empty,
                #[codec(index = 6)] CannotReanchor,
                #[codec(index = 7)] TooManyAssets,
                #[codec(index = 8)] InvalidOrigin,
                #[codec(index = 9)] BadVersion,
                #[codec(index = 10)] BadLocation,
                #[codec(index = 11)] NoSubscription,
                #[codec(index = 12)] AlreadySubscribed,
                #[codec(index = 13)] CannotCheckOutTeleport,
                #[codec(index = 14)] LowBalance,
                #[codec(index = 15)] TooManyLocks,
                #[codec(index = 16)] AccountNotSovereign,
                #[codec(index = 17)] FeesNotMet,
                #[codec(index = 18)] LockNotFound,
                #[codec(index = 19)] InUse,
                #[codec(index = 21)] InvalidAssetUnknownReserve,
                #[codec(index = 22)] InvalidAssetUnsupportedReserve,
                #[codec(index = 23)] TooManyReserves,
                #[codec(index = 24)] LocalExecutionIncomplete,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Event {
                #[codec(
                    index = 0
                )] Attempted { outcome: runtime_types::staging_xcm::v4::traits::Outcome },
                #[codec(
                    index = 1
                )] Sent { origin: runtime_types::staging_xcm::v4::location::Location, destination: runtime_types::staging_xcm::v4::location::Location, message: runtime_types::staging_xcm::v4::Xcm, message_id: [::core::primitive::u8; 32usize] },
                #[codec(
                    index = 2
                )] UnexpectedResponse { origin: runtime_types::staging_xcm::v4::location::Location, query_id: ::core::primitive::u64 },
                #[codec(
                    index = 3
                )] ResponseReady { query_id: ::core::primitive::u64, response: runtime_types::staging_xcm::v4::Response },
                #[codec(
                    index = 4
                )] Notified { query_id: ::core::primitive::u64, pallet_index: ::core::primitive::u8, call_index: ::core::primitive::u8 },
                #[codec(
                    index = 5
                )] NotifyOverweight { query_id: ::core::primitive::u64, pallet_index: ::core::primitive::u8, call_index: ::core::primitive::u8, actual_weight: runtime_types::sp_weights::weight_v2::Weight, max_budgeted_weight: runtime_types::sp_weights::weight_v2::Weight },
                #[codec(
                    index = 6
                )] NotifyDispatchError { query_id: ::core::primitive::u64, pallet_index: ::core::primitive::u8, call_index: ::core::primitive::u8 },
                #[codec(
                    index = 7
                )] NotifyDecodeFailed { query_id: ::core::primitive::u64, pallet_index: ::core::primitive::u8, call_index: ::core::primitive::u8 },
                #[codec(
                    index = 8
                )] InvalidResponder { origin: runtime_types::staging_xcm::v4::location::Location, query_id: ::core::primitive::u64, expected_location: ::core::option::Option<runtime_types::staging_xcm::v4::location::Location> },
                #[codec(
                    index = 9
                )] InvalidResponderVersion { origin: runtime_types::staging_xcm::v4::location::Location, query_id: ::core::primitive::u64 },
                #[codec(index = 10)] ResponseTaken { query_id: ::core::primitive::u64 },
                #[codec(
                    index = 11
                )] AssetsTrapped { hash: ::subxt::ext::subxt_core::utils::H256, origin: runtime_types::staging_xcm::v4::location::Location, assets: runtime_types::xcm::VersionedAssets },
                #[codec(
                    index = 12
                )] VersionChangeNotified { destination: runtime_types::staging_xcm::v4::location::Location, result: ::core::primitive::u32, cost: runtime_types::staging_xcm::v4::asset::Assets, message_id: [::core::primitive::u8; 32usize] },
                #[codec(
                    index = 13
                )] SupportedVersionChanged { location: runtime_types::staging_xcm::v4::location::Location, version: ::core::primitive::u32 },
                #[codec(
                    index = 14
                )] NotifyTargetSendFail { location: runtime_types::staging_xcm::v4::location::Location, query_id: ::core::primitive::u64, error: runtime_types::xcm::v3::traits::Error },
                #[codec(
                    index = 15
                )] NotifyTargetMigrationFail { location: runtime_types::xcm::VersionedLocation, query_id: ::core::primitive::u64 },
                #[codec(
                    index = 16
                )] InvalidQuerierVersion { origin: runtime_types::staging_xcm::v4::location::Location, query_id: ::core::primitive::u64 },
                #[codec(
                    index = 17
                )] InvalidQuerier { origin: runtime_types::staging_xcm::v4::location::Location, query_id: ::core::primitive::u64, expected_querier: runtime_types::staging_xcm::v4::location::Location, maybe_actual_querier: ::core::option::Option<runtime_types::staging_xcm::v4::location::Location> },
                #[codec(
                    index = 18
                )] VersionNotifyStarted { destination: runtime_types::staging_xcm::v4::location::Location, cost: runtime_types::staging_xcm::v4::asset::Assets, message_id: [::core::primitive::u8; 32usize] },
                #[codec(
                    index = 19
                )] VersionNotifyRequested { destination: runtime_types::staging_xcm::v4::location::Location, cost: runtime_types::staging_xcm::v4::asset::Assets, message_id: [::core::primitive::u8; 32usize] },
                #[codec(
                    index = 20
                )] VersionNotifyUnrequested { destination: runtime_types::staging_xcm::v4::location::Location, cost: runtime_types::staging_xcm::v4::asset::Assets, message_id: [::core::primitive::u8; 32usize] },
                #[codec(
                    index = 21
                )] FeesPaid { paying: runtime_types::staging_xcm::v4::location::Location, fees: runtime_types::staging_xcm::v4::asset::Assets },
                #[codec(
                    index = 22
                )] AssetsClaimed { hash: ::subxt::ext::subxt_core::utils::H256, origin: runtime_types::staging_xcm::v4::location::Location, assets: runtime_types::xcm::VersionedAssets },
                #[codec(
                    index = 23
                )] VersionMigrationFinished { version: ::core::primitive::u32 },
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Origin {
                #[codec(
                    index = 0
                )] Xcm(runtime_types::staging_xcm::v4::location::Location),
                #[codec(
                    index = 1
                )] Response(runtime_types::staging_xcm::v4::location::Location),
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum QueryStatus<_0> {
                #[codec(
                    index = 0
                )] Pending { responder: runtime_types::xcm::VersionedLocation, maybe_match_querier: ::core::option::Option<runtime_types::xcm::VersionedLocation>, maybe_notify: ::core::option::Option<(::core::primitive::u8, ::core::primitive::u8,)>, timeout: _0 },
                #[codec(
                    index = 1
                )] VersionNotifier { origin: runtime_types::xcm::VersionedLocation, is_active: ::core::primitive::bool },
                #[codec(
                    index = 2
                )] Ready { response: runtime_types::xcm::VersionedResponse, at: _0 },
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct RemoteLockedFungibleRecord<_0> {
                pub amount: ::core::primitive::u128,
                pub owner: runtime_types::xcm::VersionedLocation,
                pub locker: runtime_types::xcm::VersionedLocation,
                pub consumers: runtime_types::bounded_collections::bounded_vec::BoundedVec<(_0, ::core::primitive::u128,)>,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum VersionMigrationStage {
                #[codec(
                    index = 0
                )] MigrateSupportedVersion,
                #[codec(index = 1)] MigrateVersionNotifiers,
                #[codec(
                    index = 2
                )] NotifyCurrentTargets(::core::option::Option<::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>>),
                #[codec(index = 3)] MigrateAndNotifyOldTargets,
            }
        }
    }
    pub mod people_rococo_runtime {
        use super::runtime_types;
        pub mod people {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct IdentityInfo {
                pub display: runtime_types::pallet_identity::types::Data,
                pub legal: runtime_types::pallet_identity::types::Data,
                pub web: runtime_types::pallet_identity::types::Data,
                pub matrix: runtime_types::pallet_identity::types::Data,
                pub email: runtime_types::pallet_identity::types::Data,
                pub pgp_fingerprint: ::core::option::Option<[::core::primitive::u8; 20usize]>,
                pub image: runtime_types::pallet_identity::types::Data,
                pub twitter: runtime_types::pallet_identity::types::Data,
                pub github: runtime_types::pallet_identity::types::Data,
                pub discord: runtime_types::pallet_identity::types::Data,
            }
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub enum OriginCaller {
            #[codec(
                index = 0
            )] system(runtime_types::frame_support::dispatch::RawOrigin<::subxt::ext::subxt_core::utils::AccountId32>),
            #[codec(index = 31)] PolkadotXcm(runtime_types::pallet_xcm::pallet::Origin),
            #[codec(
                index = 32
            )] CumulusXcm(runtime_types::cumulus_pallet_xcm::pallet::Origin),
            #[codec(index = 3)] Void(runtime_types::sp_core::Void),
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct Runtime;
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub enum RuntimeCall {
            #[codec(index = 0)] System(runtime_types::frame_system::pallet::Call),
            #[codec(
                index = 1
            )] ParachainSystem(runtime_types::cumulus_pallet_parachain_system::pallet::Call),
            #[codec(index = 2)] Timestamp(runtime_types::pallet_timestamp::pallet::Call),
            #[codec(
                index = 3
            )] ParachainInfo(runtime_types::staging_parachain_info::pallet::Call),
            #[codec(index = 10)] Balances(runtime_types::pallet_balances::pallet::Call),
            #[codec(
                index = 21
            )] CollatorSelection(runtime_types::pallet_collator_selection::pallet::Call),
            #[codec(index = 22)] Session(runtime_types::pallet_session::pallet::Call),
            #[codec(
                index = 30
            )] XcmpQueue(runtime_types::cumulus_pallet_xcmp_queue::pallet::Call),
            #[codec(index = 31)] PolkadotXcm(runtime_types::pallet_xcm::pallet::Call),
            #[codec(index = 32)] CumulusXcm(runtime_types::cumulus_pallet_xcm::pallet::Call),
            #[codec(
                index = 34
            )] MessageQueue(runtime_types::pallet_message_queue::pallet::Call),
            #[codec(index = 40)] Utility(runtime_types::pallet_utility::pallet::Call),
            #[codec(index = 41)] Multisig(runtime_types::pallet_multisig::pallet::Call),
            #[codec(index = 50)] Identity(runtime_types::pallet_identity::pallet::Call),
            #[codec(
                index = 248
            )] IdentityMigrator(runtime_types::polkadot_runtime_common::identity_migrator::pallet::Call),
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub enum RuntimeError {
            #[codec(index = 0)] System(runtime_types::frame_system::pallet::Error),
            #[codec(
                index = 1
            )] ParachainSystem(runtime_types::cumulus_pallet_parachain_system::pallet::Error),
            #[codec(index = 10)] Balances(runtime_types::pallet_balances::pallet::Error),
            #[codec(
                index = 21
            )] CollatorSelection(runtime_types::pallet_collator_selection::pallet::Error),
            #[codec(index = 22)] Session(runtime_types::pallet_session::pallet::Error),
            #[codec(
                index = 30
            )] XcmpQueue(runtime_types::cumulus_pallet_xcmp_queue::pallet::Error),
            #[codec(index = 31)] PolkadotXcm(runtime_types::pallet_xcm::pallet::Error),
            #[codec(
                index = 34
            )] MessageQueue(runtime_types::pallet_message_queue::pallet::Error),
            #[codec(index = 40)] Utility(runtime_types::pallet_utility::pallet::Error),
            #[codec(index = 41)] Multisig(runtime_types::pallet_multisig::pallet::Error),
            #[codec(index = 50)] Identity(runtime_types::pallet_identity::pallet::Error),
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub enum RuntimeEvent {
            #[codec(index = 0)] System(runtime_types::frame_system::pallet::Event),
            #[codec(
                index = 1
            )] ParachainSystem(runtime_types::cumulus_pallet_parachain_system::pallet::Event),
            #[codec(index = 10)] Balances(runtime_types::pallet_balances::pallet::Event),
            #[codec(
                index = 11
            )] TransactionPayment(runtime_types::pallet_transaction_payment::pallet::Event),
            #[codec(
                index = 21
            )] CollatorSelection(runtime_types::pallet_collator_selection::pallet::Event),
            #[codec(index = 22)] Session(runtime_types::pallet_session::pallet::Event),
            #[codec(
                index = 30
            )] XcmpQueue(runtime_types::cumulus_pallet_xcmp_queue::pallet::Event),
            #[codec(index = 31)] PolkadotXcm(runtime_types::pallet_xcm::pallet::Event),
            #[codec(index = 32)] CumulusXcm(runtime_types::cumulus_pallet_xcm::pallet::Event),
            #[codec(
                index = 34
            )] MessageQueue(runtime_types::pallet_message_queue::pallet::Event),
            #[codec(index = 40)] Utility(runtime_types::pallet_utility::pallet::Event),
            #[codec(index = 41)] Multisig(runtime_types::pallet_multisig::pallet::Event),
            #[codec(index = 50)] Identity(runtime_types::pallet_identity::pallet::Event),
            #[codec(
                index = 248
            )] IdentityMigrator(runtime_types::polkadot_runtime_common::identity_migrator::pallet::Event),
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub enum RuntimeHoldReason {}
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct SessionKeys {
            pub aura: runtime_types::sp_consensus_aura::sr25519::app_sr25519::Public,
        }
    }
    pub mod polkadot_core_primitives {
        use super::runtime_types;
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct InboundDownwardMessage<_0> {
            pub sent_at: _0,
            pub msg: ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>,
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct InboundHrmpMessage<_0> {
            pub sent_at: _0,
            pub data: ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>,
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct OutboundHrmpMessage<_0> {
            pub recipient: _0,
            pub data: ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>,
        }
    }
    pub mod polkadot_parachain_primitives {
        use super::runtime_types;
        pub mod primitives {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct HeadData(pub ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>);
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::CompactAs,
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct Id(pub ::core::primitive::u32);
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct ValidationCode(pub ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>);
        }
    }
    pub mod polkadot_primitives {
        use super::runtime_types;
        pub mod v7 {
            use super::runtime_types;
            pub mod async_backing {
                use super::runtime_types;
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub struct AsyncBackingParams {
                    pub max_candidate_depth: ::core::primitive::u32,
                    pub allowed_ancestry_len: ::core::primitive::u32,
                }
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct AbridgedHostConfiguration {
                pub max_code_size: ::core::primitive::u32,
                pub max_head_data_size: ::core::primitive::u32,
                pub max_upward_queue_count: ::core::primitive::u32,
                pub max_upward_queue_size: ::core::primitive::u32,
                pub max_upward_message_size: ::core::primitive::u32,
                pub max_upward_message_num_per_candidate: ::core::primitive::u32,
                pub hrmp_max_message_num_per_candidate: ::core::primitive::u32,
                pub validation_upgrade_cooldown: ::core::primitive::u32,
                pub validation_upgrade_delay: ::core::primitive::u32,
                pub async_backing_params: runtime_types::polkadot_primitives::v7::async_backing::AsyncBackingParams,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct AbridgedHrmpChannel {
                pub max_capacity: ::core::primitive::u32,
                pub max_total_size: ::core::primitive::u32,
                pub max_message_size: ::core::primitive::u32,
                pub msg_count: ::core::primitive::u32,
                pub total_size: ::core::primitive::u32,
                pub mqc_head: ::core::option::Option<::subxt::ext::subxt_core::utils::H256>,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct PersistedValidationData<_0, _1> {
                pub parent_head: runtime_types::polkadot_parachain_primitives::primitives::HeadData,
                pub relay_parent_number: _1,
                pub relay_parent_storage_root: _0,
                pub max_pov_size: ::core::primitive::u32,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum UpgradeGoAhead { #[codec(index = 0)] Abort, #[codec(index = 1)] GoAhead }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum UpgradeRestriction { #[codec(index = 0)] Present }
        }
    }
    pub mod polkadot_runtime_common {
        use super::runtime_types;
        pub mod identity_migrator {
            use super::runtime_types;
            pub mod pallet {
                use super::runtime_types;
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub enum Call {
                    #[codec(
                        index = 0
                    )] reap_identity { who: ::subxt::ext::subxt_core::utils::AccountId32 },
                    #[codec(
                        index = 1
                    )] poke_deposit { who: ::subxt::ext::subxt_core::utils::AccountId32 },
                }
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub enum Event {
                    #[codec(
                        index = 0
                    )] IdentityReaped { who: ::subxt::ext::subxt_core::utils::AccountId32 },
                    #[codec(
                        index = 1
                    )] DepositUpdated { who: ::subxt::ext::subxt_core::utils::AccountId32, identity: ::core::primitive::u128, subs: ::core::primitive::u128 },
                }
            }
        }
    }
    pub mod sp_arithmetic {
        use super::runtime_types;
        pub mod fixed_point {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::CompactAs,
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct FixedU128(pub ::core::primitive::u128);
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub enum ArithmeticError {
            #[codec(index = 0)] Underflow,
            #[codec(
                index = 1
            )] Overflow,
            #[codec(index = 2)] DivisionByZero,
        }
    }
    pub mod sp_consensus_aura {
        use super::runtime_types;
        pub mod sr25519 {
            use super::runtime_types;
            pub mod app_sr25519 {
                use super::runtime_types;
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub struct Public(pub [::core::primitive::u8; 32usize]);
            }
        }
    }
    pub mod sp_consensus_slots {
        use super::runtime_types;
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::CompactAs,
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct Slot(pub ::core::primitive::u64);
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::CompactAs,
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct SlotDuration(pub ::core::primitive::u64);
    }
    pub mod sp_core {
        use super::runtime_types;
        pub mod crypto {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct KeyTypeId(pub [::core::primitive::u8; 4usize]);
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct OpaqueMetadata(pub ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>);
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub enum Void {}
    }
    pub mod sp_inherents {
        use super::runtime_types;
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct CheckInherentsResult {
            pub okay: ::core::primitive::bool,
            pub fatal_error: ::core::primitive::bool,
            pub errors: runtime_types::sp_inherents::InherentData,
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct InherentData {
            pub data: ::subxt::ext::subxt_core::utils::KeyedVec<[::core::primitive::u8; 8usize], ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>>,
        }
    }
    pub mod sp_runtime {
        use super::runtime_types;
        pub mod generic {
            use super::runtime_types;
            pub mod block {
                use super::runtime_types;
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub struct Block<_0, _1> {
                    pub header: _0,
                    pub extrinsics: ::subxt::ext::subxt_core::alloc::vec::Vec<_1>,
                }
            }
            pub mod digest {
                use super::runtime_types;
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub struct Digest {
                    pub logs: ::subxt::ext::subxt_core::alloc::vec::Vec<runtime_types::sp_runtime::generic::digest::DigestItem>,
                }
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub enum DigestItem {
                    #[codec(
                        index = 6
                    )] PreRuntime([::core::primitive::u8; 4usize], ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>),
                    #[codec(
                        index = 4
                    )] Consensus([::core::primitive::u8; 4usize], ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>),
                    #[codec(
                        index = 5
                    )] Seal([::core::primitive::u8; 4usize], ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>),
                    #[codec(
                        index = 0
                    )] Other(::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>),
                    #[codec(index = 8)] RuntimeEnvironmentUpdated,
                }
            }
            pub mod era {
                use super::runtime_types;
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub enum Era {
                    #[codec(index = 0)] Immortal,
                    #[codec(index = 1)] Mortal1(::core::primitive::u8),
                    #[codec(index = 2)] Mortal2(::core::primitive::u8),
                    #[codec(index = 3)] Mortal3(::core::primitive::u8),
                    #[codec(index = 4)] Mortal4(::core::primitive::u8),
                    #[codec(index = 5)] Mortal5(::core::primitive::u8),
                    #[codec(index = 6)] Mortal6(::core::primitive::u8),
                    #[codec(index = 7)] Mortal7(::core::primitive::u8),
                    #[codec(index = 8)] Mortal8(::core::primitive::u8),
                    #[codec(index = 9)] Mortal9(::core::primitive::u8),
                    #[codec(index = 10)] Mortal10(::core::primitive::u8),
                    #[codec(index = 11)] Mortal11(::core::primitive::u8),
                    #[codec(index = 12)] Mortal12(::core::primitive::u8),
                    #[codec(index = 13)] Mortal13(::core::primitive::u8),
                    #[codec(index = 14)] Mortal14(::core::primitive::u8),
                    #[codec(index = 15)] Mortal15(::core::primitive::u8),
                    #[codec(index = 16)] Mortal16(::core::primitive::u8),
                    #[codec(index = 17)] Mortal17(::core::primitive::u8),
                    #[codec(index = 18)] Mortal18(::core::primitive::u8),
                    #[codec(index = 19)] Mortal19(::core::primitive::u8),
                    #[codec(index = 20)] Mortal20(::core::primitive::u8),
                    #[codec(index = 21)] Mortal21(::core::primitive::u8),
                    #[codec(index = 22)] Mortal22(::core::primitive::u8),
                    #[codec(index = 23)] Mortal23(::core::primitive::u8),
                    #[codec(index = 24)] Mortal24(::core::primitive::u8),
                    #[codec(index = 25)] Mortal25(::core::primitive::u8),
                    #[codec(index = 26)] Mortal26(::core::primitive::u8),
                    #[codec(index = 27)] Mortal27(::core::primitive::u8),
                    #[codec(index = 28)] Mortal28(::core::primitive::u8),
                    #[codec(index = 29)] Mortal29(::core::primitive::u8),
                    #[codec(index = 30)] Mortal30(::core::primitive::u8),
                    #[codec(index = 31)] Mortal31(::core::primitive::u8),
                    #[codec(index = 32)] Mortal32(::core::primitive::u8),
                    #[codec(index = 33)] Mortal33(::core::primitive::u8),
                    #[codec(index = 34)] Mortal34(::core::primitive::u8),
                    #[codec(index = 35)] Mortal35(::core::primitive::u8),
                    #[codec(index = 36)] Mortal36(::core::primitive::u8),
                    #[codec(index = 37)] Mortal37(::core::primitive::u8),
                    #[codec(index = 38)] Mortal38(::core::primitive::u8),
                    #[codec(index = 39)] Mortal39(::core::primitive::u8),
                    #[codec(index = 40)] Mortal40(::core::primitive::u8),
                    #[codec(index = 41)] Mortal41(::core::primitive::u8),
                    #[codec(index = 42)] Mortal42(::core::primitive::u8),
                    #[codec(index = 43)] Mortal43(::core::primitive::u8),
                    #[codec(index = 44)] Mortal44(::core::primitive::u8),
                    #[codec(index = 45)] Mortal45(::core::primitive::u8),
                    #[codec(index = 46)] Mortal46(::core::primitive::u8),
                    #[codec(index = 47)] Mortal47(::core::primitive::u8),
                    #[codec(index = 48)] Mortal48(::core::primitive::u8),
                    #[codec(index = 49)] Mortal49(::core::primitive::u8),
                    #[codec(index = 50)] Mortal50(::core::primitive::u8),
                    #[codec(index = 51)] Mortal51(::core::primitive::u8),
                    #[codec(index = 52)] Mortal52(::core::primitive::u8),
                    #[codec(index = 53)] Mortal53(::core::primitive::u8),
                    #[codec(index = 54)] Mortal54(::core::primitive::u8),
                    #[codec(index = 55)] Mortal55(::core::primitive::u8),
                    #[codec(index = 56)] Mortal56(::core::primitive::u8),
                    #[codec(index = 57)] Mortal57(::core::primitive::u8),
                    #[codec(index = 58)] Mortal58(::core::primitive::u8),
                    #[codec(index = 59)] Mortal59(::core::primitive::u8),
                    #[codec(index = 60)] Mortal60(::core::primitive::u8),
                    #[codec(index = 61)] Mortal61(::core::primitive::u8),
                    #[codec(index = 62)] Mortal62(::core::primitive::u8),
                    #[codec(index = 63)] Mortal63(::core::primitive::u8),
                    #[codec(index = 64)] Mortal64(::core::primitive::u8),
                    #[codec(index = 65)] Mortal65(::core::primitive::u8),
                    #[codec(index = 66)] Mortal66(::core::primitive::u8),
                    #[codec(index = 67)] Mortal67(::core::primitive::u8),
                    #[codec(index = 68)] Mortal68(::core::primitive::u8),
                    #[codec(index = 69)] Mortal69(::core::primitive::u8),
                    #[codec(index = 70)] Mortal70(::core::primitive::u8),
                    #[codec(index = 71)] Mortal71(::core::primitive::u8),
                    #[codec(index = 72)] Mortal72(::core::primitive::u8),
                    #[codec(index = 73)] Mortal73(::core::primitive::u8),
                    #[codec(index = 74)] Mortal74(::core::primitive::u8),
                    #[codec(index = 75)] Mortal75(::core::primitive::u8),
                    #[codec(index = 76)] Mortal76(::core::primitive::u8),
                    #[codec(index = 77)] Mortal77(::core::primitive::u8),
                    #[codec(index = 78)] Mortal78(::core::primitive::u8),
                    #[codec(index = 79)] Mortal79(::core::primitive::u8),
                    #[codec(index = 80)] Mortal80(::core::primitive::u8),
                    #[codec(index = 81)] Mortal81(::core::primitive::u8),
                    #[codec(index = 82)] Mortal82(::core::primitive::u8),
                    #[codec(index = 83)] Mortal83(::core::primitive::u8),
                    #[codec(index = 84)] Mortal84(::core::primitive::u8),
                    #[codec(index = 85)] Mortal85(::core::primitive::u8),
                    #[codec(index = 86)] Mortal86(::core::primitive::u8),
                    #[codec(index = 87)] Mortal87(::core::primitive::u8),
                    #[codec(index = 88)] Mortal88(::core::primitive::u8),
                    #[codec(index = 89)] Mortal89(::core::primitive::u8),
                    #[codec(index = 90)] Mortal90(::core::primitive::u8),
                    #[codec(index = 91)] Mortal91(::core::primitive::u8),
                    #[codec(index = 92)] Mortal92(::core::primitive::u8),
                    #[codec(index = 93)] Mortal93(::core::primitive::u8),
                    #[codec(index = 94)] Mortal94(::core::primitive::u8),
                    #[codec(index = 95)] Mortal95(::core::primitive::u8),
                    #[codec(index = 96)] Mortal96(::core::primitive::u8),
                    #[codec(index = 97)] Mortal97(::core::primitive::u8),
                    #[codec(index = 98)] Mortal98(::core::primitive::u8),
                    #[codec(index = 99)] Mortal99(::core::primitive::u8),
                    #[codec(index = 100)] Mortal100(::core::primitive::u8),
                    #[codec(index = 101)] Mortal101(::core::primitive::u8),
                    #[codec(index = 102)] Mortal102(::core::primitive::u8),
                    #[codec(index = 103)] Mortal103(::core::primitive::u8),
                    #[codec(index = 104)] Mortal104(::core::primitive::u8),
                    #[codec(index = 105)] Mortal105(::core::primitive::u8),
                    #[codec(index = 106)] Mortal106(::core::primitive::u8),
                    #[codec(index = 107)] Mortal107(::core::primitive::u8),
                    #[codec(index = 108)] Mortal108(::core::primitive::u8),
                    #[codec(index = 109)] Mortal109(::core::primitive::u8),
                    #[codec(index = 110)] Mortal110(::core::primitive::u8),
                    #[codec(index = 111)] Mortal111(::core::primitive::u8),
                    #[codec(index = 112)] Mortal112(::core::primitive::u8),
                    #[codec(index = 113)] Mortal113(::core::primitive::u8),
                    #[codec(index = 114)] Mortal114(::core::primitive::u8),
                    #[codec(index = 115)] Mortal115(::core::primitive::u8),
                    #[codec(index = 116)] Mortal116(::core::primitive::u8),
                    #[codec(index = 117)] Mortal117(::core::primitive::u8),
                    #[codec(index = 118)] Mortal118(::core::primitive::u8),
                    #[codec(index = 119)] Mortal119(::core::primitive::u8),
                    #[codec(index = 120)] Mortal120(::core::primitive::u8),
                    #[codec(index = 121)] Mortal121(::core::primitive::u8),
                    #[codec(index = 122)] Mortal122(::core::primitive::u8),
                    #[codec(index = 123)] Mortal123(::core::primitive::u8),
                    #[codec(index = 124)] Mortal124(::core::primitive::u8),
                    #[codec(index = 125)] Mortal125(::core::primitive::u8),
                    #[codec(index = 126)] Mortal126(::core::primitive::u8),
                    #[codec(index = 127)] Mortal127(::core::primitive::u8),
                    #[codec(index = 128)] Mortal128(::core::primitive::u8),
                    #[codec(index = 129)] Mortal129(::core::primitive::u8),
                    #[codec(index = 130)] Mortal130(::core::primitive::u8),
                    #[codec(index = 131)] Mortal131(::core::primitive::u8),
                    #[codec(index = 132)] Mortal132(::core::primitive::u8),
                    #[codec(index = 133)] Mortal133(::core::primitive::u8),
                    #[codec(index = 134)] Mortal134(::core::primitive::u8),
                    #[codec(index = 135)] Mortal135(::core::primitive::u8),
                    #[codec(index = 136)] Mortal136(::core::primitive::u8),
                    #[codec(index = 137)] Mortal137(::core::primitive::u8),
                    #[codec(index = 138)] Mortal138(::core::primitive::u8),
                    #[codec(index = 139)] Mortal139(::core::primitive::u8),
                    #[codec(index = 140)] Mortal140(::core::primitive::u8),
                    #[codec(index = 141)] Mortal141(::core::primitive::u8),
                    #[codec(index = 142)] Mortal142(::core::primitive::u8),
                    #[codec(index = 143)] Mortal143(::core::primitive::u8),
                    #[codec(index = 144)] Mortal144(::core::primitive::u8),
                    #[codec(index = 145)] Mortal145(::core::primitive::u8),
                    #[codec(index = 146)] Mortal146(::core::primitive::u8),
                    #[codec(index = 147)] Mortal147(::core::primitive::u8),
                    #[codec(index = 148)] Mortal148(::core::primitive::u8),
                    #[codec(index = 149)] Mortal149(::core::primitive::u8),
                    #[codec(index = 150)] Mortal150(::core::primitive::u8),
                    #[codec(index = 151)] Mortal151(::core::primitive::u8),
                    #[codec(index = 152)] Mortal152(::core::primitive::u8),
                    #[codec(index = 153)] Mortal153(::core::primitive::u8),
                    #[codec(index = 154)] Mortal154(::core::primitive::u8),
                    #[codec(index = 155)] Mortal155(::core::primitive::u8),
                    #[codec(index = 156)] Mortal156(::core::primitive::u8),
                    #[codec(index = 157)] Mortal157(::core::primitive::u8),
                    #[codec(index = 158)] Mortal158(::core::primitive::u8),
                    #[codec(index = 159)] Mortal159(::core::primitive::u8),
                    #[codec(index = 160)] Mortal160(::core::primitive::u8),
                    #[codec(index = 161)] Mortal161(::core::primitive::u8),
                    #[codec(index = 162)] Mortal162(::core::primitive::u8),
                    #[codec(index = 163)] Mortal163(::core::primitive::u8),
                    #[codec(index = 164)] Mortal164(::core::primitive::u8),
                    #[codec(index = 165)] Mortal165(::core::primitive::u8),
                    #[codec(index = 166)] Mortal166(::core::primitive::u8),
                    #[codec(index = 167)] Mortal167(::core::primitive::u8),
                    #[codec(index = 168)] Mortal168(::core::primitive::u8),
                    #[codec(index = 169)] Mortal169(::core::primitive::u8),
                    #[codec(index = 170)] Mortal170(::core::primitive::u8),
                    #[codec(index = 171)] Mortal171(::core::primitive::u8),
                    #[codec(index = 172)] Mortal172(::core::primitive::u8),
                    #[codec(index = 173)] Mortal173(::core::primitive::u8),
                    #[codec(index = 174)] Mortal174(::core::primitive::u8),
                    #[codec(index = 175)] Mortal175(::core::primitive::u8),
                    #[codec(index = 176)] Mortal176(::core::primitive::u8),
                    #[codec(index = 177)] Mortal177(::core::primitive::u8),
                    #[codec(index = 178)] Mortal178(::core::primitive::u8),
                    #[codec(index = 179)] Mortal179(::core::primitive::u8),
                    #[codec(index = 180)] Mortal180(::core::primitive::u8),
                    #[codec(index = 181)] Mortal181(::core::primitive::u8),
                    #[codec(index = 182)] Mortal182(::core::primitive::u8),
                    #[codec(index = 183)] Mortal183(::core::primitive::u8),
                    #[codec(index = 184)] Mortal184(::core::primitive::u8),
                    #[codec(index = 185)] Mortal185(::core::primitive::u8),
                    #[codec(index = 186)] Mortal186(::core::primitive::u8),
                    #[codec(index = 187)] Mortal187(::core::primitive::u8),
                    #[codec(index = 188)] Mortal188(::core::primitive::u8),
                    #[codec(index = 189)] Mortal189(::core::primitive::u8),
                    #[codec(index = 190)] Mortal190(::core::primitive::u8),
                    #[codec(index = 191)] Mortal191(::core::primitive::u8),
                    #[codec(index = 192)] Mortal192(::core::primitive::u8),
                    #[codec(index = 193)] Mortal193(::core::primitive::u8),
                    #[codec(index = 194)] Mortal194(::core::primitive::u8),
                    #[codec(index = 195)] Mortal195(::core::primitive::u8),
                    #[codec(index = 196)] Mortal196(::core::primitive::u8),
                    #[codec(index = 197)] Mortal197(::core::primitive::u8),
                    #[codec(index = 198)] Mortal198(::core::primitive::u8),
                    #[codec(index = 199)] Mortal199(::core::primitive::u8),
                    #[codec(index = 200)] Mortal200(::core::primitive::u8),
                    #[codec(index = 201)] Mortal201(::core::primitive::u8),
                    #[codec(index = 202)] Mortal202(::core::primitive::u8),
                    #[codec(index = 203)] Mortal203(::core::primitive::u8),
                    #[codec(index = 204)] Mortal204(::core::primitive::u8),
                    #[codec(index = 205)] Mortal205(::core::primitive::u8),
                    #[codec(index = 206)] Mortal206(::core::primitive::u8),
                    #[codec(index = 207)] Mortal207(::core::primitive::u8),
                    #[codec(index = 208)] Mortal208(::core::primitive::u8),
                    #[codec(index = 209)] Mortal209(::core::primitive::u8),
                    #[codec(index = 210)] Mortal210(::core::primitive::u8),
                    #[codec(index = 211)] Mortal211(::core::primitive::u8),
                    #[codec(index = 212)] Mortal212(::core::primitive::u8),
                    #[codec(index = 213)] Mortal213(::core::primitive::u8),
                    #[codec(index = 214)] Mortal214(::core::primitive::u8),
                    #[codec(index = 215)] Mortal215(::core::primitive::u8),
                    #[codec(index = 216)] Mortal216(::core::primitive::u8),
                    #[codec(index = 217)] Mortal217(::core::primitive::u8),
                    #[codec(index = 218)] Mortal218(::core::primitive::u8),
                    #[codec(index = 219)] Mortal219(::core::primitive::u8),
                    #[codec(index = 220)] Mortal220(::core::primitive::u8),
                    #[codec(index = 221)] Mortal221(::core::primitive::u8),
                    #[codec(index = 222)] Mortal222(::core::primitive::u8),
                    #[codec(index = 223)] Mortal223(::core::primitive::u8),
                    #[codec(index = 224)] Mortal224(::core::primitive::u8),
                    #[codec(index = 225)] Mortal225(::core::primitive::u8),
                    #[codec(index = 226)] Mortal226(::core::primitive::u8),
                    #[codec(index = 227)] Mortal227(::core::primitive::u8),
                    #[codec(index = 228)] Mortal228(::core::primitive::u8),
                    #[codec(index = 229)] Mortal229(::core::primitive::u8),
                    #[codec(index = 230)] Mortal230(::core::primitive::u8),
                    #[codec(index = 231)] Mortal231(::core::primitive::u8),
                    #[codec(index = 232)] Mortal232(::core::primitive::u8),
                    #[codec(index = 233)] Mortal233(::core::primitive::u8),
                    #[codec(index = 234)] Mortal234(::core::primitive::u8),
                    #[codec(index = 235)] Mortal235(::core::primitive::u8),
                    #[codec(index = 236)] Mortal236(::core::primitive::u8),
                    #[codec(index = 237)] Mortal237(::core::primitive::u8),
                    #[codec(index = 238)] Mortal238(::core::primitive::u8),
                    #[codec(index = 239)] Mortal239(::core::primitive::u8),
                    #[codec(index = 240)] Mortal240(::core::primitive::u8),
                    #[codec(index = 241)] Mortal241(::core::primitive::u8),
                    #[codec(index = 242)] Mortal242(::core::primitive::u8),
                    #[codec(index = 243)] Mortal243(::core::primitive::u8),
                    #[codec(index = 244)] Mortal244(::core::primitive::u8),
                    #[codec(index = 245)] Mortal245(::core::primitive::u8),
                    #[codec(index = 246)] Mortal246(::core::primitive::u8),
                    #[codec(index = 247)] Mortal247(::core::primitive::u8),
                    #[codec(index = 248)] Mortal248(::core::primitive::u8),
                    #[codec(index = 249)] Mortal249(::core::primitive::u8),
                    #[codec(index = 250)] Mortal250(::core::primitive::u8),
                    #[codec(index = 251)] Mortal251(::core::primitive::u8),
                    #[codec(index = 252)] Mortal252(::core::primitive::u8),
                    #[codec(index = 253)] Mortal253(::core::primitive::u8),
                    #[codec(index = 254)] Mortal254(::core::primitive::u8),
                    #[codec(index = 255)] Mortal255(::core::primitive::u8),
                }
            }
            pub mod header {
                use super::runtime_types;
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub struct Header<_0> {
                    pub parent_hash: ::subxt::ext::subxt_core::utils::H256,
                    #[codec(compact)] pub number: _0,
                    pub state_root: ::subxt::ext::subxt_core::utils::H256,
                    pub extrinsics_root: ::subxt::ext::subxt_core::utils::H256,
                    pub digest: runtime_types::sp_runtime::generic::digest::Digest,
                }
            }
        }
        pub mod transaction_validity {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum InvalidTransaction {
                #[codec(index = 0)] Call,
                #[codec(
                    index = 1
                )] Payment,
                #[codec(index = 2)] Future,
                #[codec(index = 3)] Stale,
                #[codec(index = 4)] BadProof,
                #[codec(index = 5)] AncientBirthBlock,
                #[codec(index = 6)] ExhaustsResources,
                #[codec(index = 7)] Custom(::core::primitive::u8),
                #[codec(index = 8)] BadMandatory,
                #[codec(index = 9)] MandatoryValidation,
                #[codec(index = 10)] BadSigner,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum TransactionSource {
                #[codec(index = 0)] InBlock,
                #[codec(
                    index = 1
                )] Local,
                #[codec(index = 2)] External,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum TransactionValidityError {
                #[codec(
                    index = 0
                )] Invalid(runtime_types::sp_runtime::transaction_validity::InvalidTransaction),
                #[codec(
                    index = 1
                )] Unknown(runtime_types::sp_runtime::transaction_validity::UnknownTransaction),
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum UnknownTransaction {
                #[codec(index = 0)] CannotLookup,
                #[codec(
                    index = 1
                )] NoUnsignedValidator,
                #[codec(index = 2)] Custom(::core::primitive::u8),
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct ValidTransaction {
                pub priority: ::core::primitive::u64,
                pub requires: ::subxt::ext::subxt_core::alloc::vec::Vec<::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>>,
                pub provides: ::subxt::ext::subxt_core::alloc::vec::Vec<::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>>,
                pub longevity: ::core::primitive::u64,
                pub propagate: ::core::primitive::bool,
            }
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub enum DispatchError {
            #[codec(index = 0)] Other,
            #[codec(index = 1)] CannotLookup,
            #[codec(index = 2)] BadOrigin,
            #[codec(index = 3)] Module(runtime_types::sp_runtime::ModuleError),
            #[codec(index = 4)] ConsumerRemaining,
            #[codec(index = 5)] NoProviders,
            #[codec(index = 6)] TooManyConsumers,
            #[codec(index = 7)] Token(runtime_types::sp_runtime::TokenError),
            #[codec(index = 8)] Arithmetic(runtime_types::sp_arithmetic::ArithmeticError),
            #[codec(index = 9)] Transactional(runtime_types::sp_runtime::TransactionalError),
            #[codec(index = 10)] Exhausted,
            #[codec(index = 11)] Corruption,
            #[codec(index = 12)] Unavailable,
            #[codec(index = 13)] RootNotAllowed,
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct DispatchErrorWithPostInfo<_0> {
            pub post_info: _0,
            pub error: runtime_types::sp_runtime::DispatchError,
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub enum ExtrinsicInclusionMode {
            #[codec(index = 0)] AllExtrinsics,
            #[codec(
                index = 1
            )] OnlyInherents,
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct ModuleError {
            pub index: ::core::primitive::u8,
            pub error: [::core::primitive::u8; 4usize],
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub enum MultiSignature {
            #[codec(
                index = 0
            )] Ed25519([::core::primitive::u8; 64usize]),
            #[codec(index = 1)] Sr25519([::core::primitive::u8; 64usize]),
            #[codec(index = 2)] Ecdsa([::core::primitive::u8; 65usize]),
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub enum TokenError {
            #[codec(index = 0)] FundsUnavailable,
            #[codec(
                index = 1
            )] OnlyProvider,
            #[codec(index = 2)] BelowMinimum,
            #[codec(index = 3)] CannotCreate,
            #[codec(index = 4)] UnknownAsset,
            #[codec(index = 5)] Frozen,
            #[codec(index = 6)] Unsupported,
            #[codec(index = 7)] CannotCreateHold,
            #[codec(index = 8)] NotExpendable,
            #[codec(index = 9)] Blocked,
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub enum TransactionalError {
            #[codec(index = 0)] LimitReached,
            #[codec(
                index = 1
            )] NoLayer,
        }
    }
    pub mod sp_trie {
        use super::runtime_types;
        pub mod storage_proof {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct StorageProof {
                pub trie_nodes: ::subxt::ext::subxt_core::alloc::vec::Vec<::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>>,
            }
        }
    }
    pub mod sp_version {
        use super::runtime_types;
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct RuntimeVersion {
            pub spec_name: ::subxt::ext::subxt_core::alloc::string::String,
            pub impl_name: ::subxt::ext::subxt_core::alloc::string::String,
            pub authoring_version: ::core::primitive::u32,
            pub spec_version: ::core::primitive::u32,
            pub impl_version: ::core::primitive::u32,
            pub apis: ::subxt::ext::subxt_core::alloc::vec::Vec<([::core::primitive::u8; 8usize], ::core::primitive::u32,)>,
            pub transaction_version: ::core::primitive::u32,
            pub state_version: ::core::primitive::u8,
        }
    }
    pub mod sp_weights {
        use super::runtime_types;
        pub mod weight_v2 {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct Weight {
                #[codec(compact)] pub ref_time: ::core::primitive::u64,
                #[codec(compact)] pub proof_size: ::core::primitive::u64,
            }
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub struct RuntimeDbWeight {
            pub read: ::core::primitive::u64,
            pub write: ::core::primitive::u64,
        }
    }
    pub mod staging_parachain_info {
        use super::runtime_types;
        pub mod pallet {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Call {}
        }
    }
    pub mod staging_xcm {
        use super::runtime_types;
        pub mod v3 {
            use super::runtime_types;
            pub mod multilocation {
                use super::runtime_types;
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub struct MultiLocation {
                    pub parents: ::core::primitive::u8,
                    pub interior: runtime_types::xcm::v3::junctions::Junctions,
                }
            }
        }
        pub mod v4 {
            use super::runtime_types;
            pub mod asset {
                use super::runtime_types;
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub struct Asset {
                    pub id: runtime_types::staging_xcm::v4::asset::AssetId,
                    pub fun: runtime_types::staging_xcm::v4::asset::Fungibility,
                }
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub enum AssetFilter {
                    #[codec(
                        index = 0
                    )] Definite(runtime_types::staging_xcm::v4::asset::Assets),
                    #[codec(
                        index = 1
                    )] Wild(runtime_types::staging_xcm::v4::asset::WildAsset),
                }
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub struct AssetId(pub runtime_types::staging_xcm::v4::location::Location);
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub enum AssetInstance {
                    #[codec(index = 0)] Undefined,
                    #[codec(
                        index = 1
                    )] Index(#[codec(compact)] ::core::primitive::u128),
                    #[codec(index = 2)] Array4([::core::primitive::u8; 4usize]),
                    #[codec(index = 3)] Array8([::core::primitive::u8; 8usize]),
                    #[codec(index = 4)] Array16([::core::primitive::u8; 16usize]),
                    #[codec(index = 5)] Array32([::core::primitive::u8; 32usize]),
                }
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub struct Assets(pub ::subxt::ext::subxt_core::alloc::vec::Vec<runtime_types::staging_xcm::v4::asset::Asset>);
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub enum Fungibility {
                    #[codec(index = 0)] Fungible(#[codec(
                        compact
                    )] ::core::primitive::u128, ),
                    #[codec(
                        index = 1
                    )] NonFungible(runtime_types::staging_xcm::v4::asset::AssetInstance),
                }
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub enum WildAsset {
                    #[codec(index = 0)] All,
                    #[codec(
                        index = 1
                    )] AllOf { id: runtime_types::staging_xcm::v4::asset::AssetId, fun: runtime_types::staging_xcm::v4::asset::WildFungibility },
                    #[codec(index = 2)] AllCounted(#[codec(compact)] ::core::primitive::u32),
                    #[codec(
                        index = 3
                    )] AllOfCounted {
                        id: runtime_types::staging_xcm::v4::asset::AssetId,
                        fun: runtime_types::staging_xcm::v4::asset::WildFungibility,
                        #[codec(
                            compact
                        )] count: ::core::primitive::u32,
                    },
                }
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub enum WildFungibility {
                    #[codec(index = 0)] Fungible,
                    #[codec(
                        index = 1
                    )] NonFungible,
                }
            }
            pub mod junction {
                use super::runtime_types;
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub enum Junction {
                    #[codec(index = 0)] Parachain(#[codec(compact)] ::core::primitive::u32),
                    #[codec(
                        index = 1
                    )] AccountId32 { network: ::core::option::Option<runtime_types::staging_xcm::v4::junction::NetworkId>, id: [::core::primitive::u8; 32usize] },
                    #[codec(
                        index = 2
                    )] AccountIndex64 {
                        network: ::core::option::Option<runtime_types::staging_xcm::v4::junction::NetworkId>,
                        #[codec(
                            compact
                        )] index: ::core::primitive::u64,
                    },
                    #[codec(
                        index = 3
                    )] AccountKey20 { network: ::core::option::Option<runtime_types::staging_xcm::v4::junction::NetworkId>, key: [::core::primitive::u8; 20usize] },
                    #[codec(index = 4)] PalletInstance(::core::primitive::u8),
                    #[codec(index = 5)] GeneralIndex(#[codec(
                        compact
                    )] ::core::primitive::u128, ),
                    #[codec(
                        index = 6
                    )] GeneralKey { length: ::core::primitive::u8, data: [::core::primitive::u8; 32usize] },
                    #[codec(index = 7)] OnlyChild,
                    #[codec(
                        index = 8
                    )] Plurality { id: runtime_types::xcm::v3::junction::BodyId, part: runtime_types::xcm::v3::junction::BodyPart },
                    #[codec(
                        index = 9
                    )] GlobalConsensus(runtime_types::staging_xcm::v4::junction::NetworkId),
                }
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub enum NetworkId {
                    #[codec(
                        index = 0
                    )] ByGenesis([::core::primitive::u8; 32usize]),
                    #[codec(
                        index = 1
                    )] ByFork { block_number: ::core::primitive::u64, block_hash: [::core::primitive::u8; 32usize] },
                    #[codec(index = 2)] Polkadot,
                    #[codec(index = 3)] Kusama,
                    #[codec(index = 4)] Westend,
                    #[codec(index = 5)] Rococo,
                    #[codec(index = 6)] Wococo,
                    #[codec(index = 7)] Ethereum {
                        #[codec(
                            compact
                        )] chain_id: ::core::primitive::u64,
                    },
                    #[codec(index = 8)] BitcoinCore,
                    #[codec(index = 9)] BitcoinCash,
                    #[codec(index = 10)] PolkadotBulletin,
                }
            }
            pub mod junctions {
                use super::runtime_types;
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub enum Junctions {
                    #[codec(index = 0)] Here,
                    #[codec(
                        index = 1
                    )] X1([runtime_types::staging_xcm::v4::junction::Junction; 1usize]),
                    #[codec(
                        index = 2
                    )] X2([runtime_types::staging_xcm::v4::junction::Junction; 2usize]),
                    #[codec(
                        index = 3
                    )] X3([runtime_types::staging_xcm::v4::junction::Junction; 3usize]),
                    #[codec(
                        index = 4
                    )] X4([runtime_types::staging_xcm::v4::junction::Junction; 4usize]),
                    #[codec(
                        index = 5
                    )] X5([runtime_types::staging_xcm::v4::junction::Junction; 5usize]),
                    #[codec(
                        index = 6
                    )] X6([runtime_types::staging_xcm::v4::junction::Junction; 6usize]),
                    #[codec(
                        index = 7
                    )] X7([runtime_types::staging_xcm::v4::junction::Junction; 7usize]),
                    #[codec(
                        index = 8
                    )] X8([runtime_types::staging_xcm::v4::junction::Junction; 8usize]),
                }
            }
            pub mod location {
                use super::runtime_types;
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub struct Location {
                    pub parents: ::core::primitive::u8,
                    pub interior: runtime_types::staging_xcm::v4::junctions::Junctions,
                }
            }
            pub mod traits {
                use super::runtime_types;
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub enum Outcome {
                    #[codec(
                        index = 0
                    )] Complete { used: runtime_types::sp_weights::weight_v2::Weight },
                    #[codec(
                        index = 1
                    )] Incomplete { used: runtime_types::sp_weights::weight_v2::Weight, error: runtime_types::xcm::v3::traits::Error },
                    #[codec(index = 2)] Error { error: runtime_types::xcm::v3::traits::Error },
                }
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Instruction {
                #[codec(
                    index = 0
                )] WithdrawAsset(runtime_types::staging_xcm::v4::asset::Assets),
                #[codec(
                    index = 1
                )] ReserveAssetDeposited(runtime_types::staging_xcm::v4::asset::Assets),
                #[codec(
                    index = 2
                )] ReceiveTeleportedAsset(runtime_types::staging_xcm::v4::asset::Assets),
                #[codec(index = 3)] QueryResponse {
                    #[codec(
                        compact
                    )] query_id: ::core::primitive::u64,
                    response: runtime_types::staging_xcm::v4::Response,
                    max_weight: runtime_types::sp_weights::weight_v2::Weight,
                    querier: ::core::option::Option<runtime_types::staging_xcm::v4::location::Location>,
                },
                #[codec(
                    index = 4
                )] TransferAsset { assets: runtime_types::staging_xcm::v4::asset::Assets, beneficiary: runtime_types::staging_xcm::v4::location::Location },
                #[codec(
                    index = 5
                )] TransferReserveAsset { assets: runtime_types::staging_xcm::v4::asset::Assets, dest: runtime_types::staging_xcm::v4::location::Location, xcm: runtime_types::staging_xcm::v4::Xcm },
                #[codec(
                    index = 6
                )] Transact { origin_kind: runtime_types::xcm::v3::OriginKind, require_weight_at_most: runtime_types::sp_weights::weight_v2::Weight, call: runtime_types::xcm::double_encoded::DoubleEncoded },
                #[codec(index = 7)] HrmpNewChannelOpenRequest {
                    #[codec(
                        compact
                    )] sender: ::core::primitive::u32,
                    #[codec(compact)] max_message_size: ::core::primitive::u32,
                    #[codec(compact)] max_capacity: ::core::primitive::u32,
                },
                #[codec(index = 8)] HrmpChannelAccepted {
                    #[codec(
                        compact
                    )] recipient: ::core::primitive::u32,
                },
                #[codec(index = 9)] HrmpChannelClosing {
                    #[codec(
                        compact
                    )] initiator: ::core::primitive::u32,
                    #[codec(compact)] sender: ::core::primitive::u32,
                    #[codec(compact)] recipient: ::core::primitive::u32,
                },
                #[codec(index = 10)] ClearOrigin,
                #[codec(
                    index = 11
                )] DescendOrigin(runtime_types::staging_xcm::v4::junctions::Junctions),
                #[codec(
                    index = 12
                )] ReportError(runtime_types::staging_xcm::v4::QueryResponseInfo),
                #[codec(
                    index = 13
                )] DepositAsset { assets: runtime_types::staging_xcm::v4::asset::AssetFilter, beneficiary: runtime_types::staging_xcm::v4::location::Location },
                #[codec(
                    index = 14
                )] DepositReserveAsset { assets: runtime_types::staging_xcm::v4::asset::AssetFilter, dest: runtime_types::staging_xcm::v4::location::Location, xcm: runtime_types::staging_xcm::v4::Xcm },
                #[codec(
                    index = 15
                )] ExchangeAsset { give: runtime_types::staging_xcm::v4::asset::AssetFilter, want: runtime_types::staging_xcm::v4::asset::Assets, maximal: ::core::primitive::bool },
                #[codec(
                    index = 16
                )] InitiateReserveWithdraw { assets: runtime_types::staging_xcm::v4::asset::AssetFilter, reserve: runtime_types::staging_xcm::v4::location::Location, xcm: runtime_types::staging_xcm::v4::Xcm },
                #[codec(
                    index = 17
                )] InitiateTeleport { assets: runtime_types::staging_xcm::v4::asset::AssetFilter, dest: runtime_types::staging_xcm::v4::location::Location, xcm: runtime_types::staging_xcm::v4::Xcm },
                #[codec(
                    index = 18
                )] ReportHolding { response_info: runtime_types::staging_xcm::v4::QueryResponseInfo, assets: runtime_types::staging_xcm::v4::asset::AssetFilter },
                #[codec(
                    index = 19
                )] BuyExecution { fees: runtime_types::staging_xcm::v4::asset::Asset, weight_limit: runtime_types::xcm::v3::WeightLimit },
                #[codec(index = 20)] RefundSurplus,
                #[codec(index = 21)] SetErrorHandler(runtime_types::staging_xcm::v4::Xcm),
                #[codec(index = 22)] SetAppendix(runtime_types::staging_xcm::v4::Xcm),
                #[codec(index = 23)] ClearError,
                #[codec(
                    index = 24
                )] ClaimAsset { assets: runtime_types::staging_xcm::v4::asset::Assets, ticket: runtime_types::staging_xcm::v4::location::Location },
                #[codec(index = 25)] Trap(#[codec(compact)] ::core::primitive::u64),
                #[codec(index = 26)] SubscribeVersion {
                    #[codec(
                        compact
                    )] query_id: ::core::primitive::u64,
                    max_response_weight: runtime_types::sp_weights::weight_v2::Weight,
                },
                #[codec(index = 27)] UnsubscribeVersion,
                #[codec(index = 28)] BurnAsset(runtime_types::staging_xcm::v4::asset::Assets),
                #[codec(
                    index = 29
                )] ExpectAsset(runtime_types::staging_xcm::v4::asset::Assets),
                #[codec(
                    index = 30
                )] ExpectOrigin(::core::option::Option<runtime_types::staging_xcm::v4::location::Location>),
                #[codec(
                    index = 31
                )] ExpectError(::core::option::Option<(::core::primitive::u32, runtime_types::xcm::v3::traits::Error,)>),
                #[codec(
                    index = 32
                )] ExpectTransactStatus(runtime_types::xcm::v3::MaybeErrorCode),
                #[codec(
                    index = 33
                )] QueryPallet { module_name: ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>, response_info: runtime_types::staging_xcm::v4::QueryResponseInfo },
                #[codec(index = 34)] ExpectPallet {
                    #[codec(
                        compact
                    )] index: ::core::primitive::u32,
                    name: ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>,
                    module_name: ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>,
                    #[codec(compact)] crate_major: ::core::primitive::u32,
                    #[codec(compact)] min_crate_minor: ::core::primitive::u32,
                },
                #[codec(
                    index = 35
                )] ReportTransactStatus(runtime_types::staging_xcm::v4::QueryResponseInfo),
                #[codec(index = 36)] ClearTransactStatus,
                #[codec(
                    index = 37
                )] UniversalOrigin(runtime_types::staging_xcm::v4::junction::Junction),
                #[codec(
                    index = 38
                )] ExportMessage { network: runtime_types::staging_xcm::v4::junction::NetworkId, destination: runtime_types::staging_xcm::v4::junctions::Junctions, xcm: runtime_types::staging_xcm::v4::Xcm },
                #[codec(
                    index = 39
                )] LockAsset { asset: runtime_types::staging_xcm::v4::asset::Asset, unlocker: runtime_types::staging_xcm::v4::location::Location },
                #[codec(
                    index = 40
                )] UnlockAsset { asset: runtime_types::staging_xcm::v4::asset::Asset, target: runtime_types::staging_xcm::v4::location::Location },
                #[codec(
                    index = 41
                )] NoteUnlockable { asset: runtime_types::staging_xcm::v4::asset::Asset, owner: runtime_types::staging_xcm::v4::location::Location },
                #[codec(
                    index = 42
                )] RequestUnlock { asset: runtime_types::staging_xcm::v4::asset::Asset, locker: runtime_types::staging_xcm::v4::location::Location },
                #[codec(index = 43)] SetFeesMode { jit_withdraw: ::core::primitive::bool },
                #[codec(index = 44)] SetTopic([::core::primitive::u8; 32usize]),
                #[codec(index = 45)] ClearTopic,
                #[codec(
                    index = 46
                )] AliasOrigin(runtime_types::staging_xcm::v4::location::Location),
                #[codec(
                    index = 47
                )] UnpaidExecution { weight_limit: runtime_types::xcm::v3::WeightLimit, check_origin: ::core::option::Option<runtime_types::staging_xcm::v4::location::Location> },
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct PalletInfo {
                #[codec(compact)] pub index: ::core::primitive::u32,
                pub name: runtime_types::bounded_collections::bounded_vec::BoundedVec<::core::primitive::u8>,
                pub module_name: runtime_types::bounded_collections::bounded_vec::BoundedVec<::core::primitive::u8>,
                #[codec(compact)] pub major: ::core::primitive::u32,
                #[codec(compact)] pub minor: ::core::primitive::u32,
                #[codec(compact)] pub patch: ::core::primitive::u32,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct QueryResponseInfo {
                pub destination: runtime_types::staging_xcm::v4::location::Location,
                #[codec(compact)] pub query_id: ::core::primitive::u64,
                pub max_weight: runtime_types::sp_weights::weight_v2::Weight,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Response {
                #[codec(index = 0)] Null,
                #[codec(
                    index = 1
                )] Assets(runtime_types::staging_xcm::v4::asset::Assets),
                #[codec(
                    index = 2
                )] ExecutionResult(::core::option::Option<(::core::primitive::u32, runtime_types::xcm::v3::traits::Error,)>),
                #[codec(index = 3)] Version(::core::primitive::u32),
                #[codec(
                    index = 4
                )] PalletsInfo(runtime_types::bounded_collections::bounded_vec::BoundedVec<runtime_types::staging_xcm::v4::PalletInfo>),
                #[codec(index = 5)] DispatchResult(runtime_types::xcm::v3::MaybeErrorCode),
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct Xcm(pub ::subxt::ext::subxt_core::alloc::vec::Vec<runtime_types::staging_xcm::v4::Instruction>);
        }
    }
    pub mod staging_xcm_executor {
        use super::runtime_types;
        pub mod traits {
            use super::runtime_types;
            pub mod asset_transfer {
                use super::runtime_types;
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub enum TransferType {
                    #[codec(index = 0)] Teleport,
                    #[codec(
                        index = 1
                    )] LocalReserve,
                    #[codec(index = 2)] DestinationReserve,
                    #[codec(index = 3)] RemoteReserve(runtime_types::xcm::VersionedLocation),
                }
            }
        }
    }
    pub mod xcm {
        use super::runtime_types;
        pub mod double_encoded {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct DoubleEncoded {
                pub encoded: ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>,
            }
        }
        pub mod v2 {
            use super::runtime_types;
            pub mod junction {
                use super::runtime_types;
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub enum Junction {
                    #[codec(index = 0)] Parachain(#[codec(compact)] ::core::primitive::u32),
                    #[codec(
                        index = 1
                    )] AccountId32 { network: runtime_types::xcm::v2::NetworkId, id: [::core::primitive::u8; 32usize] },
                    #[codec(
                        index = 2
                    )] AccountIndex64 {
                        network: runtime_types::xcm::v2::NetworkId,
                        #[codec(
                            compact
                        )] index: ::core::primitive::u64,
                    },
                    #[codec(
                        index = 3
                    )] AccountKey20 { network: runtime_types::xcm::v2::NetworkId, key: [::core::primitive::u8; 20usize] },
                    #[codec(index = 4)] PalletInstance(::core::primitive::u8),
                    #[codec(index = 5)] GeneralIndex(#[codec(
                        compact
                    )] ::core::primitive::u128, ),
                    #[codec(
                        index = 6
                    )] GeneralKey(runtime_types::bounded_collections::weak_bounded_vec::WeakBoundedVec<::core::primitive::u8>),
                    #[codec(index = 7)] OnlyChild,
                    #[codec(
                        index = 8
                    )] Plurality { id: runtime_types::xcm::v2::BodyId, part: runtime_types::xcm::v2::BodyPart },
                }
            }
            pub mod multiasset {
                use super::runtime_types;
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub enum AssetId {
                    #[codec(
                        index = 0
                    )] Concrete(runtime_types::xcm::v2::multilocation::MultiLocation),
                    #[codec(
                        index = 1
                    )] Abstract(::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>),
                }
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub enum AssetInstance {
                    #[codec(index = 0)] Undefined,
                    #[codec(
                        index = 1
                    )] Index(#[codec(compact)] ::core::primitive::u128),
                    #[codec(index = 2)] Array4([::core::primitive::u8; 4usize]),
                    #[codec(index = 3)] Array8([::core::primitive::u8; 8usize]),
                    #[codec(index = 4)] Array16([::core::primitive::u8; 16usize]),
                    #[codec(index = 5)] Array32([::core::primitive::u8; 32usize]),
                    #[codec(
                        index = 6
                    )] Blob(::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>),
                }
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub enum Fungibility {
                    #[codec(index = 0)] Fungible(#[codec(
                        compact
                    )] ::core::primitive::u128, ),
                    #[codec(
                        index = 1
                    )] NonFungible(runtime_types::xcm::v2::multiasset::AssetInstance),
                }
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub struct MultiAsset {
                    pub id: runtime_types::xcm::v2::multiasset::AssetId,
                    pub fun: runtime_types::xcm::v2::multiasset::Fungibility,
                }
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub enum MultiAssetFilter {
                    #[codec(
                        index = 0
                    )] Definite(runtime_types::xcm::v2::multiasset::MultiAssets),
                    #[codec(
                        index = 1
                    )] Wild(runtime_types::xcm::v2::multiasset::WildMultiAsset),
                }
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub struct MultiAssets(pub ::subxt::ext::subxt_core::alloc::vec::Vec<runtime_types::xcm::v2::multiasset::MultiAsset>);
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub enum WildFungibility {
                    #[codec(index = 0)] Fungible,
                    #[codec(
                        index = 1
                    )] NonFungible,
                }
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub enum WildMultiAsset {
                    #[codec(index = 0)] All,
                    #[codec(
                        index = 1
                    )] AllOf { id: runtime_types::xcm::v2::multiasset::AssetId, fun: runtime_types::xcm::v2::multiasset::WildFungibility },
                }
            }
            pub mod multilocation {
                use super::runtime_types;
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub enum Junctions {
                    #[codec(index = 0)] Here,
                    #[codec(index = 1)] X1(runtime_types::xcm::v2::junction::Junction),
                    #[codec(
                        index = 2
                    )] X2(runtime_types::xcm::v2::junction::Junction, runtime_types::xcm::v2::junction::Junction),
                    #[codec(
                        index = 3
                    )] X3(runtime_types::xcm::v2::junction::Junction, runtime_types::xcm::v2::junction::Junction, runtime_types::xcm::v2::junction::Junction),
                    #[codec(
                        index = 4
                    )] X4(runtime_types::xcm::v2::junction::Junction, runtime_types::xcm::v2::junction::Junction, runtime_types::xcm::v2::junction::Junction, runtime_types::xcm::v2::junction::Junction),
                    #[codec(
                        index = 5
                    )] X5(runtime_types::xcm::v2::junction::Junction, runtime_types::xcm::v2::junction::Junction, runtime_types::xcm::v2::junction::Junction, runtime_types::xcm::v2::junction::Junction, runtime_types::xcm::v2::junction::Junction),
                    #[codec(
                        index = 6
                    )] X6(runtime_types::xcm::v2::junction::Junction, runtime_types::xcm::v2::junction::Junction, runtime_types::xcm::v2::junction::Junction, runtime_types::xcm::v2::junction::Junction, runtime_types::xcm::v2::junction::Junction, runtime_types::xcm::v2::junction::Junction),
                    #[codec(
                        index = 7
                    )] X7(runtime_types::xcm::v2::junction::Junction, runtime_types::xcm::v2::junction::Junction, runtime_types::xcm::v2::junction::Junction, runtime_types::xcm::v2::junction::Junction, runtime_types::xcm::v2::junction::Junction, runtime_types::xcm::v2::junction::Junction, runtime_types::xcm::v2::junction::Junction),
                    #[codec(
                        index = 8
                    )] X8(runtime_types::xcm::v2::junction::Junction, runtime_types::xcm::v2::junction::Junction, runtime_types::xcm::v2::junction::Junction, runtime_types::xcm::v2::junction::Junction, runtime_types::xcm::v2::junction::Junction, runtime_types::xcm::v2::junction::Junction, runtime_types::xcm::v2::junction::Junction, runtime_types::xcm::v2::junction::Junction),
                }
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub struct MultiLocation {
                    pub parents: ::core::primitive::u8,
                    pub interior: runtime_types::xcm::v2::multilocation::Junctions,
                }
            }
            pub mod traits {
                use super::runtime_types;
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub enum Error {
                    #[codec(index = 0)] Overflow,
                    #[codec(index = 1)] Unimplemented,
                    #[codec(index = 2)] UntrustedReserveLocation,
                    #[codec(index = 3)] UntrustedTeleportLocation,
                    #[codec(index = 4)] MultiLocationFull,
                    #[codec(index = 5)] MultiLocationNotInvertible,
                    #[codec(index = 6)] BadOrigin,
                    #[codec(index = 7)] InvalidLocation,
                    #[codec(index = 8)] AssetNotFound,
                    #[codec(index = 9)] FailedToTransactAsset,
                    #[codec(index = 10)] NotWithdrawable,
                    #[codec(index = 11)] LocationCannotHold,
                    #[codec(index = 12)] ExceedsMaxMessageSize,
                    #[codec(index = 13)] DestinationUnsupported,
                    #[codec(index = 14)] Transport,
                    #[codec(index = 15)] Unroutable,
                    #[codec(index = 16)] UnknownClaim,
                    #[codec(index = 17)] FailedToDecode,
                    #[codec(index = 18)] MaxWeightInvalid,
                    #[codec(index = 19)] NotHoldingFees,
                    #[codec(index = 20)] TooExpensive,
                    #[codec(index = 21)] Trap(::core::primitive::u64),
                    #[codec(index = 22)] UnhandledXcmVersion,
                    #[codec(index = 23)] WeightLimitReached(::core::primitive::u64),
                    #[codec(index = 24)] Barrier,
                    #[codec(index = 25)] WeightNotComputable,
                }
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum BodyId {
                #[codec(index = 0)] Unit,
                #[codec(
                    index = 1
                )] Named(runtime_types::bounded_collections::weak_bounded_vec::WeakBoundedVec<::core::primitive::u8>),
                #[codec(index = 2)] Index(#[codec(compact)] ::core::primitive::u32),
                #[codec(index = 3)] Executive,
                #[codec(index = 4)] Technical,
                #[codec(index = 5)] Legislative,
                #[codec(index = 6)] Judicial,
                #[codec(index = 7)] Defense,
                #[codec(index = 8)] Administration,
                #[codec(index = 9)] Treasury,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum BodyPart {
                #[codec(index = 0)] Voice,
                #[codec(
                    index = 1
                )] Members { #[codec(compact)] count: ::core::primitive::u32 },
                #[codec(index = 2)] Fraction {
                    #[codec(
                        compact
                    )] nom: ::core::primitive::u32,
                    #[codec(compact)] denom: ::core::primitive::u32,
                },
                #[codec(index = 3)] AtLeastProportion {
                    #[codec(
                        compact
                    )] nom: ::core::primitive::u32,
                    #[codec(compact)] denom: ::core::primitive::u32,
                },
                #[codec(index = 4)] MoreThanProportion {
                    #[codec(
                        compact
                    )] nom: ::core::primitive::u32,
                    #[codec(compact)] denom: ::core::primitive::u32,
                },
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Instruction {
                #[codec(
                    index = 0
                )] WithdrawAsset(runtime_types::xcm::v2::multiasset::MultiAssets),
                #[codec(
                    index = 1
                )] ReserveAssetDeposited(runtime_types::xcm::v2::multiasset::MultiAssets),
                #[codec(
                    index = 2
                )] ReceiveTeleportedAsset(runtime_types::xcm::v2::multiasset::MultiAssets),
                #[codec(index = 3)] QueryResponse {
                    #[codec(
                        compact
                    )] query_id: ::core::primitive::u64,
                    response: runtime_types::xcm::v2::Response,
                    #[codec(compact)] max_weight: ::core::primitive::u64,
                },
                #[codec(
                    index = 4
                )] TransferAsset { assets: runtime_types::xcm::v2::multiasset::MultiAssets, beneficiary: runtime_types::xcm::v2::multilocation::MultiLocation },
                #[codec(
                    index = 5
                )] TransferReserveAsset { assets: runtime_types::xcm::v2::multiasset::MultiAssets, dest: runtime_types::xcm::v2::multilocation::MultiLocation, xcm: runtime_types::xcm::v2::Xcm },
                #[codec(
                    index = 6
                )] Transact {
                    origin_type: runtime_types::xcm::v2::OriginKind,
                    #[codec(
                        compact
                    )] require_weight_at_most: ::core::primitive::u64,
                    call: runtime_types::xcm::double_encoded::DoubleEncoded,
                },
                #[codec(index = 7)] HrmpNewChannelOpenRequest {
                    #[codec(
                        compact
                    )] sender: ::core::primitive::u32,
                    #[codec(compact)] max_message_size: ::core::primitive::u32,
                    #[codec(compact)] max_capacity: ::core::primitive::u32,
                },
                #[codec(index = 8)] HrmpChannelAccepted {
                    #[codec(
                        compact
                    )] recipient: ::core::primitive::u32,
                },
                #[codec(index = 9)] HrmpChannelClosing {
                    #[codec(
                        compact
                    )] initiator: ::core::primitive::u32,
                    #[codec(compact)] sender: ::core::primitive::u32,
                    #[codec(compact)] recipient: ::core::primitive::u32,
                },
                #[codec(index = 10)] ClearOrigin,
                #[codec(
                    index = 11
                )] DescendOrigin(runtime_types::xcm::v2::multilocation::Junctions),
                #[codec(index = 12)] ReportError {
                    #[codec(
                        compact
                    )] query_id: ::core::primitive::u64,
                    dest: runtime_types::xcm::v2::multilocation::MultiLocation,
                    #[codec(compact)] max_response_weight: ::core::primitive::u64,
                },
                #[codec(
                    index = 13
                )] DepositAsset {
                    assets: runtime_types::xcm::v2::multiasset::MultiAssetFilter,
                    #[codec(
                        compact
                    )] max_assets: ::core::primitive::u32,
                    beneficiary: runtime_types::xcm::v2::multilocation::MultiLocation,
                },
                #[codec(
                    index = 14
                )] DepositReserveAsset {
                    assets: runtime_types::xcm::v2::multiasset::MultiAssetFilter,
                    #[codec(
                        compact
                    )] max_assets: ::core::primitive::u32,
                    dest: runtime_types::xcm::v2::multilocation::MultiLocation,
                    xcm: runtime_types::xcm::v2::Xcm,
                },
                #[codec(
                    index = 15
                )] ExchangeAsset { give: runtime_types::xcm::v2::multiasset::MultiAssetFilter, receive: runtime_types::xcm::v2::multiasset::MultiAssets },
                #[codec(
                    index = 16
                )] InitiateReserveWithdraw { assets: runtime_types::xcm::v2::multiasset::MultiAssetFilter, reserve: runtime_types::xcm::v2::multilocation::MultiLocation, xcm: runtime_types::xcm::v2::Xcm },
                #[codec(
                    index = 17
                )] InitiateTeleport { assets: runtime_types::xcm::v2::multiasset::MultiAssetFilter, dest: runtime_types::xcm::v2::multilocation::MultiLocation, xcm: runtime_types::xcm::v2::Xcm },
                #[codec(index = 18)] QueryHolding {
                    #[codec(
                        compact
                    )] query_id: ::core::primitive::u64,
                    dest: runtime_types::xcm::v2::multilocation::MultiLocation,
                    assets: runtime_types::xcm::v2::multiasset::MultiAssetFilter,
                    #[codec(compact)] max_response_weight: ::core::primitive::u64,
                },
                #[codec(
                    index = 19
                )] BuyExecution { fees: runtime_types::xcm::v2::multiasset::MultiAsset, weight_limit: runtime_types::xcm::v2::WeightLimit },
                #[codec(index = 20)] RefundSurplus,
                #[codec(index = 21)] SetErrorHandler(runtime_types::xcm::v2::Xcm),
                #[codec(index = 22)] SetAppendix(runtime_types::xcm::v2::Xcm),
                #[codec(index = 23)] ClearError,
                #[codec(
                    index = 24
                )] ClaimAsset { assets: runtime_types::xcm::v2::multiasset::MultiAssets, ticket: runtime_types::xcm::v2::multilocation::MultiLocation },
                #[codec(index = 25)] Trap(#[codec(compact)] ::core::primitive::u64),
                #[codec(index = 26)] SubscribeVersion {
                    #[codec(
                        compact
                    )] query_id: ::core::primitive::u64,
                    #[codec(compact)] max_response_weight: ::core::primitive::u64,
                },
                #[codec(index = 27)] UnsubscribeVersion,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum NetworkId {
                #[codec(index = 0)] Any,
                #[codec(
                    index = 1
                )] Named(runtime_types::bounded_collections::weak_bounded_vec::WeakBoundedVec<::core::primitive::u8>),
                #[codec(index = 2)] Polkadot,
                #[codec(index = 3)] Kusama,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum OriginKind {
                #[codec(index = 0)] Native,
                #[codec(
                    index = 1
                )] SovereignAccount,
                #[codec(index = 2)] Superuser,
                #[codec(index = 3)] Xcm,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Response {
                #[codec(index = 0)] Null,
                #[codec(
                    index = 1
                )] Assets(runtime_types::xcm::v2::multiasset::MultiAssets),
                #[codec(
                    index = 2
                )] ExecutionResult(::core::option::Option<(::core::primitive::u32, runtime_types::xcm::v2::traits::Error,)>),
                #[codec(index = 3)] Version(::core::primitive::u32),
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum WeightLimit {
                #[codec(index = 0)] Unlimited,
                #[codec(
                    index = 1
                )] Limited(#[codec(compact)] ::core::primitive::u64),
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct Xcm(pub ::subxt::ext::subxt_core::alloc::vec::Vec<runtime_types::xcm::v2::Instruction>);
        }
        pub mod v3 {
            use super::runtime_types;
            pub mod junction {
                use super::runtime_types;
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub enum BodyId {
                    #[codec(index = 0)] Unit,
                    #[codec(
                        index = 1
                    )] Moniker([::core::primitive::u8; 4usize]),
                    #[codec(index = 2)] Index(#[codec(compact)] ::core::primitive::u32),
                    #[codec(index = 3)] Executive,
                    #[codec(index = 4)] Technical,
                    #[codec(index = 5)] Legislative,
                    #[codec(index = 6)] Judicial,
                    #[codec(index = 7)] Defense,
                    #[codec(index = 8)] Administration,
                    #[codec(index = 9)] Treasury,
                }
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub enum BodyPart {
                    #[codec(index = 0)] Voice,
                    #[codec(
                        index = 1
                    )] Members { #[codec(compact)] count: ::core::primitive::u32 },
                    #[codec(index = 2)] Fraction {
                        #[codec(
                            compact
                        )] nom: ::core::primitive::u32,
                        #[codec(compact)] denom: ::core::primitive::u32,
                    },
                    #[codec(index = 3)] AtLeastProportion {
                        #[codec(
                            compact
                        )] nom: ::core::primitive::u32,
                        #[codec(compact)] denom: ::core::primitive::u32,
                    },
                    #[codec(index = 4)] MoreThanProportion {
                        #[codec(
                            compact
                        )] nom: ::core::primitive::u32,
                        #[codec(compact)] denom: ::core::primitive::u32,
                    },
                }
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub enum Junction {
                    #[codec(index = 0)] Parachain(#[codec(compact)] ::core::primitive::u32),
                    #[codec(
                        index = 1
                    )] AccountId32 { network: ::core::option::Option<runtime_types::xcm::v3::junction::NetworkId>, id: [::core::primitive::u8; 32usize] },
                    #[codec(
                        index = 2
                    )] AccountIndex64 {
                        network: ::core::option::Option<runtime_types::xcm::v3::junction::NetworkId>,
                        #[codec(
                            compact
                        )] index: ::core::primitive::u64,
                    },
                    #[codec(
                        index = 3
                    )] AccountKey20 { network: ::core::option::Option<runtime_types::xcm::v3::junction::NetworkId>, key: [::core::primitive::u8; 20usize] },
                    #[codec(index = 4)] PalletInstance(::core::primitive::u8),
                    #[codec(index = 5)] GeneralIndex(#[codec(
                        compact
                    )] ::core::primitive::u128, ),
                    #[codec(
                        index = 6
                    )] GeneralKey { length: ::core::primitive::u8, data: [::core::primitive::u8; 32usize] },
                    #[codec(index = 7)] OnlyChild,
                    #[codec(
                        index = 8
                    )] Plurality { id: runtime_types::xcm::v3::junction::BodyId, part: runtime_types::xcm::v3::junction::BodyPart },
                    #[codec(
                        index = 9
                    )] GlobalConsensus(runtime_types::xcm::v3::junction::NetworkId),
                }
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub enum NetworkId {
                    #[codec(
                        index = 0
                    )] ByGenesis([::core::primitive::u8; 32usize]),
                    #[codec(
                        index = 1
                    )] ByFork { block_number: ::core::primitive::u64, block_hash: [::core::primitive::u8; 32usize] },
                    #[codec(index = 2)] Polkadot,
                    #[codec(index = 3)] Kusama,
                    #[codec(index = 4)] Westend,
                    #[codec(index = 5)] Rococo,
                    #[codec(index = 6)] Wococo,
                    #[codec(index = 7)] Ethereum {
                        #[codec(
                            compact
                        )] chain_id: ::core::primitive::u64,
                    },
                    #[codec(index = 8)] BitcoinCore,
                    #[codec(index = 9)] BitcoinCash,
                    #[codec(index = 10)] PolkadotBulletin,
                }
            }
            pub mod junctions {
                use super::runtime_types;
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub enum Junctions {
                    #[codec(index = 0)] Here,
                    #[codec(index = 1)] X1(runtime_types::xcm::v3::junction::Junction),
                    #[codec(
                        index = 2
                    )] X2(runtime_types::xcm::v3::junction::Junction, runtime_types::xcm::v3::junction::Junction),
                    #[codec(
                        index = 3
                    )] X3(runtime_types::xcm::v3::junction::Junction, runtime_types::xcm::v3::junction::Junction, runtime_types::xcm::v3::junction::Junction),
                    #[codec(
                        index = 4
                    )] X4(runtime_types::xcm::v3::junction::Junction, runtime_types::xcm::v3::junction::Junction, runtime_types::xcm::v3::junction::Junction, runtime_types::xcm::v3::junction::Junction),
                    #[codec(
                        index = 5
                    )] X5(runtime_types::xcm::v3::junction::Junction, runtime_types::xcm::v3::junction::Junction, runtime_types::xcm::v3::junction::Junction, runtime_types::xcm::v3::junction::Junction, runtime_types::xcm::v3::junction::Junction),
                    #[codec(
                        index = 6
                    )] X6(runtime_types::xcm::v3::junction::Junction, runtime_types::xcm::v3::junction::Junction, runtime_types::xcm::v3::junction::Junction, runtime_types::xcm::v3::junction::Junction, runtime_types::xcm::v3::junction::Junction, runtime_types::xcm::v3::junction::Junction),
                    #[codec(
                        index = 7
                    )] X7(runtime_types::xcm::v3::junction::Junction, runtime_types::xcm::v3::junction::Junction, runtime_types::xcm::v3::junction::Junction, runtime_types::xcm::v3::junction::Junction, runtime_types::xcm::v3::junction::Junction, runtime_types::xcm::v3::junction::Junction, runtime_types::xcm::v3::junction::Junction),
                    #[codec(
                        index = 8
                    )] X8(runtime_types::xcm::v3::junction::Junction, runtime_types::xcm::v3::junction::Junction, runtime_types::xcm::v3::junction::Junction, runtime_types::xcm::v3::junction::Junction, runtime_types::xcm::v3::junction::Junction, runtime_types::xcm::v3::junction::Junction, runtime_types::xcm::v3::junction::Junction, runtime_types::xcm::v3::junction::Junction),
                }
            }
            pub mod multiasset {
                use super::runtime_types;
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub enum AssetId {
                    #[codec(
                        index = 0
                    )] Concrete(runtime_types::staging_xcm::v3::multilocation::MultiLocation),
                    #[codec(index = 1)] Abstract([::core::primitive::u8; 32usize]),
                }
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub enum AssetInstance {
                    #[codec(index = 0)] Undefined,
                    #[codec(
                        index = 1
                    )] Index(#[codec(compact)] ::core::primitive::u128),
                    #[codec(index = 2)] Array4([::core::primitive::u8; 4usize]),
                    #[codec(index = 3)] Array8([::core::primitive::u8; 8usize]),
                    #[codec(index = 4)] Array16([::core::primitive::u8; 16usize]),
                    #[codec(index = 5)] Array32([::core::primitive::u8; 32usize]),
                }
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub enum Fungibility {
                    #[codec(index = 0)] Fungible(#[codec(
                        compact
                    )] ::core::primitive::u128, ),
                    #[codec(
                        index = 1
                    )] NonFungible(runtime_types::xcm::v3::multiasset::AssetInstance),
                }
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub struct MultiAsset {
                    pub id: runtime_types::xcm::v3::multiasset::AssetId,
                    pub fun: runtime_types::xcm::v3::multiasset::Fungibility,
                }
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub enum MultiAssetFilter {
                    #[codec(
                        index = 0
                    )] Definite(runtime_types::xcm::v3::multiasset::MultiAssets),
                    #[codec(
                        index = 1
                    )] Wild(runtime_types::xcm::v3::multiasset::WildMultiAsset),
                }
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub struct MultiAssets(pub ::subxt::ext::subxt_core::alloc::vec::Vec<runtime_types::xcm::v3::multiasset::MultiAsset>);
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub enum WildFungibility {
                    #[codec(index = 0)] Fungible,
                    #[codec(
                        index = 1
                    )] NonFungible,
                }
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub enum WildMultiAsset {
                    #[codec(index = 0)] All,
                    #[codec(
                        index = 1
                    )] AllOf { id: runtime_types::xcm::v3::multiasset::AssetId, fun: runtime_types::xcm::v3::multiasset::WildFungibility },
                    #[codec(index = 2)] AllCounted(#[codec(compact)] ::core::primitive::u32),
                    #[codec(
                        index = 3
                    )] AllOfCounted {
                        id: runtime_types::xcm::v3::multiasset::AssetId,
                        fun: runtime_types::xcm::v3::multiasset::WildFungibility,
                        #[codec(
                            compact
                        )] count: ::core::primitive::u32,
                    },
                }
            }
            pub mod traits {
                use super::runtime_types;
                #[derive(
                    ::subxt::ext::subxt_core::ext::codec::Decode,
                    ::subxt::ext::subxt_core::ext::codec::Encode,
                    ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                    ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                    Debug
                )]
                #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
                )]
                #[decode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
                )]
                #[encode_as_type(
                    crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
                )]
                pub enum Error {
                    #[codec(index = 0)] Overflow,
                    #[codec(index = 1)] Unimplemented,
                    #[codec(index = 2)] UntrustedReserveLocation,
                    #[codec(index = 3)] UntrustedTeleportLocation,
                    #[codec(index = 4)] LocationFull,
                    #[codec(index = 5)] LocationNotInvertible,
                    #[codec(index = 6)] BadOrigin,
                    #[codec(index = 7)] InvalidLocation,
                    #[codec(index = 8)] AssetNotFound,
                    #[codec(index = 9)] FailedToTransactAsset,
                    #[codec(index = 10)] NotWithdrawable,
                    #[codec(index = 11)] LocationCannotHold,
                    #[codec(index = 12)] ExceedsMaxMessageSize,
                    #[codec(index = 13)] DestinationUnsupported,
                    #[codec(index = 14)] Transport,
                    #[codec(index = 15)] Unroutable,
                    #[codec(index = 16)] UnknownClaim,
                    #[codec(index = 17)] FailedToDecode,
                    #[codec(index = 18)] MaxWeightInvalid,
                    #[codec(index = 19)] NotHoldingFees,
                    #[codec(index = 20)] TooExpensive,
                    #[codec(index = 21)] Trap(::core::primitive::u64),
                    #[codec(index = 22)] ExpectationFalse,
                    #[codec(index = 23)] PalletNotFound,
                    #[codec(index = 24)] NameMismatch,
                    #[codec(index = 25)] VersionIncompatible,
                    #[codec(index = 26)] HoldingWouldOverflow,
                    #[codec(index = 27)] ExportError,
                    #[codec(index = 28)] ReanchorFailed,
                    #[codec(index = 29)] NoDeal,
                    #[codec(index = 30)] FeesNotMet,
                    #[codec(index = 31)] LockError,
                    #[codec(index = 32)] NoPermission,
                    #[codec(index = 33)] Unanchored,
                    #[codec(index = 34)] NotDepositable,
                    #[codec(index = 35)] UnhandledXcmVersion,
                    #[codec(
                        index = 36
                    )] WeightLimitReached(runtime_types::sp_weights::weight_v2::Weight),
                    #[codec(index = 37)] Barrier,
                    #[codec(index = 38)] WeightNotComputable,
                    #[codec(index = 39)] ExceedsStackLimit,
                }
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Instruction {
                #[codec(
                    index = 0
                )] WithdrawAsset(runtime_types::xcm::v3::multiasset::MultiAssets),
                #[codec(
                    index = 1
                )] ReserveAssetDeposited(runtime_types::xcm::v3::multiasset::MultiAssets),
                #[codec(
                    index = 2
                )] ReceiveTeleportedAsset(runtime_types::xcm::v3::multiasset::MultiAssets),
                #[codec(index = 3)] QueryResponse {
                    #[codec(
                        compact
                    )] query_id: ::core::primitive::u64,
                    response: runtime_types::xcm::v3::Response,
                    max_weight: runtime_types::sp_weights::weight_v2::Weight,
                    querier: ::core::option::Option<runtime_types::staging_xcm::v3::multilocation::MultiLocation>,
                },
                #[codec(
                    index = 4
                )] TransferAsset { assets: runtime_types::xcm::v3::multiasset::MultiAssets, beneficiary: runtime_types::staging_xcm::v3::multilocation::MultiLocation },
                #[codec(
                    index = 5
                )] TransferReserveAsset { assets: runtime_types::xcm::v3::multiasset::MultiAssets, dest: runtime_types::staging_xcm::v3::multilocation::MultiLocation, xcm: runtime_types::xcm::v3::Xcm },
                #[codec(
                    index = 6
                )] Transact { origin_kind: runtime_types::xcm::v3::OriginKind, require_weight_at_most: runtime_types::sp_weights::weight_v2::Weight, call: runtime_types::xcm::double_encoded::DoubleEncoded },
                #[codec(index = 7)] HrmpNewChannelOpenRequest {
                    #[codec(
                        compact
                    )] sender: ::core::primitive::u32,
                    #[codec(compact)] max_message_size: ::core::primitive::u32,
                    #[codec(compact)] max_capacity: ::core::primitive::u32,
                },
                #[codec(index = 8)] HrmpChannelAccepted {
                    #[codec(
                        compact
                    )] recipient: ::core::primitive::u32,
                },
                #[codec(index = 9)] HrmpChannelClosing {
                    #[codec(
                        compact
                    )] initiator: ::core::primitive::u32,
                    #[codec(compact)] sender: ::core::primitive::u32,
                    #[codec(compact)] recipient: ::core::primitive::u32,
                },
                #[codec(index = 10)] ClearOrigin,
                #[codec(
                    index = 11
                )] DescendOrigin(runtime_types::xcm::v3::junctions::Junctions),
                #[codec(index = 12)] ReportError(runtime_types::xcm::v3::QueryResponseInfo),
                #[codec(
                    index = 13
                )] DepositAsset { assets: runtime_types::xcm::v3::multiasset::MultiAssetFilter, beneficiary: runtime_types::staging_xcm::v3::multilocation::MultiLocation },
                #[codec(
                    index = 14
                )] DepositReserveAsset { assets: runtime_types::xcm::v3::multiasset::MultiAssetFilter, dest: runtime_types::staging_xcm::v3::multilocation::MultiLocation, xcm: runtime_types::xcm::v3::Xcm },
                #[codec(
                    index = 15
                )] ExchangeAsset { give: runtime_types::xcm::v3::multiasset::MultiAssetFilter, want: runtime_types::xcm::v3::multiasset::MultiAssets, maximal: ::core::primitive::bool },
                #[codec(
                    index = 16
                )] InitiateReserveWithdraw { assets: runtime_types::xcm::v3::multiasset::MultiAssetFilter, reserve: runtime_types::staging_xcm::v3::multilocation::MultiLocation, xcm: runtime_types::xcm::v3::Xcm },
                #[codec(
                    index = 17
                )] InitiateTeleport { assets: runtime_types::xcm::v3::multiasset::MultiAssetFilter, dest: runtime_types::staging_xcm::v3::multilocation::MultiLocation, xcm: runtime_types::xcm::v3::Xcm },
                #[codec(
                    index = 18
                )] ReportHolding { response_info: runtime_types::xcm::v3::QueryResponseInfo, assets: runtime_types::xcm::v3::multiasset::MultiAssetFilter },
                #[codec(
                    index = 19
                )] BuyExecution { fees: runtime_types::xcm::v3::multiasset::MultiAsset, weight_limit: runtime_types::xcm::v3::WeightLimit },
                #[codec(index = 20)] RefundSurplus,
                #[codec(index = 21)] SetErrorHandler(runtime_types::xcm::v3::Xcm),
                #[codec(index = 22)] SetAppendix(runtime_types::xcm::v3::Xcm),
                #[codec(index = 23)] ClearError,
                #[codec(
                    index = 24
                )] ClaimAsset { assets: runtime_types::xcm::v3::multiasset::MultiAssets, ticket: runtime_types::staging_xcm::v3::multilocation::MultiLocation },
                #[codec(index = 25)] Trap(#[codec(compact)] ::core::primitive::u64),
                #[codec(index = 26)] SubscribeVersion {
                    #[codec(
                        compact
                    )] query_id: ::core::primitive::u64,
                    max_response_weight: runtime_types::sp_weights::weight_v2::Weight,
                },
                #[codec(index = 27)] UnsubscribeVersion,
                #[codec(
                    index = 28
                )] BurnAsset(runtime_types::xcm::v3::multiasset::MultiAssets),
                #[codec(
                    index = 29
                )] ExpectAsset(runtime_types::xcm::v3::multiasset::MultiAssets),
                #[codec(
                    index = 30
                )] ExpectOrigin(::core::option::Option<runtime_types::staging_xcm::v3::multilocation::MultiLocation>),
                #[codec(
                    index = 31
                )] ExpectError(::core::option::Option<(::core::primitive::u32, runtime_types::xcm::v3::traits::Error,)>),
                #[codec(
                    index = 32
                )] ExpectTransactStatus(runtime_types::xcm::v3::MaybeErrorCode),
                #[codec(
                    index = 33
                )] QueryPallet { module_name: ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>, response_info: runtime_types::xcm::v3::QueryResponseInfo },
                #[codec(index = 34)] ExpectPallet {
                    #[codec(
                        compact
                    )] index: ::core::primitive::u32,
                    name: ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>,
                    module_name: ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>,
                    #[codec(compact)] crate_major: ::core::primitive::u32,
                    #[codec(compact)] min_crate_minor: ::core::primitive::u32,
                },
                #[codec(
                    index = 35
                )] ReportTransactStatus(runtime_types::xcm::v3::QueryResponseInfo),
                #[codec(index = 36)] ClearTransactStatus,
                #[codec(
                    index = 37
                )] UniversalOrigin(runtime_types::xcm::v3::junction::Junction),
                #[codec(
                    index = 38
                )] ExportMessage { network: runtime_types::xcm::v3::junction::NetworkId, destination: runtime_types::xcm::v3::junctions::Junctions, xcm: runtime_types::xcm::v3::Xcm },
                #[codec(
                    index = 39
                )] LockAsset { asset: runtime_types::xcm::v3::multiasset::MultiAsset, unlocker: runtime_types::staging_xcm::v3::multilocation::MultiLocation },
                #[codec(
                    index = 40
                )] UnlockAsset { asset: runtime_types::xcm::v3::multiasset::MultiAsset, target: runtime_types::staging_xcm::v3::multilocation::MultiLocation },
                #[codec(
                    index = 41
                )] NoteUnlockable { asset: runtime_types::xcm::v3::multiasset::MultiAsset, owner: runtime_types::staging_xcm::v3::multilocation::MultiLocation },
                #[codec(
                    index = 42
                )] RequestUnlock { asset: runtime_types::xcm::v3::multiasset::MultiAsset, locker: runtime_types::staging_xcm::v3::multilocation::MultiLocation },
                #[codec(index = 43)] SetFeesMode { jit_withdraw: ::core::primitive::bool },
                #[codec(index = 44)] SetTopic([::core::primitive::u8; 32usize]),
                #[codec(index = 45)] ClearTopic,
                #[codec(
                    index = 46
                )] AliasOrigin(runtime_types::staging_xcm::v3::multilocation::MultiLocation),
                #[codec(
                    index = 47
                )] UnpaidExecution { weight_limit: runtime_types::xcm::v3::WeightLimit, check_origin: ::core::option::Option<runtime_types::staging_xcm::v3::multilocation::MultiLocation> },
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum MaybeErrorCode {
                #[codec(index = 0)] Success,
                #[codec(
                    index = 1
                )] Error(runtime_types::bounded_collections::bounded_vec::BoundedVec<::core::primitive::u8>),
                #[codec(
                    index = 2
                )] TruncatedError(runtime_types::bounded_collections::bounded_vec::BoundedVec<::core::primitive::u8>),
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum OriginKind {
                #[codec(index = 0)] Native,
                #[codec(
                    index = 1
                )] SovereignAccount,
                #[codec(index = 2)] Superuser,
                #[codec(index = 3)] Xcm,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct PalletInfo {
                #[codec(compact)] pub index: ::core::primitive::u32,
                pub name: runtime_types::bounded_collections::bounded_vec::BoundedVec<::core::primitive::u8>,
                pub module_name: runtime_types::bounded_collections::bounded_vec::BoundedVec<::core::primitive::u8>,
                #[codec(compact)] pub major: ::core::primitive::u32,
                #[codec(compact)] pub minor: ::core::primitive::u32,
                #[codec(compact)] pub patch: ::core::primitive::u32,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct QueryResponseInfo {
                pub destination: runtime_types::staging_xcm::v3::multilocation::MultiLocation,
                #[codec(compact)] pub query_id: ::core::primitive::u64,
                pub max_weight: runtime_types::sp_weights::weight_v2::Weight,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Response {
                #[codec(index = 0)] Null,
                #[codec(
                    index = 1
                )] Assets(runtime_types::xcm::v3::multiasset::MultiAssets),
                #[codec(
                    index = 2
                )] ExecutionResult(::core::option::Option<(::core::primitive::u32, runtime_types::xcm::v3::traits::Error,)>),
                #[codec(index = 3)] Version(::core::primitive::u32),
                #[codec(
                    index = 4
                )] PalletsInfo(runtime_types::bounded_collections::bounded_vec::BoundedVec<runtime_types::xcm::v3::PalletInfo>),
                #[codec(index = 5)] DispatchResult(runtime_types::xcm::v3::MaybeErrorCode),
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum WeightLimit {
                #[codec(index = 0)] Unlimited,
                #[codec(
                    index = 1
                )] Limited(runtime_types::sp_weights::weight_v2::Weight),
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct Xcm(pub ::subxt::ext::subxt_core::alloc::vec::Vec<runtime_types::xcm::v3::Instruction>);
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub enum VersionedAssetId {
            #[codec(
                index = 3
            )] V3(runtime_types::xcm::v3::multiasset::AssetId),
            #[codec(index = 4)] V4(runtime_types::staging_xcm::v4::asset::AssetId),
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub enum VersionedAssets {
            #[codec(
                index = 1
            )] V2(runtime_types::xcm::v2::multiasset::MultiAssets),
            #[codec(index = 3)] V3(runtime_types::xcm::v3::multiasset::MultiAssets),
            #[codec(index = 4)] V4(runtime_types::staging_xcm::v4::asset::Assets),
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub enum VersionedLocation {
            #[codec(
                index = 1
            )] V2(runtime_types::xcm::v2::multilocation::MultiLocation),
            #[codec(
                index = 3
            )] V3(runtime_types::staging_xcm::v3::multilocation::MultiLocation),
            #[codec(index = 4)] V4(runtime_types::staging_xcm::v4::location::Location),
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub enum VersionedResponse {
            #[codec(
                index = 2
            )] V2(runtime_types::xcm::v2::Response),
            #[codec(index = 3)] V3(runtime_types::xcm::v3::Response),
            #[codec(index = 4)] V4(runtime_types::staging_xcm::v4::Response),
        }
        #[derive(
            ::subxt::ext::subxt_core::ext::codec::Decode,
            ::subxt::ext::subxt_core::ext::codec::Encode,
            ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
            ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
            Debug
        )]
        #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec)]
        #[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
        #[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
        pub enum VersionedXcm {
            #[codec(index = 2)] V2(runtime_types::xcm::v2::Xcm),
            #[codec(
                index = 3
            )] V3(runtime_types::xcm::v3::Xcm),
            #[codec(index = 4)] V4(runtime_types::staging_xcm::v4::Xcm),
        }
    }
    pub mod xcm_fee_payment_runtime_api {
        use super::runtime_types;
        pub mod dry_run {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct CallDryRunEffects<_0> {
                pub execution_result: ::core::result::Result<runtime_types::frame_support::dispatch::PostDispatchInfo, runtime_types::sp_runtime::DispatchErrorWithPostInfo<runtime_types::frame_support::dispatch::PostDispatchInfo>>,
                pub emitted_events: ::subxt::ext::subxt_core::alloc::vec::Vec<_0>,
                pub local_xcm: ::core::option::Option<runtime_types::xcm::VersionedXcm>,
                pub forwarded_xcms: ::subxt::ext::subxt_core::alloc::vec::Vec<(runtime_types::xcm::VersionedLocation, ::subxt::ext::subxt_core::alloc::vec::Vec<runtime_types::xcm::VersionedXcm>,)>,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Error {
                #[codec(index = 0)] Unimplemented,
                #[codec(
                    index = 1
                )] VersionedConversionFailed,
            }
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub struct XcmDryRunEffects<_0> {
                pub execution_result: runtime_types::staging_xcm::v4::traits::Outcome,
                pub emitted_events: ::subxt::ext::subxt_core::alloc::vec::Vec<_0>,
                pub forwarded_xcms: ::subxt::ext::subxt_core::alloc::vec::Vec<(runtime_types::xcm::VersionedLocation, ::subxt::ext::subxt_core::alloc::vec::Vec<runtime_types::xcm::VersionedXcm>,)>,
            }
        }
        pub mod fees {
            use super::runtime_types;
            #[derive(
                ::subxt::ext::subxt_core::ext::codec::Decode,
                ::subxt::ext::subxt_core::ext::codec::Encode,
                ::subxt::ext::subxt_core::ext::scale_decode::DecodeAsType,
                ::subxt::ext::subxt_core::ext::scale_encode::EncodeAsType,
                Debug
            )]
            #[codec( crate   =   ::   subxt   ::   ext   ::   subxt_core   ::   ext   ::   codec
            )]
            #[decode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
            )]
            #[encode_as_type(
                crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
            )]
            pub enum Error {
                #[codec(index = 0)] Unimplemented,
                #[codec(
                    index = 1
                )] VersionedConversionFailed,
                #[codec(index = 2)] WeightNotComputable,
                #[codec(index = 3)] UnhandledXcmVersion,
                #[codec(index = 4)] AssetNotFound,
                #[codec(index = 5)] Unroutable,
            }
        }
    }
}
