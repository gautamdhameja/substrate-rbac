use crate::{self as access_control};
use frame_support::traits::{ConstU16, ConstU64, GenesisBuild};
use frame_system as system;
use sp_core::{sr25519::Signature, Pair, H256};
use sp_runtime::{
    testing::Header,
    traits::{BlakeTwo256, IdentifyAccount, IdentityLookup, Verify},
};
use sp_std::convert::{TryFrom, TryInto};
use system::EnsureRoot;
use test_context::{futures::sink::With, TestContext};

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;

// Configure a mock runtime to test the pallet.
frame_support::construct_runtime!(
    pub enum Test where
        Block = Block,
        NodeBlock = Block,
        UncheckedExtrinsic = UncheckedExtrinsic,
    {
        System: frame_system,
        AccessControl: access_control,
    }
);

impl system::Config for Test {
    type BaseCallFilter = frame_support::traits::Everything;
    type BlockWeights = ();
    type BlockLength = ();
    type DbWeight = ();
    type RuntimeOrigin = RuntimeOrigin;
    type RuntimeCall = RuntimeCall;
    type Index = u64;
    type BlockNumber = u64;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = sp_core::sr25519::Public;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Header = Header;
    type RuntimeEvent = RuntimeEvent;
    type BlockHashCount = ConstU64<250>;
    type Version = ();
    type PalletInfo = PalletInfo;
    type AccountData = ();
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = ConstU16<42>;
    type OnSetCode = ();
    type MaxConsumers = frame_support::traits::ConstU32<16>;
}

pub type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;

impl access_control::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type AdminOrigin = EnsureRoot<AccountId>;
}

pub struct WithAccessControlContext {
    pub admins: Vec<AccountId>,
    pub access_controls: Vec<(access_control::AccessControl, Vec<AccountId>)>,
}

impl TestContext for WithAccessControlContext {
    fn setup() -> Self {
        let admin_account = new_account();
        let execute_access_control = access_control::AccessControl {
            pallet: pallet_name(),
            extrinsic: create_access_control(),
            permission: access_control::Permission::Execute,
        };
        let manage_access_control = access_control::AccessControl {
            pallet: pallet_name(),
            extrinsic: create_access_control(),
            permission: access_control::Permission::Manage,
        };

        WithAccessControlContext {
            admins: vec![admin_account],
            access_controls: vec![
                (execute_access_control, vec![admin_account]),
                (manage_access_control, vec![admin_account]),
            ],
        }
    }
}

impl WithAccessControlContext {
    pub fn admin_signer(self: &Self) -> RuntimeOrigin {
        RuntimeOrigin::signed(*self.admins.first().clone().unwrap())
    }
}

pub fn pallet_name() -> Vec<u8> {
    "AccessControl".as_bytes().to_vec()
}

pub fn create_access_control() -> Vec<u8> {
    "create_access_control".as_bytes().to_vec()
}

pub fn fake_extrinsic() -> Vec<u8> {
    "fake_extrinsic".as_bytes().to_vec()
}

pub fn new_account() -> sp_core::sr25519::Public {
    let key_pair = sp_core::sr25519::Pair::generate_with_phrase(None);
    key_pair.0.public()
}

// Build genesis storage according to the mock runtime.
pub fn new_test_ext(access_controls: &mut WithAccessControlContext) -> sp_io::TestExternalities {
    let mut t = frame_system::GenesisConfig::default()
        .build_storage::<Test>()
        .unwrap();
    let genesis = access_control::GenesisConfig::<Test> {
        admins: access_controls.admins.clone(),
        access_controls: access_controls.access_controls.clone(),
    };
    genesis.assimilate_storage(&mut t).unwrap();
    t.into()
}
