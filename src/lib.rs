//! # Role-based Access Control (RBAC) Pallet
//!
//! The RBAC Pallet implements role-based access control and permissions for Substrate extrinsic calls.
#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use frame_support::{
    dispatch::{DispatchInfo, PostDispatchInfo},
    traits::GetCallMetadata,
};
pub use pallet::*;
use scale_info::TypeInfo;
// use scale_info::TypeInfo;
use sp_runtime::{
    print,
    traits::{DispatchInfoOf, Dispatchable, SignedExtension},
    transaction_validity::{InvalidTransaction, TransactionValidity, TransactionValidityError},
    RuntimeDebug,
};
use sp_std::prelude::*;

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::{dispatch::DispatchResult, pallet_prelude::*};
    use frame_system::pallet_prelude::*;
    use sp_std::convert::TryInto;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// The Event type.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Origin for adding or removing a roles and permissions.
        type RbacAdminOrigin: EnsureOrigin<Self::RuntimeOrigin>;
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    // The pallet's storage items.
    #[pallet::storage]
    #[pallet::getter(fn super_admins)]
    pub type SuperAdmins<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, ()>;

    #[pallet::storage]
    #[pallet::getter(fn permissions)]
    pub type Permissions<T: Config> = StorageMap<_, Blake2_128Concat, (T::AccountId, Role), ()>;

    #[pallet::storage]
    #[pallet::getter(fn roles)]
    pub type Roles<T: Config> = StorageMap<_, Blake2_128Concat, Role, ()>;

    #[pallet::genesis_config]
    pub struct GenesisConfig<T: Config> {
        pub super_admins: Vec<T::AccountId>,
    }

    #[cfg(feature = "std")]
    impl<T: Config> Default for GenesisConfig<T> {
        fn default() -> Self {
            Self {
                super_admins: Vec::new(),
            }
        }
    }

    // The build of genesis for the pallet.
    #[pallet::genesis_build]
    impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
        fn build(&self) {
            for admin in &self.super_admins {
                <SuperAdmins<T>>::insert(admin, ());
            }
        }
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        AccessRevoked(T::AccountId, Vec<u8>),
        AccessGranted(T::AccountId, Vec<u8>),
        SuperAdminAdded(T::AccountId),
    }

    #[derive(PartialEq)]
    #[pallet::error]
    pub enum Error<T> {
        AccessDenied,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::weight(0)]
        pub fn create_role(
            origin: OriginFor<T>,
            pallet_name: Vec<u8>,
            permission: Permission,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            let role = Role {
                pallet: pallet_name,
                permission,
            };

            Roles::<T>::insert(role, ());

            Ok(())
        }

        #[pallet::weight(0)]
        pub fn assign_role(
            origin: OriginFor<T>,
            account_id: T::AccountId,
            role: Role,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            if Self::verify_manage_access(who, role.pallet.clone()) {
                Self::deposit_event(Event::AccessGranted(
                    account_id.clone(),
                    role.pallet.clone(),
                ));
                <Permissions<T>>::insert((account_id, role), ());
            } else {
                return Err(Error::<T>::AccessDenied.into());
            }

            Ok(())
        }

        #[pallet::weight(0)]
        pub fn revoke_access(
            origin: OriginFor<T>,
            account_id: T::AccountId,
            role: Role,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            if Self::verify_manage_access(who, role.pallet.clone()) {
                Self::deposit_event(Event::AccessRevoked(
                    account_id.clone(),
                    role.pallet.clone(),
                ));
                <Permissions<T>>::remove((account_id, role));
            } else {
                return Err(Error::<T>::AccessDenied.into());
            }

            Ok(())
        }

        /// Add a new Super Admin.
        /// Super Admins have access to execute and manage all pallets.
        ///
        /// Only _root_ can add a Super Admin.
        #[pallet::weight(0)]
        pub fn add_super_admin(origin: OriginFor<T>, account_id: T::AccountId) -> DispatchResult {
            T::RbacAdminOrigin::ensure_origin(origin)?;
            <SuperAdmins<T>>::insert(&account_id, ());
            Self::deposit_event(Event::SuperAdminAdded(account_id));
            Ok(())
        }
    }
}

#[derive(PartialEq, Eq, Clone, RuntimeDebug, Encode, Decode, TypeInfo)]
pub enum Permission {
    Execute = 1,
    Manage = 2,
}

impl Default for Permission {
    fn default() -> Self {
        Permission::Execute
    }
}

#[derive(PartialEq, Eq, Clone, RuntimeDebug, Encode, Decode, TypeInfo)]
pub struct Role {
    pallet: Vec<u8>, // Update to be a BoundedVec
    permission: Permission,
}

impl<T: Config> Pallet<T> {
    pub fn verify_execute_access(account_id: T::AccountId, pallet: Vec<u8>) -> bool {
        let role = Role {
            pallet,
            permission: Permission::Execute,
        };

        if <Roles<T>>::contains_key(&role) && <Permissions<T>>::contains_key((account_id, role)) {
            return true;
        }

        false
    }

    fn verify_manage_access(account_id: T::AccountId, pallet: Vec<u8>) -> bool {
        let role = Role {
            pallet,
            permission: Permission::Manage,
        };

        if <Roles<T>>::contains_key(&role) && <Permissions<T>>::contains_key((account_id, role)) {
            return true;
        }

        false
    }
}

/// The following section implements the `SignedExtension` trait
/// for the `Authorize` type.
/// `SignedExtension` is being used here to filter out the not authorized accounts
/// when they try to send extrinsics to the runtime.
/// Inside the `validate` function of the `SignedExtension` trait,
/// we check if the sender (origin) of the extrinsic has the execute permission or not.
/// The validation happens at the transaction queue level,
///  and the extrinsics are filtered out before they hit the pallet logic.

/// The `Authorize` struct.
#[derive(Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
#[scale_info(skip_type_params(T))]
pub struct Authorize<T: Config + Send + Sync>(sp_std::marker::PhantomData<T>);

/// Debug impl for the `Authorize` struct.
impl<T: Config + Send + Sync> sp_std::fmt::Debug for Authorize<T> {
    #[cfg(feature = "std")]
    fn fmt(&self, f: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
        write!(f, "Authorize")
    }

    #[cfg(not(feature = "std"))]
    fn fmt(&self, _: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
        Ok(())
    }
}

impl<T: Config + Send + Sync> Authorize<T> {
    pub fn new() -> Self {
        Self(sp_std::marker::PhantomData)
    }
}

impl<T: Config + Send + Sync> SignedExtension for Authorize<T>
where
    T::RuntimeCall:
        Dispatchable<Info = DispatchInfo, PostInfo = PostDispatchInfo> + GetCallMetadata,
{
    type AccountId = T::AccountId;
    type Call = T::RuntimeCall;
    type AdditionalSigned = ();
    type Pre = ();
    const IDENTIFIER: &'static str = "Authorize";

    fn additional_signed(&self) -> sp_std::result::Result<(), TransactionValidityError> {
        Ok(())
    }

    fn validate(
        &self,
        who: &Self::AccountId,
        call: &Self::Call,
        _info: &DispatchInfoOf<Self::Call>,
        _len: usize,
    ) -> TransactionValidity {
        let md = call.get_call_metadata();

        if <SuperAdmins<T>>::contains_key(who.clone()) {
            print("Access Granted!");
            Ok(Default::default())
        } else if <Pallet<T>>::verify_execute_access(
            who.clone(),
            md.pallet_name.as_bytes().to_vec(),
        ) {
            print("Access Granted!");
            Ok(Default::default())
        } else {
            print("Access Denied!");
            Err(InvalidTransaction::Call.into())
        }
    }

    fn pre_dispatch(
        self,
        who: &Self::AccountId,
        call: &Self::Call,
        info: &DispatchInfoOf<Self::Call>,
        len: usize,
    ) -> Result<Self::Pre, TransactionValidityError> {
        todo!()
    }
}
