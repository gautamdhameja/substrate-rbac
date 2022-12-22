//! # Role-based Access Control (RBAC) Pallet
//!
//! The RBAC Pallet implements role-based access control and permissions for Substrate extrinsic calls.
#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

use codec::{Decode, Encode};

#[cfg(feature = "std")]
use frame_support::serde::{Deserialize, Serialize};
use frame_support::{
    dispatch::{DispatchInfo, PostDispatchInfo},
    traits::GetCallMetadata,
};

use scale_info::TypeInfo;
// use scale_info::TypeInfo;
use sp_runtime::{
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
    pub type Permissions<T: Config> = StorageNMap<
        _,
        (
            storage::Key<Blake2_128Concat, T::AccountId>,
            storage::Key<Blake2_128Concat, AccessControl>,
        ),
        (),
    >;

    // Store access controls for Executing and managing a specific extrinsic on a pallet.
    #[pallet::storage]
    #[pallet::getter(fn roles)]
    pub type AccessControls<T: Config> = StorageMap<_, Blake2_128Concat, AccessControl, ()>;

    #[pallet::genesis_config]
    pub struct GenesisConfig<T: Config> {
        pub super_admins: Vec<T::AccountId>,
        pub permissions: Vec<(T::AccountId, AccessControl)>,
        pub access_controls: Vec<AccessControl>,
    }

    #[cfg(feature = "std")]
    impl<T: Config> Default for GenesisConfig<T> {
        fn default() -> Self {
            Self {
                super_admins: Vec::new(),
                permissions: Vec::new(),
                access_controls: Vec::new(),
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

            for permission in &self.permissions {
                <Permissions<T>>::insert(permission, ());
            }

            for role in &self.access_controls {
                <AccessControls<T>>::insert(role, ());
            }
        }
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        AccessRevoked(T::AccountId, Vec<u8>, Vec<u8>),
        AccessGranted(T::AccountId, Vec<u8>, Vec<u8>),
        SuperAdminAdded(T::AccountId),
    }

    #[derive(PartialEq)]
    #[pallet::error]
    pub enum Error<T> {
        AccessDenied,
        InvalidNameSize,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::weight(0)]
        pub fn create_role(
            origin: OriginFor<T>,
            pallet_name: Vec<u8>,
            pallet_function: Vec<u8>,
            permission: Permission,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            let role = AccessControl {
                pallet: pallet_name,
                function: pallet_function,
                permission,
            };

            AccessControls::<T>::insert(role, ());

            Ok(())
        }

        #[pallet::weight(0)]
        pub fn assign_role(
            origin: OriginFor<T>,
            account_id: T::AccountId,
            role: AccessControl,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            match Self::verify_manage_access(who, role.pallet.clone(), role.function.clone()) {
                Ok(_) => {
                    Self::deposit_event(Event::AccessGranted(
                        account_id.clone(),
                        role.pallet.clone().into(),
                        role.function.clone().into(),
                    ));

                    <Permissions<T>>::insert((account_id, role), ()); // access_permission);
                    return Ok(());
                }
                Err(e) => {
                    log::error!("assign role failed: {:?}", e);

                    return Err(Error::<T>::AccessDenied.into());
                }
            }
        }

        #[pallet::weight(0)]
        pub fn revoke_access(
            origin: OriginFor<T>,
            account_id: T::AccountId,
            role: AccessControl,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            // Ok(())

            match Self::verify_manage_access(who, role.pallet.clone(), role.function.clone()) {
                Ok(_) => {
                    Self::deposit_event(Event::AccessRevoked(
                        account_id.clone(),
                        role.pallet.clone().into(),
                        role.function.clone().into(),
                    ));
                    <Permissions<T>>::remove((account_id, role));
                    return Ok(());
                }
                Err(e) => {
                    log::error!("revoke role failed: {:?}", e);
                    return Err(Error::<T>::AccessDenied.into());
                }
            }
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
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
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
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct AccessControl {
    pub pallet: Vec<u8>,
    pub function: Vec<u8>,
    pub permission: Permission,
}

impl<T: Config> Pallet<T> {
    /** Verify that account can execute a function on a pallet.
     All Pallet functions works as normal when it does not have a Role created for it.
     Access is denied when then pallet and function has a role, and the account does not have permission to execute
    */
    pub fn verify_execute_access(
        account_id: T::AccountId,
        pallet: Vec<u8>,
        function: Vec<u8>,
    ) -> Result<(), Error<T>> {
        let role = AccessControl {
            pallet,
            function,
            permission: Permission::Execute,
        };

        if <AccessControls<T>>::contains_key(&role) {
            if <Permissions<T>>::contains_key((account_id, role)) {
                return Ok(());
            } else {
                return Err(Error::<T>::AccessDenied.into());
            }
        }

        Ok(())
    }

    /** Verify the ability to manage the access to a pallets extrinsics.
     The user must either be an Admin or have the Manage permission for a pallet and function.
    */
    fn verify_manage_access(
        account_id: T::AccountId,
        pallet: Vec<u8>,
        function: Vec<u8>,
    ) -> Result<(), Error<T>> {
        let role = AccessControl {
            pallet,
            function,
            permission: Permission::Manage,
        };

        if <AccessControls<T>>::contains_key(&role)
            && <Permissions<T>>::contains_key((account_id, role))
        {
            return Ok(());
        }

        Err(Error::<T>::AccessDenied)
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

    /** Used to drop the transaction at the transaction pool level and prevents a transaction from being gossiped */
    fn validate(
        &self,
        who: &Self::AccountId,
        call: &Self::Call,
        _info: &DispatchInfoOf<Self::Call>,
        _len: usize,
    ) -> TransactionValidity {
        let md = call.get_call_metadata();
        if <SuperAdmins<T>>::contains_key(who.clone()) {
            // log::info!("Access Granted!");
            return Ok(Default::default());
        }

        match <Pallet<T>>::verify_execute_access(
            who.clone(),
            md.pallet_name.as_bytes().to_vec(),
            md.function_name.as_bytes().to_vec(),
        ) {
            Ok(_) => {
                // log::info!("Access Granted!");
                Ok(Default::default())
            }
            Err(e) => {
                log::error!("{:?}", e);
                log::info!("Access Denied! who: {:?}", who);
                Err(InvalidTransaction::Call.into())
            }
        }
    }

    /** Use to hook in before the transaction runs */
    fn pre_dispatch(
        self,
        who: &Self::AccountId,
        call: &Self::Call,
        info: &DispatchInfoOf<Self::Call>,
        len: usize,
    ) -> Result<Self::Pre, TransactionValidityError> {
        match self.validate(who, call, info, len) {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }
}
