//! # Access Control Pallet
//!
//! Implements Access controls for allowing specific addresses to sign extrinsics and permissions for assigning access.
#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;
pub mod traits;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

use codec::{Decode, Encode};

#[cfg(feature = "std")]
use frame_support::serde::{Deserialize, Serialize};
use frame_support::{
    dispatch::{DispatchInfo, PostDispatchInfo},
    traits::GetCallMetadata,
};

use scale_info::TypeInfo;
use sp_runtime::{
    traits::{DispatchInfoOf, Dispatchable, SignedExtension},
    transaction_validity::{InvalidTransaction, TransactionValidity, TransactionValidityError},
    RuntimeDebug,
};
use sp_std::prelude::*;
use traits::{TraitError, VerifyAccess};

#[derive(PartialEq, Eq, Clone, RuntimeDebug, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub enum Permission {
    Execute,
    Manage,
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
    pub extrinsic: Vec<u8>,
    pub permission: Permission,
}

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::{
        dispatch::DispatchResult,
        pallet_prelude::{OptionQuery, *},
    };
    use frame_system::pallet_prelude::*;
    use sp_std::convert::TryInto;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// The Event type.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Origin for adding or removing a access_controls and permissions.
        type AdminOrigin: EnsureOrigin<Self::RuntimeOrigin>;
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    /** Admins who manage the assignment of access */
    #[pallet::storage]
    #[pallet::getter(fn admins)]
    pub type Admins<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, ()>;

    /** Store access controls for Executing and managing a specific extrinsic on a pallet. */
    #[pallet::storage]
    #[pallet::getter(fn access_controls)]
    pub type AccessControls<T: Config> =
        StorageMap<_, Blake2_128Concat, AccessControl, Vec<T::AccountId>, OptionQuery>;

    #[pallet::genesis_config]
    pub struct GenesisConfig<T: Config> {
        pub admins: Vec<T::AccountId>,
        pub access_controls: Vec<(AccessControl, Vec<T::AccountId>)>,
    }

    #[cfg(feature = "std")]
    impl<T: Config> Default for GenesisConfig<T> {
        fn default() -> Self {
            Self {
                admins: Vec::new(),
                access_controls: Vec::new(),
            }
        }
    }

    // The build of genesis for the pallet.
    #[pallet::genesis_build]
    impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
        fn build(&self) {
            for admin in &self.admins {
                <Admins<T>>::insert(admin, ());
            }

            for access_control in &self.access_controls {
                <AccessControls<T>>::insert(access_control.0.clone(), access_control.1.clone());
            }
        }
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        AccessRevoked(T::AccountId, Vec<u8>, Vec<u8>),
        AccessGranted(T::AccountId, Vec<u8>, Vec<u8>),
        AdminAdded(T::AccountId),
        AdminRevoked(T::AccountId),
    }

    #[derive(PartialEq)]
    #[pallet::error]
    pub enum Error<T> {
        AccessDenied,
        AccessControlNotFound,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /** Create Access Control for a specific extrinsic on a pallet.
            The caller must have permissions to update the c
            pallet_name: Vec<u8> | "PalletTemplate"
            pallet_extrinsic: Vec<u8> | "do_something"
            permission: Permission | `Execute` or `Manage`
        */
        #[pallet::weight(0)]
        pub fn create_access_control(
            origin: OriginFor<T>,
            pallet_name: Vec<u8>,
            pallet_extrinsic: Vec<u8>,
            permission: Permission,
        ) -> DispatchResult {
            // Check permissions
            let signer = ensure_signed(origin.clone())?;

            match Self::verify_execute_access(
                signer,
                "AccessControl".as_bytes().to_vec(),
                "create_access_control".as_bytes().to_vec(),
                Some(true),
            ) {
                Ok(()) => {
                    log::info!("Successfully verified access");
                }
                Err(_e) => return Err(Error::<T>::AccessDenied.into()),
            }

            let access_control = AccessControl {
                pallet: pallet_name,
                extrinsic: pallet_extrinsic,
                permission,
            };

            let accounts: Vec<T::AccountId> = Vec::new();
            AccessControls::<T>::insert(access_control, accounts);

            Ok(())
        }

        #[pallet::weight(0)]
        pub fn assign_access_control(
            origin: OriginFor<T>,
            account_id: T::AccountId,
            access_control: AccessControl,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            match Self::verify_manage_access(
                who,
                access_control.pallet.clone(),
                access_control.extrinsic.clone(),
            ) {
                Ok(_) => {
                    Self::deposit_event(Event::AccessGranted(
                        account_id.clone(),
                        access_control.pallet.clone().into(),
                        access_control.extrinsic.clone().into(),
                    ));

                    match AccessControls::<T>::get(access_control.clone()) {
                        Some(mut accounts) => {
                            log::info!("Accounts: {:?}", accounts);
                            accounts.push(account_id.clone());
                            AccessControls::<T>::insert(access_control.clone(), accounts);
                        }
                        None => return Err(Error::<T>::AccessControlNotFound.into()),
                    }

                    return Ok(());
                }
                Err(e) => {
                    log::error!("assign access_control failed: {:?}", e);

                    return Err(e.into());
                }
            }
        }

        #[pallet::weight(0)]
        pub fn revoke_access(
            origin: OriginFor<T>,
            account_id: T::AccountId,
            access_control: AccessControl,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            match Self::verify_manage_access(
                who,
                access_control.pallet.clone(),
                access_control.extrinsic.clone(),
            ) {
                Ok(_) => {
                    Self::deposit_event(Event::AccessRevoked(
                        account_id.clone(),
                        access_control.pallet.clone().into(),
                        access_control.extrinsic.clone().into(),
                    ));

                    match AccessControls::<T>::get(access_control.clone()) {
                        Some(mut accounts) => {
                            log::info!("Accounts: {:?}", accounts);
                            accounts.retain(|stored_account| stored_account != &account_id);
                        }
                        None => {
                            return Err(Error::<T>::AccessControlNotFound.into());
                        }
                    }

                    return Ok(());
                }
                Err(e) => {
                    log::error!("revoke access_control failed: {:?}", e);
                    return Err(e.into());
                }
            }
        }

        /// Add a new Super Admin.
        /// Admins have access to execute and manage all pallets.
        ///
        /// Only _root_ can add a Admin.
        #[pallet::weight(0)]
        pub fn add_super_admin(origin: OriginFor<T>, account_id: T::AccountId) -> DispatchResult {
            T::AdminOrigin::ensure_origin(origin)?;

            <Admins<T>>::insert(&account_id, ());
            Self::deposit_event(Event::AdminAdded(account_id));
            Ok(())
        }

        #[pallet::weight(0)]
        pub fn revoke_super_admin(
            origin: OriginFor<T>,
            account_id: T::AccountId,
        ) -> DispatchResult {
            T::AdminOrigin::ensure_origin(origin)?;

            <Admins<T>>::remove(&account_id);
            Self::deposit_event(Event::AdminRevoked(account_id));
            Ok(())
        }
    }
}

impl<T: Config> Pallet<T> {
    /** Verify that account can execute an extrinsic on a pallet.
     All Pallet extrinsics work as normal when it does not have a access_control created for it.
     Access is denied when then a pallet and an extrinsic has a access_control, and the account does not have permission to execute.
    */
    pub fn verify_execute_access(
        account_id: T::AccountId,
        pallet: Vec<u8>,
        extrinsic: Vec<u8>,
        requires_access_control: Option<bool>,
    ) -> Result<(), Error<T>> {
        let access_control = AccessControl {
            pallet,
            extrinsic,
            permission: Permission::Execute,
        };

        Self::verify_access(account_id, access_control, requires_access_control)
    }

    /** Verify the ability to manage the access to a pallets extrinsics.
     The user must either be an Admin or have the Manage permission for a pallet and extrinsic.
    */
    pub fn verify_manage_access(
        account_id: T::AccountId,
        pallet: Vec<u8>,
        extrinsic: Vec<u8>,
    ) -> Result<(), Error<T>> {
        let access_control = AccessControl {
            pallet,
            extrinsic,
            permission: Permission::Manage,
        };

        Self::verify_access(account_id, access_control, None)
    }

    /** Private helper method for access authentication */
    fn verify_access(
        account_id: T::AccountId,
        access_control: AccessControl,
        requires_access_control: Option<bool>,
    ) -> Result<(), Error<T>> {
        match <AccessControls<T>>::get(&access_control) {
            Some(accounts) => {
                if accounts.contains(&account_id) {
                    return Ok(());
                } else {
                    return Err(Error::<T>::AccessDenied.into());
                }
            }
            None => {
                if requires_access_control.unwrap_or(false) {
                    return Err(Error::<T>::AccessDenied.into());
                } else {
                    return Ok(());
                }
            }
        }
    }
}

impl<T: Config> VerifyAccess<T::AccountId> for Pallet<T> {
    /** Expose the verify_execute_access to other pallets
    When using the trait if the AccessControl is not present the verification will fail
    */
    fn verify_execute_access(
        account_id: T::AccountId,
        pallet: Vec<u8>,
        extrinsic: Vec<u8>,
    ) -> Result<(), TraitError> {
        match Self::verify_execute_access(account_id, pallet, extrinsic, Some(true)) {
            Ok(()) => Ok(()),
            Err(_e) => Err(TraitError::AccessDenied),
        }
    }
}

/// The following section implements the `SignedExtension` trait
/// for the `Authorize` type.
/// `SignedExtension` is being used here to filter out the not authorized accounts
/// when they try to send extrinsics to the runtime.
/// Inside the `validate` extrinsic of the `SignedExtension` trait,
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
        let call_metadata = call.get_call_metadata();
        if <Admins<T>>::contains_key(who.clone()) {
            return Ok(Default::default());
        }

        match <Pallet<T>>::verify_execute_access(
            who.clone(),
            call_metadata.pallet_name.as_bytes().to_vec(),
            call_metadata.function_name.as_bytes().to_vec(),
            None,
        ) {
            Ok(_) => Ok(Default::default()),
            Err(e) => {
                log::error!("{:?}! who: {:?}", e, who);
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
