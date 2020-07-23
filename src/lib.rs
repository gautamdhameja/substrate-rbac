//! # Role-based Access Control (RBAC) Pallet
//!
//! The RBAC Pallet implements role-based access control and permissions for Substrate extrinsic calls.

#![cfg_attr(not(feature = "std"), no_std)]

use sp_std::prelude::*;
use codec::{Decode, Encode};
use sp_std::marker::PhantomData;
use sp_std::fmt::Debug;
use frame_support::{
    decl_event, decl_storage, decl_module, decl_error,
    dispatch,
    weights::DispatchInfo,
    traits::GetCallMetadata
};
use system::{self as system, ensure_root, ensure_signed};
use sp_runtime::{
    print, RuntimeDebug,
    transaction_validity::{
		ValidTransaction, TransactionValidityError,
        InvalidTransaction, TransactionValidity,
        TransactionPriority, TransactionLongevity,
	},
    traits::{SignedExtension, DispatchInfoOf, Dispatchable}
};

pub trait Trait: system::Trait {
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;    
}

#[derive(PartialEq, Eq, Clone, RuntimeDebug, Encode, Decode)]
pub enum Permission {
    Execute = 1,
    Manage = 2
}

impl Default for Permission {
	fn default() -> Self {
        Permission::Execute
    }
}

#[derive(PartialEq, Eq, Clone, RuntimeDebug, Encode, Decode)]
pub struct Role {
    pallet: Vec<u8>,
    permission: Permission
}

decl_storage! {
    trait Store for Module<T: Trait> as RBAC {
        pub SuperAdmins get(fn super_admins): map hasher(blake2_128_concat) T::AccountId => ();
        pub Permissions get(fn permissions): map hasher(blake2_128_concat) (T::AccountId, Role) => ();
        pub Roles get(fn roles): map hasher(blake2_128_concat) Role => ();
    }
    add_extra_genesis {
		config(super_admins): Vec<T::AccountId>;
		build(|config| {
			for admin in config.super_admins.iter() {
                <SuperAdmins<T>>::insert(admin, ());
			}
		})
	}
}

decl_error! {
	pub enum Error for Module<T: Trait> {
		AccessDenied
	}
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        type Error = Error<T>;
        fn deposit_event() = default;

        #[weight = 0]
        pub fn create_role(origin, pallet_name: Vec<u8>, permission: Permission) -> dispatch::DispatchResult {
            ensure_signed(origin)?;

            let role = Role {
                pallet: pallet_name,
                permission: Permission::Execute
            };

            Roles::insert(role, ());
            
            Ok(())
        }
        
        #[weight = 0]
        pub fn assign_role(origin, account_id: T::AccountId, role: Role) -> dispatch::DispatchResult {
            let who = ensure_signed(origin)?;

            if Self::verify_manage_access(who, role.pallet.clone()) {
                Self::deposit_event(RawEvent::AccessGranted(account_id.clone(), role.pallet.clone()));
                <Permissions<T>>::insert((account_id, role), ());
            } else {
                return Err(Error::<T>::AccessDenied.into())
            }
            
            Ok(())
        }

        #[weight = 0]
        pub fn revoke_access(origin, account_id: T::AccountId, role: Role) -> dispatch::DispatchResult {
            let who = ensure_signed(origin)?;

            if Self::verify_manage_access(who, role.pallet.clone()) {
                Self::deposit_event(RawEvent::AccessRevoked(account_id.clone(), role.pallet.clone()));
                <Permissions<T>>::remove((account_id, role));
            } else {
                return Err(Error::<T>::AccessDenied.into())
            }
            
            Ok(())
        }

        /// Add a new Super Admin.
        /// Super Admins have access to execute and manage all pallets.
        /// 
        /// Only _root_ can add a Super Admin.
        #[weight = 0]
        pub fn add_super_admin(origin, account_id: T::AccountId) -> dispatch::DispatchResult {
            ensure_root(origin)?;
            <SuperAdmins<T>>::insert(&account_id, ());
            Self::deposit_event(RawEvent::SuperAdminAdded(account_id));
            Ok(())
        }
    }
}

decl_event!(
    pub enum Event<T>
    where
        AccountId = <T as system::Trait>::AccountId,
    {
        AccessRevoked(AccountId, Vec<u8>),
        AccessGranted(AccountId, Vec<u8>),
        SuperAdminAdded(AccountId),
    }
);


impl<T: Trait> Module<T> {
    pub fn verify_execute_access(account_id: T::AccountId, pallet: Vec<u8>) -> bool {
        let role = Role {
            pallet,
            permission: Permission::Execute
        };

        if Roles::contains_key(&role) && <Permissions<T>>::contains_key((account_id, role)) {
            return true;
        }

        false
    }

    fn verify_manage_access(account_id: T::AccountId, pallet: Vec<u8>) -> bool {
        let role = Role {
            pallet,
            permission: Permission::Manage
        };

        if Roles::contains_key(&role) && <Permissions<T>>::contains_key((account_id, role)) {
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
#[derive(Encode, Decode, Clone, Eq, PartialEq)]
pub struct Authorize<T: Trait + Send + Sync>(PhantomData<T>);

/// Debug impl for the `Authorize` struct.
impl<T: Trait + Send + Sync> Debug for Authorize<T> {
	#[cfg(feature = "std")]
	fn fmt(&self, f: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
		write!(f, "Authorize")
	}

	#[cfg(not(feature = "std"))]
	fn fmt(&self, _: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
		Ok(())
	}
}

impl<T: Trait + Send + Sync> SignedExtension for Authorize<T> where 
    T::Call: Dispatchable<Info=DispatchInfo> + GetCallMetadata {
    type AccountId = T::AccountId;
	type Call = T::Call;
	type AdditionalSigned = ();
	type Pre = ();
	const IDENTIFIER: &'static str = "Authorize";

    fn additional_signed(&self) -> sp_std::result::Result<(), TransactionValidityError> { Ok(()) }

    fn validate(
        &self,
		who: &Self::AccountId,
		call: &Self::Call,
		info: &DispatchInfoOf<Self::Call>,
		_len: usize,
    ) -> TransactionValidity {
        let md = call.get_call_metadata();

        if <SuperAdmins<T>>::contains_key(who.clone()) {
            print("Access Granted!");
            Ok(ValidTransaction {
                priority: info.weight as TransactionPriority,
                longevity: TransactionLongevity::max_value(),
                propagate: true,
                ..Default::default()
            })
        } else if <Module<T>>::verify_execute_access(who.clone(), md.pallet_name.as_bytes().to_vec()) {
            print("Access Granted!");
            Ok(ValidTransaction {
                priority: info.weight as TransactionPriority,
                longevity: TransactionLongevity::max_value(),
                propagate: true,
                ..Default::default()
            })
        }
        else {
            print("Access Denied!");
            Err(InvalidTransaction::Call.into())
        }
    }
}
