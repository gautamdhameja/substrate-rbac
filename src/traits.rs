use crate::Vec;

pub enum TraitError {
    AccessDenied,
}

pub trait VerifyAccess<AccountId> {
    /** Verify that account can execute a function on a pallet.
     All Pallet functions works as normal when it does not have a access_control created for it.
     Access is denied when then pallet and function has a access_control, and the account does not have permission to execute.
     Additionally when using the trait, if the pallet extrinsic is not found access will be denied.
    */
    fn verify_execute_access(
        account_id: AccountId,
        pallet: Vec<u8>,
        function: Vec<u8>,
    ) -> Result<(), TraitError>;
}
