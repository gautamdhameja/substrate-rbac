#![cfg(feature = "runtime-benchmarks")]

use super::*;
use crate::Pallet as AccessControlPallet;
use crate::{self as access_control};
use frame_benchmarking::{benchmarks, whitelisted_caller};
use frame_system::RawOrigin;

pub fn pallet_name() -> Vec<u8> {
    "AccessControl".as_bytes().to_vec()
}

pub fn fake_extrinsic() -> Vec<u8> {
    "fake_extrinsic".as_bytes().to_vec()
}

// TODO: These need to run inside a runtime, so they wont work atm...
benchmarks! {
  create_access_control_weight {
    let caller: T::AccountId = whitelisted_caller();
    let access_control = access_control::AccessControl {
      pallet: pallet_name(),
      extrinsic: fake_extrinsic(),
      permission: Permission::Execute
    };
  }: create_access_control(
    RawOrigin::Signed(caller.clone()),
    access_control.pallet.clone(),
    access_control.extrinsic.clone(),
    access_control.permission.clone()
  )
  verify {
    assert_eq!(AccessControlPallet::<T>::access_controls(access_control.clone()), Some(vec![]));
  }

    impl_benchmark_test_suite!(AccessControlPallet, crate::mock::new_test_ext(), crate::mock::Test);
}
