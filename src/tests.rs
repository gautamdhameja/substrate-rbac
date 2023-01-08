use crate::{self as access_control};
use crate::{
    mock::{self, WithAccessControlContext, *},
    Error, Permission,
};
use frame_support::error::BadOrigin;
use frame_support::{assert_noop, assert_ok};
use test_context::test_context;

#[test_context(WithAccessControlContext)]
#[test]
fn authorized_execution_of_an_extrinsic(ctx: &mut WithAccessControlContext) {
    new_test_ext(ctx).execute_with(|| {
        let expected_access_control = access_control::AccessControl {
            pallet: mock::pallet_name(),
            extrinsic: mock::fake_extrinsic(),
            permission: Permission::Execute,
        };

        assert_ok!(AccessControl::create_access_control(
            ctx.admin_signer(),
            expected_access_control.pallet.clone(),
            expected_access_control.extrinsic.clone(),
            expected_access_control.permission.clone()
        ));

        assert_eq!(
            AccessControl::access_controls(expected_access_control),
            Some(vec![])
        )
    });
}

#[test_context(WithAccessControlContext)]
#[test]
fn deny_execution_of_an_extrinsic(ctx: &mut WithAccessControlContext) {
    new_test_ext(ctx).execute_with(|| {
        let another_account = mock::new_account();
        let signer = RuntimeOrigin::signed(another_account);

        assert_noop!(
            AccessControl::create_access_control(
                signer,
                mock::pallet_name(),
                mock::fake_extrinsic(),
                Permission::Execute
            ),
            Error::<Test>::AccessDenied
        );
    });
}

#[test_context(WithAccessControlContext)]
#[test]
fn sudo_override_create_access_control(ctx: &mut WithAccessControlContext) {
    new_test_ext(ctx).execute_with(|| {
        let expected_access_control = access_control::AccessControl {
            pallet: mock::pallet_name(),
            extrinsic: mock::fake_extrinsic(),
            permission: Permission::Execute,
        };

        assert_ok!(AccessControl::create_access_control(
            RuntimeOrigin::root(),
            expected_access_control.pallet.clone(),
            expected_access_control.extrinsic.clone(),
            expected_access_control.permission.clone()
        ));

        assert_eq!(
            AccessControl::access_controls(expected_access_control),
            Some(vec![])
        )
    });
}

#[test_context(WithAccessControlContext)]
#[test]
fn assign_access_control(ctx: &mut WithAccessControlContext) {
    new_test_ext(ctx).execute_with(|| {
        let account_to_add = mock::new_account();
        let unauthorized_signer = RuntimeOrigin::signed(account_to_add);
        let access_control = ctx.access_controls.first().unwrap().0.clone();

        let new_access_control = access_control::AccessControl {
            pallet: mock::pallet_name(),
            extrinsic: mock::fake_extrinsic(),
            permission: access_control::Permission::Execute,
        };

        // The new Account is denied access
        assert_noop!(
            AccessControl::create_access_control(
                unauthorized_signer,
                new_access_control.pallet.clone(),
                new_access_control.extrinsic.clone(),
                new_access_control.permission.clone()
            ),
            Error::<Test>::AccessDenied
        );

        // Add the new account to the admins who can create access controls
        assert_ok!(AccessControl::assign_access_control(
            ctx.admin_signer(),
            account_to_add.clone(),
            access_control.clone()
        ));

        assert!(AccessControl::access_controls(access_control.clone())
            .unwrap()
            .contains(&account_to_add));

        // ensure that the new account is now able to create access controls
        assert_ok!(AccessControl::create_access_control(
            RuntimeOrigin::signed(account_to_add),
            new_access_control.pallet.clone(),
            new_access_control.extrinsic.clone(),
            new_access_control.permission.clone()
        ));

        assert_eq!(
            AccessControl::access_controls(new_access_control.clone()),
            Some(vec![])
        );

        // ensure that the new account is not a manager
        // ensure that an account with the execution permissions cannot make themselves a manager
        assert_noop!(
            AccessControl::assign_access_control(
                RuntimeOrigin::signed(account_to_add),
                account_to_add,
                new_access_control.clone()
            ),
            Error::<Test>::AccessDenied
        );
    });
}

#[test_context(WithAccessControlContext)]
#[test]
fn sudo_override_assign_access_control(ctx: &mut WithAccessControlContext) {
    new_test_ext(ctx).execute_with(|| {
        let account_to_add = mock::new_account();
        let access_control = ctx.access_controls.first().unwrap().0.clone();

        assert_ok!(AccessControl::assign_access_control(
            RuntimeOrigin::root(),
            account_to_add.clone(),
            access_control.clone()
        ));

        assert!(AccessControl::access_controls(access_control.clone())
            .unwrap()
            .contains(&account_to_add));
    });
}

#[test_context(WithAccessControlContext)]
#[test]
fn revoke_access_for_an_account(ctx: &mut WithAccessControlContext) {
    new_test_ext(ctx).execute_with(|| {
        let account_to_remove = ctx.admins.first().clone().unwrap();

        let access_control = access_control::AccessControl {
            pallet: mock::pallet_name(),
            extrinsic: mock::create_access_control(),
            permission: access_control::Permission::Execute,
        };

        assert_ok!(AccessControl::revoke_access(
            ctx.admin_signer(),
            *account_to_remove,
            access_control.clone()
        ));

        assert_noop!(
            AccessControl::create_access_control(
                ctx.admin_signer(),
                mock::pallet_name(),
                mock::fake_extrinsic(),
                Permission::Execute
            ),
            Error::<Test>::AccessDenied
        );
    });
}

#[test_context(WithAccessControlContext)]
#[test]
fn sudo_override_revoke_access(ctx: &mut WithAccessControlContext) {
    new_test_ext(ctx).execute_with(|| {
        let account_to_remove = ctx.admins.first().clone().unwrap();

        let access_control = access_control::AccessControl {
            pallet: mock::pallet_name(),
            extrinsic: mock::create_access_control(),
            permission: access_control::Permission::Execute,
        };

        assert_ok!(AccessControl::revoke_access(
            RuntimeOrigin::root(),
            *account_to_remove,
            access_control.clone()
        ));

        assert!(!AccessControl::access_controls(access_control.clone())
            .unwrap()
            .contains(&account_to_remove));

        assert_noop!(
            AccessControl::create_access_control(
                ctx.admin_signer(),
                mock::pallet_name(),
                mock::fake_extrinsic(),
                Permission::Execute
            ),
            Error::<Test>::AccessDenied
        );
    });
}

#[test_context(WithAccessControlContext)]
#[test]
fn add_admin(ctx: &mut WithAccessControlContext) {
    new_test_ext(ctx).execute_with(|| {
        let account_to_add = mock::new_account();

        assert_ok!(AccessControl::add_admin(
            RuntimeOrigin::root(),
            account_to_add.clone()
        ));

        assert_eq!(AccessControl::admins(account_to_add), Some(()));
    });
}

#[test_context(WithAccessControlContext)]
#[test]
fn add_admin_is_sudo_only(ctx: &mut WithAccessControlContext) {
    new_test_ext(ctx).execute_with(|| {
        let account_to_add = mock::new_account();

        assert_noop!(
            AccessControl::add_admin(ctx.admin_signer(), account_to_add.clone()),
            BadOrigin
        );
    });
}

#[test_context(WithAccessControlContext)]
#[test]
fn revoke_admin(ctx: &mut WithAccessControlContext) {
    new_test_ext(ctx).execute_with(|| {
        let account_to_remove = ctx.admins.first().unwrap();

        assert_ok!(AccessControl::revoke_admin(
            RuntimeOrigin::root(),
            account_to_remove.clone()
        ));

        assert_eq!(AccessControl::admins(account_to_remove), None)
    });
}

#[test_context(WithAccessControlContext)]
#[test]
fn revoke_admin_is_sudo_only(ctx: &mut WithAccessControlContext) {
    new_test_ext(ctx).execute_with(|| {
        let account_to_remove = ctx.admins.first().unwrap();

        assert_noop!(
            AccessControl::revoke_admin(ctx.admin_signer(), account_to_remove.clone()),
            BadOrigin
        );
    });
}
