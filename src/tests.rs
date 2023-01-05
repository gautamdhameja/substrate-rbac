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
fn verify_authorized_execution_of_an_extrinsic(ctx: &mut WithAccessControlContext) {
    new_test_ext(ctx).execute_with(|| {
        assert_ok!(AccessControl::create_access_control(
            ctx.admin_signer(),
            mock::pallet_name(),
            mock::fake_extrinsic(),
            Permission::Execute
        ));
    });
}

#[test_context(WithAccessControlContext)]
#[test]
fn deny_extrinsic_execution_access(ctx: &mut WithAccessControlContext) {
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
fn assign_access_control(ctx: &mut WithAccessControlContext) {
    new_test_ext(ctx).execute_with(|| {
        let account_to_add = mock::new_account();
        let unauthorized_signer = RuntimeOrigin::signed(account_to_add);

        // The new Account is denied access
        assert_noop!(
            AccessControl::create_access_control(
                unauthorized_signer,
                mock::pallet_name(),
                mock::fake_extrinsic(),
                Permission::Execute
            ),
            Error::<Test>::AccessDenied
        );

        // Add the new account to the admins who can create access controls
        assert_ok!(AccessControl::assign_access_control(
            ctx.admin_signer(),
            account_to_add,
            access_control::AccessControl {
                pallet: mock::pallet_name(),
                extrinsic: mock::create_access_control(),
                permission: access_control::Permission::Execute,
            }
        ));

        // ensure that the new account is now able to create access controls
        assert_ok!(AccessControl::create_access_control(
            RuntimeOrigin::signed(account_to_add),
            mock::pallet_name(),
            mock::fake_extrinsic(),
            Permission::Execute
        ));

        // ensure that the new account is not a manager

        // ensure that an account with the execution permissions cannot make themselves a manager
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
fn add_admin_is_root_only(ctx: &mut WithAccessControlContext) {
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
fn revoke_admin_is_root_only(ctx: &mut WithAccessControlContext) {
    new_test_ext(ctx).execute_with(|| {
        let account_to_remove = ctx.admins.first().unwrap();

        assert_noop!(
            AccessControl::revoke_admin(ctx.admin_signer(), account_to_remove.clone()),
            BadOrigin
        );
    });
}
