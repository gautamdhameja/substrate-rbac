# FRAME Role-Based Access Control Pallet

A [FRAME](https://substrate.dev/docs/en/knowledgebase/runtime/) pallet (runtime module) for [Substrate](https://github.com/paritytech/substrate)-based
blockchains that implements role-based access control for Substrate [extrinsic](https://substrate.dev/docs/en/knowledgebase/learn-substrate/extrinsics) calls.

Access control validation is done at the [transaction pool](https://substrate.dev/docs/en/knowledgebase/learn-substrate/tx-pool) validation layer, using
Substrate's [signed extension](https://substrate.dev/docs/en/knowledgebase/learn-substrate/extrinsics#signed-extension) capabilities.

## Description

This pallet maintains an on-chain registry of roles and the users to which those roles are assigned. A `Role` is a tuple that encapsulates the name of a pallet
and a `Permission` that qualifies the level of access granted by the `Role`. A `Permission` is an enum with the following variants: `Execute` and `Manage`. The
`Execute` permission allows a user to invoke a pallet's dispatchable functions. The `Manage` permission allows a user to assign and revoke roles for a pallet
and also implies the `Execute` permission. The RBAC pallet also defines "super admin" role that has `Execute` permission on all pallets. Super admins may be
configured in the [chain specification](https://substrate.dev/docs/en/knowledgebase/integrate/chain-spec); the
[`Root` origin](https://substrate.dev/docs/en/knowledgebase/runtime/origin) also has the privilege to dynamically configure super admins.

## Usage

* Add the module as a dependency in the `Cargo.toml` of your `runtime` directory. Make sure to enter the correct path or git url of the pallet as per your
  setup.

```toml
[dependencies.substrate_rbac]
package = 'substrate-rbac'
git = 'https://github.com/gautamdhameja/substrate-rbac.git'
default-features = false
```

* Declare the pallet in your `runtime/src/lib.rs`.

```rust
pub use substrate_rbac;

impl substrate_rbac::Trait for Runtime {
    type Event = Event;
}

construct_runtime!(
    pub enum Runtime where
        Block = Block,
        NodeBlock = opaque::Block,
        UncheckedExtrinsic = UncheckedExtrinsic
    {
        ...
        ...
        ...
        RBAC: substrate_rbac::{Module, Call, Storage, Event<T>, Config<T>},
    }
);
```

* Add the module's `Authorize` type in the `SignedExtra` checklist.

```rust
pub type SignedExtra = (
    ...
    ...
    balances::TakeFees<Runtime>,
    substrate_rbac::Authorize<Runtime>
```

* Add a genesis configuration for the module in the `src/chain_spec.rs` file.

```rust
rbac: Some(RBACConfig {
	super_admins: vec![get_account_id_from_seed::<sr25519::Public>("Alice")],
	permissions: vec![(Role { pallet: b"Rbac".to_vec(), permission: Permission::Manage },
					  vec![get_account_id_from_seed::<sr25519::Public>("Alice")])
	],
})
```

* `cargo build --release` and then `cargo run --release -- --dev`

## Sample

The usage of this pallet are demonstrated in the [Substrate permissioning sample](https://github.com/gautamdhameja/substrate-permissioning).

## Disclaimer

This code not audited and reviewed for production use cases. You can expect bugs and security vulnerabilities. Do not use it as-is in real applications.
