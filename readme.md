# Substrate Access Control Pallet
Fork from [substrate-rbac](https://github.com/gautamdhameja/substrate-rbac)

A [Substrate](https://github.com/paritytech/substrate) pallet implementing access controls and permissions for Substrate extrinsic calls.

The filtering of incoming extrinsics and their sender accounts is done at the transaction queue validation layer, using the `SignedExtension` trait.

## Usage

* Add the module's dependency in the `Cargo.toml` of your `runtime` directory. Make sure to enter the correct path or git url of the pallet as per your setup.

```toml
access-control = { version = "0.1.0", default-features = false, git = "https://github.com/WunderbarNetwork/access-control" }
```

* Declare the pallet in your `runtime/src/lib.rs`.

```rust
// runtime/src/lib.rs
pub use access_control;

// ...

impl access_control::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type AdminOrigin = EnsureRoot<AccountId>;
}

// ...

// Add access_control to create_transaction function
fn create_transaction(...) -> Option<(...)> { 
    // ...

    let extra = ( 
        // ...
        access_control::Authorize::<Runtime>::new(),
    );
}

// ...

// Add access_control to the runtime
construct_runtime!(
    pub enum Runtime where
        Block = Block,
        NodeBlock = opaque::Block,
        UncheckedExtrinsic = UncheckedExtrinsic
    {
        // ...
        AccessControl: access_control,
        // ...
    }
);

// ...

// Add the module's `Authorize` type in the `SignedExtra` checklist.
pub type SignedExtra = (
    // ...
   access_control::Authorize<Runtime>,
);

//...
```

* Add a genesis configuration for the module in the `src/chain_spec.rs` file.

```rust
/// node/src/chain_spec.rs

// Import access_control and AccessControlConfig from the runtime
use _runtime::{ 
    // ...
    access_control, AccessControlConfig
}

// ...

fn testnet_genesis(...) -> GenesisConfig {
    let authorized_accounts = initial_authorities
        .iter()
        .map(|authority| authority.0.clone())
        .collect::<Vec<_>>();

    // Create initial access controls including the AccessControl Pallet
    let access_control_structs = vec![
            // Create both Execute and Manage controls for the AccessControl Pallets `create_access_control` extrinsic.
            access_control::AccessControl {
                pallet: "AccessControl".as_bytes().to_vec(),
                extrinsic: "create_access_control".as_bytes().to_vec(),
                permission: access_control::Permission::Execute,
            },
            access_control::AccessControl {
                pallet: "AccessControl".as_bytes().to_vec(),
                extrinsic: "create_access_control".as_bytes().to_vec(),
                permission: access_control::Permission::Manage,
            },
            // ... additional AccessControls ...
    ];

    // Create the tuple of access controls and accounts who can action.
	let access_controls: Vec<(access_control::AccessControl, Vec<AccountId>)> =
		access_control_structs
			.iter()
			.map(|access_control| (access_control.clone(), authorized_accounts.clone()))
			.collect::<Vec<_>>();

    // ...

    GenesisConfig { 
        /// ...
        access_control: AccessControlConfig { admins: authorized_accounts.clone() , access_controls }
    }
}
```

### Followed by runtime compilation 

```bash
cargo build --release
```

## Disclaimer

This code not audited and reviewed for production use cases. You can expect bugs and security vulnerabilities. Do not use it as-is in real applications.
