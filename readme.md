# Substrate Access Control Pallet
Fork from [substrate-rbac](https://github.com/gautamdhameja/substrate-rbac)

A [Substrate](https://github.com/paritytech/substrate) pallet implementing access controls and permissions for Substrate extrinsic calls.

The filtering of incoming extrinsics and their sender accounts is done at the transaction queue validation layer, using the `SignedExtension` trait.
Extrinsics operate with substrates default behavior if they do not have access controls enabled.

Introduce the `VerifyAccess` type into the config of your custom pallets and call the `verify_execution_access` function to ensure a specific extrinsic has access controls by default.

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

### Access Control for custom pallets
* Add access_control to your custom pallets Cargo.toml
* Followed by implementing your access control logic

```rust
use access_control::traits::VerifyAccess;

// ...

#[pallet::config]
pub trait Config: frame_system::Config + CreateSignedTransaction<Call<Self>> {
    // ...

    // Add VerifyAccess trait to the pallet.
    type VerifyAccess: VerifyAccess<Self::AccountId>;
}



#[pallet:weight(0)]
fn do_something(origin: OriginFor<T>) -> DispatchResult {
    // 1. Ensure that the extrinsic was signed.
    let signer = ensure_signed(origin);

    // 2. ensure that the signer has authentication access and access control was setup.
    //   - If the access_control was configured correctly the the SignedExtension will reject the transaction before it was added to the transaction pool,
    ///    however adding this additional check ensures that in the case of the access control not been setup correctly the extrinsic will fail.
    //   - This also serves as development documentation that this extrinsic is meant to have AccessControl at the transaction pool level.
    match T::VerifyAccess::verify_execute_access(
		signer,
		"MyCustomPallet".as_bytes().to_vec(),
		"do_something".as_bytes().to_vec(),
	) {
		Ok(_) => {
			info!("Successfully verified access")
            // Additional logic
		},
            // Return an Error
			Err(_e) => return Err(frame_support::error::BadOrigin.into()),
		}

    // custom pallet logic ...
}
```

### Followed by runtime compilation 

```bash
cargo build --release
```

## Disclaimer

This code not audited and reviewed for production use cases. You can expect bugs and security vulnerabilities. Do not use it as-is in real applications.
