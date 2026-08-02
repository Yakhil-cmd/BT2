No vulnerability found for this question.

The reasoning in the exploit question misunderstands the Move resource storage model. `MoveStructType::ADDRESS` (defaulting to `CORE_CODE_ADDRESS`) represents the address where the *module defining the struct* is published (e.g., `0x1` for `account::Account`), not the address where a specific account's resource instance is stored. [1](#0-0) 

The actual per-account storage location is a separate parameter passed explicitly into resource-fetch functions, independent of `struct_tag().address`. In `vm_validator::get_account_sequence_number`, the sender's `address` is passed explicitly as the storage key, while `AccountResource::struct_tag()` (whose `address` field is `CORE_CODE_ADDRESS` because `AccountResource` doesn't override `ADDRESS`) only identifies *which type* is being fetched, not *where*: [2](#0-1) 

This mirrors the general Move global storage addressing model, where a resource is stored at `(account_address, struct_tag)`. Two different accounts calling this function with different `address` values will read distinct storage slots even though `AccountResource::struct_tag().address` is identical for both (`0x1`), because the account address is a separate key component, not derived from the struct tag. The codebase even has an explicit test asserting `AccountResource::struct_tag().address.is_special()` is intentional and load-bearing for gas-charging logic — confirming this is expected, documented behavior, not a bug: [3](#0-2) 

Additional confirmation from `aptos_vm.rs`, which explicitly separates the struct tag's special address (used only to locate the `account` module) from `txn_data.sender()` (used as the actual resource storage key): [4](#0-3) 

There is no code path where two different unprivileged accounts' sequence numbers collide or alias to the same storage slot due to a missing `ADDRESS` override. The proof-of-concept idea in the question (asserting `struct_tag().address != CORE_CODE_ADDRESS` for account-scoped resources) is based on an incorrect premise — many legitimate framework-defined resource types intentionally share `CORE_CODE_ADDRESS` as their struct tag address (since they're defined in `0x1`-published modules), while still being stored per-account via the separate address parameter in the storage key.

### Citations

**File:** third_party/move/move-core/types/src/move_resource.rs (L13-37)
```rust
pub trait MoveStructType {
    const ADDRESS: AccountAddress = crate::language_storage::CORE_CODE_ADDRESS;
    const MODULE_NAME: &'static IdentStr;
    const STRUCT_NAME: &'static IdentStr;

    fn module_identifier() -> Identifier {
        Self::MODULE_NAME.to_owned()
    }

    fn struct_identifier() -> Identifier {
        Self::STRUCT_NAME.to_owned()
    }

    fn type_args() -> Vec<TypeTag> {
        vec![]
    }

    fn struct_tag() -> StructTag {
        StructTag {
            address: Self::ADDRESS,
            name: Self::struct_identifier(),
            module: Self::module_identifier(),
            type_args: Self::type_args(),
        }
    }
```

**File:** vm-validator/src/vm_validator.rs (L102-117)
```rust
/// returns account's sequence number from storage
pub fn get_account_sequence_number(
    state_view: &DbStateView,
    address: AccountAddress,
) -> Result<u64> {
    fail_point!("vm_validator::get_account_sequence_number", |_| {
        Err(anyhow::anyhow!(
            "Injected error in get_account_sequence_number"
        ))
    });

    match AccountResource::fetch_move_resource(state_view, &address)? {
        Some(account_resource) => Ok(account_resource.sequence_number()),
        None => Ok(0),
    }
}
```

**File:** types/src/account_config/resources/core_account.rs (L93-109)
```rust
impl MoveStructType for AccountResource {
    const MODULE_NAME: &'static IdentStr = ident_str!("account");
    const STRUCT_NAME: &'static IdentStr = ident_str!("Account");
}

impl MoveResource for AccountResource {}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_account_resource_has_special_address() {
        // Note: module loading gas charging logic depends on this assumption. This should never
        // change, but a test should catch if address changes at any point.
        assert!(AccountResource::struct_tag().address.is_special());
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L3763-3782)
```rust
    {
        let account_tag = AccountResource::struct_tag();

        // INVARIANT:
        //   Account lives at a special address, so we should not be charging for it and unmetered
        //   access is safe. There are tests that ensure that address is always special.
        assert!(account_tag.address.is_special());
        let module = module_storage.unmetered_get_existing_deserialized_module(
            &account_tag.address,
            &account_tag.module,
        )?;

        let (maybe_bytes, _) = resolver
            .get_resource_bytes_with_metadata_and_layout(
                &txn_data.sender(),
                &account_tag,
                &module.metadata,
                None,
            )
            .map_err(|e| e.finish(Location::Undefined))?;
```
