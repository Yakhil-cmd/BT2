[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** crates/sui-transaction-checks/src/deny.rs (L29-38)
```rust
/// Check that the provided transaction is allowed to be signed according to the
/// deny config.
pub fn check_transaction_for_signing(
    tx_data: &TransactionData,
    tx_signatures: &[GenericSignature],
    input_object_kinds: &[InputObjectKind],
    receiving_objects: &[ObjectRef],
    filter_config: &TransactionDenyConfig,
    package_store: &dyn BackingPackageStore,
) -> SuiResult {
```

**File:** crates/sui-transaction-checks/src/deny.rs (L246-259)
```rust
    for command in tx_data.kind().iter_commands() {
        match command {
            Command::Publish(_, deps) => {
                // It is possible that the deps list is inaccurate since it's provided
                // by the user. But that's OK because this publish transaction will fail
                // to execute in the end. Similar reasoning for Upgrade.
                dependencies.extend(deps.iter().copied());
            }
            Command::Upgrade(_, deps, package_id, _) => {
                dependencies.extend(deps.iter().copied());
                // It's crucial that we don't allow upgrading a package in the deny list,
                // otherwise one can bypass the deny list by upgrading a package.
                dependencies.push(*package_id);
            }
```

**File:** crates/sui-transaction-checks/src/deny.rs (L260-282)
```rust
            Command::MoveCall(call) => {
                let package = package_store.get_package_object(&call.package)?.ok_or(
                    SuiErrorKind::UserInputError {
                        error: UserInputError::ObjectNotFound {
                            object_id: call.package,
                            version: None,
                        },
                    },
                )?;
                // linkage_table maps from the original package ID to the upgraded ID for each
                // dependency. Here we only check the upgraded (i.e. the latest) ID against the
                // deny list. This means that we only make sure that the denied package is not
                // currently used as a dependency. This allows us to deny an older version of
                // package but permits the use of a newer version.
                dependencies.extend(
                    package
                        .move_package()
                        .linkage_table()
                        .values()
                        .map(|upgrade_info| upgrade_info.upgraded_id),
                );
                dependencies.push(package.move_package().id());
            }
```
