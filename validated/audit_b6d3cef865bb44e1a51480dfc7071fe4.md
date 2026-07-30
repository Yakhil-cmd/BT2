[1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** crates/sui-types/src/deny_list_v1.rs (L52-71)
```rust
pub fn check_coin_deny_list_v1(
    sender: SuiAddress,
    input_objects: &CheckedInputObjects,
    receiving_objects: &ReceivingObjects,
    funds_withdraw_types: BTreeSet<String>,
    object_store: &dyn ObjectStore,
) -> UserInputResult {
    let mut coin_types =
        input_object_coin_types_for_denylist_check(input_objects, receiving_objects);
    coin_types.extend(funds_withdraw_types);

    let Some(deny_list) = get_coin_deny_list(object_store) else {
        // TODO: This is where we should fire an invariant violation metric.
        if cfg!(debug_assertions) {
            panic!("Failed to get the coin deny list");
        } else {
            return Ok(());
        }
    };
    check_deny_list_v1_impl(deny_list, sender, coin_types, object_store)
```

**File:** crates/sui-types/src/deny_list_v1.rs (L155-172)
```rust
pub fn get_coin_deny_list(object_store: &dyn ObjectStore) -> Option<PerTypeDenyList> {
    get_deny_list_root_object(object_store).and_then(|obj| {
        let deny_list: DenyList = obj
            .to_rust()
            .expect("DenyList object type must be consistent");
        match get_dynamic_field_from_store(
            object_store,
            *deny_list.lists.id.object_id(),
            &DENY_LIST_COIN_TYPE_INDEX,
        ) {
            Ok(deny_list) => Some(deny_list),
            Err(err) => {
                error!("Failed to get deny list inner state: {}", err);
                None
            }
        }
    })
}
```
