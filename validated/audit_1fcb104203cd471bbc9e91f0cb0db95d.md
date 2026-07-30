[1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** crates/sui-framework/packages/sui-framework/sources/vec_map.move (L45-49)
```text
/// Insert the entry `key` |-> `value` into `self`.
/// Aborts if `key` is already bound in `self`.
public fun insert<K: copy, V>(self: &mut VecMap<K, V>, key: K, value: V) {
    assert!(!self.contains(&key), EKeyAlreadyExists);
    self.contents.push_back(Entry { key, value })
```

**File:** crates/sui-framework/packages/bridge/sources/treasury.move (L90-120)
```text
public(package) fun register_foreign_token<T>(
    self: &mut BridgeTreasury,
    tc: TreasuryCap<T>,
    uc: UpgradeCap,
    metadata: &CoinMetadata<T>,
) {
    // Make sure TreasuryCap has not been minted before.
    assert!(coin::total_supply(&tc) == 0, ETokenSupplyNonZero);
    let type_name = type_name::with_defining_ids<T>();
    let address_bytes = hex::decode(ascii::into_bytes(type_name::address_string(&type_name)));
    let coin_address = address::from_bytes(address_bytes);
    // Make sure upgrade cap is for the Coin package
    // FIXME: add test
    assert!(
        object::id_to_address(&package::upgrade_package(&uc)) == coin_address,
        EInvalidUpgradeCap,
    );
    let registration = ForeignTokenRegistration {
        type_name,
        uc,
        decimal: coin::get_decimals(metadata),
    };
    self.waiting_room.add(type_name::into_string(type_name), registration);
    self.treasuries.add(type_name, tc);

    event::emit(TokenRegistrationEvent {
        type_name,
        decimal: coin::get_decimals(metadata),
        native_token: false,
    });
}
```

**File:** crates/sui-framework/packages/bridge/sources/treasury.move (L122-148)
```text
public(package) fun add_new_token(
    self: &mut BridgeTreasury,
    token_name: String,
    token_id: u8,
    native_token: bool,
    notional_value: u64,
) {
    if (!native_token) {
        assert!(notional_value > 0, EInvalidNotionalValue);
        let ForeignTokenRegistration {
            type_name,
            uc,
            decimal,
        } = self.waiting_room.remove<String, ForeignTokenRegistration>(token_name);
        let decimal_multiplier = 10u64.pow(decimal);
        self
            .supported_tokens
            .insert(
                type_name,
                BridgeTokenMetadata {
                    id: token_id,
                    decimal_multiplier,
                    notional_value,
                    native_token,
                },
            );
        self.id_token_type_map.insert(token_id, type_name);
```
