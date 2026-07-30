### Title
Unauthorized `TreasuryCap<T>` creation via `coin_registry::new_currency<T>` allows counterfeit minting of any pre-existing coin type - (File: crates/sui-framework/packages/sui-framework/sources/registries/coin_registry.move)

### Summary
The external report's root cause is that a privileged resource (the ATA holding LP tokens) is created based on a check (`lamports == 0`) that does not actually verify legitimate initialization state, allowing an attacker to squat/corrupt the slot before the legitimate owner initializes it. The Sui analog is `sui::coin_registry::new_currency<T>` [1](#0-0) , which mints a brand-new `TreasuryCap<T>` and claims the registry slot for `T` based only on a generic ability bound (`T: key`) rather than on proof that the caller actually owns/defines `T` (normally enforced via a one-time-witness, as in the sibling function `new_currency_with_otw`).

### Finding Description
`new_currency<T: /* internal */ key>` is declared `public` and gated only by:
- `assert!(!registry.exists<T>(), ECurrencyAlreadyExists)` [2](#0-1) 
- `derived_object::claim(&mut registry.id, CurrencyKey<T>())` to reserve the deterministic registry slot [3](#0-2) 
- a fresh `TreasuryCap<T>` minted via `coin::new_treasury_cap(ctx)` [4](#0-3) 

Crucially, `T` only needs the `key` ability — Move's generic type-parameter substitution does not require the caller to be the module that defines `T`, nor does it require any witness value proving exclusive/first-time creation. The `/* internal */` annotation on `T` is a plain comment, not an enforced Move construct, so it provides no actual protection.

Contrast this with the two other currency-creation entry points, which correctly gate single-issuance:
- `new_currency_with_otw<T: drop>` requires `sui::types::is_one_time_witness(&otw)` [5](#0-4) 
- the deprecated `coin::create_currency<T: drop>` requires the same OTW check [6](#0-5) 

`coin::new_treasury_cap<T>` itself is `public(package)` [7](#0-6) , so it cannot be called directly by outside code — but `coin_registry::new_currency` (in the same `sui` package) exposes it publicly without the witness gate, effectively re-exporting unauthenticated `TreasuryCap<T>` minting for arbitrary `T`.

Because `Coin<T>`/`Balance<T>` fungibility is determined purely by the type tag `T`, not by which `TreasuryCap<T>` instance minted it, any `Coin<T>` minted from this rogue treasury cap is indistinguishable from, and fully fungible with, coins minted by the legitimate treasury cap for the same `T`. `registry.exists<T>()` only tracks whether the *coin_registry* slot for `T` has been claimed — it has nothing to do with whether a legitimate `TreasuryCap<T>` already exists from a pre-registry (legacy) `create_currency` call. Thus, for any coin type `T` that has been published (even years ago, with real economic value in circulation) but has not yet been migrated into the new registry via `new_currency`/`migrate_legacy_metadata`, an unprivileged attacker can:
1. Call `coin_registry::new_currency<T>(...)` themselves.
2. Receive a fresh, independent `TreasuryCap<T>` with `total_supply = 0`.
3. Mint unlimited `Coin<T>` using this illegitimate cap.
4. Spend/trade the counterfeit coins as genuine `T` tokens anywhere that only checks the type tag (virtually all DeFi protocols, DEXes, wallets).

This is directly analogous to the reported bug's root cause: a resource-creation gate (`lamports==0` / `!registry.exists<T>()`) that is meant to imply "no prior legitimate state exists," but which an attacker can satisfy first through a public, unauthenticated entry point, thereby seizing control of a slot/capability that should only be attainable by the legitimate owner.

### Impact Explanation
This enables direct, permissionless counterfeiting/minting of any not-yet-migrated coin type on Sui, which is unauthorized object creation (a forged `TreasuryCap<T>`) leading directly to fund theft/dilution of an existing fungible asset — squarely matching the Critical impact category "direct fund theft or state corruption from unauthorized object creation ... " Any market or protocol that trusts `Coin<T>`/`Balance<T>` purely by type (the standard, intended trust model on Sui) would accept these counterfeit coins as genuine.

### Likelihood Explanation
Likelihood is high: `new_currency` is a `public` framework function reachable with a normal, unprivileged PTB call; the only requirement is that `registry.exists<T>()` is false for the targeted type, which is true for the (likely very large) set of coin types that have not yet been proactively migrated to the new `coin_registry` system. No special permissions, keys, or race conditions beyond ordinary transaction ordering are needed.

### Recommendation
Require the same one-time-witness proof used by `new_currency_with_otw`/`create_currency` before minting a `TreasuryCap<T>` and claiming the registry slot in `new_currency<T>`, or otherwise cryptographically bind `T` to the calling module (verifying it via `type_name::with_defining_ids<T>()` matches the current package) so that only the module that defines `T` can obtain a `TreasuryCap<T>`/registry entry for it. At minimum, `new_currency` should be restricted (e.g., `public(package)`/friend-only, or witness-gated) so it cannot be invoked directly against arbitrary pre-existing types by unrelated callers.

### Proof of Concept
1. Identify any published coin type `T` (e.g., an existing, valuable legacy coin) for which `coin_registry::exists<T>()` is still `false` (i.e., not yet migrated to the new registry).
2. As an unprivileged account, submit a PTB calling `sui::coin_registry::new_currency<T>(registry, decimals, symbol, name, description, icon_url, ctx)` [1](#0-0) . This succeeds because only `T: key` is required, and `assert!(!registry.exists<T>())` passes for `T` not yet migrated.
3. The call returns a `TreasuryCap<T>` to the attacker with `total_supply = 0` (freshly created via `coin::new_treasury_cap`) [7](#0-6) .
4. The attacker calls `coin::mint`/`coin::mint_balance` (standard `TreasuryCap` API) using this rogue cap to mint arbitrary amounts of `Coin<T>`.
5. These `Coin<T>` are fully fungible with legitimate `Coin<T>` balances everywhere that trusts type `T` alone (exchanges, lending markets, wallets), allowing the attacker to redeem/trade counterfeit value.

### Citations

**File:** crates/sui-framework/packages/sui-framework/sources/registries/coin_registry.move (L174-202)
```text
public fun new_currency<T: /* internal */ key>(
    registry: &mut CoinRegistry,
    decimals: u8,
    symbol: String,
    name: String,
    description: String,
    icon_url: String,
    ctx: &mut TxContext,
): (CurrencyInitializer<T>, TreasuryCap<T>) {
    assert!(!registry.exists<T>(), ECurrencyAlreadyExists);
    assert!(is_ascii_printable!(&symbol), EInvalidSymbol);

    let treasury_cap = coin::new_treasury_cap(ctx);
    let currency = Currency<T> {
        id: derived_object::claim(&mut registry.id, CurrencyKey<T>()),
        decimals,
        name,
        symbol,
        description,
        icon_url,
        supply: option::some(SupplyState::Unknown),
        regulated: RegulatedState::Unregulated,
        treasury_cap_id: option::some(object::id(&treasury_cap)),
        metadata_cap_id: MetadataCapState::Unclaimed,
        extra_fields: vec_map::empty(),
    };

    (CurrencyInitializer { currency, is_otw: false, extra_fields: bag::new(ctx) }, treasury_cap)
}
```

**File:** crates/sui-framework/packages/sui-framework/sources/registries/coin_registry.move (L209-218)
```text
public fun new_currency_with_otw<T: drop>(
    otw: T,
    decimals: u8,
    symbol: String,
    name: String,
    description: String,
    icon_url: String,
    ctx: &mut TxContext,
): (CurrencyInitializer<T>, TreasuryCap<T>) {
    assert!(sui::types::is_one_time_witness(&otw), ENotOneTimeWitness);
```

**File:** crates/sui-framework/packages/sui-framework/sources/coin.move (L220-234)
```text
/// Create a new currency type `T` as and return the `TreasuryCap` for
/// `T` to the caller. Can only be called with a `one-time-witness`
/// type, ensuring that there's only one `TreasuryCap` per `T`.
#[deprecated(note = b"Use `coin_registry::new_currency_with_otw` instead")]
public fun create_currency<T: drop>(
    witness: T,
    decimals: u8,
    symbol: vector<u8>,
    name: vector<u8>,
    description: vector<u8>,
    icon_url: Option<Url>,
    ctx: &mut TxContext,
): (TreasuryCap<T>, CoinMetadata<T>) {
    // Make sure there's only one instance of the type T
    assert!(sui::types::is_one_time_witness(&witness), EBadWitness);
```

**File:** crates/sui-framework/packages/sui-framework/sources/coin.move (L523-528)
```text
public(package) fun new_treasury_cap<T>(ctx: &mut TxContext): TreasuryCap<T> {
    TreasuryCap {
        id: object::new(ctx),
        total_supply: balance::create_supply_internal(),
    }
}
```
