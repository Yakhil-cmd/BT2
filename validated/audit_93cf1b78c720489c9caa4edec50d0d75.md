### Title
Permissionless `coin_registry::new_currency<T>` Lets Anyone Front-Run and Hijack the `TreasuryCap<T>` and Registry Slot for Any `key`-Ability Coin Type - (File: `crates/sui-framework/packages/sui-framework/sources/registries/coin_registry.move`)

### Summary
`coin_registry::new_currency<T: /* internal */ key>` is a `public fun` that mints a brand-new `TreasuryCap<T>` and reserves the single derived-address `Currency<T>` slot for type `T`, gated only by `!registry.exists<T>()`. The type parameter is bounded only by `key` — there is no witness, `TreasuryCap`, or capability proof that the caller controls or defines `T`. The doc comment ("can be called from the module that defines `T`") describes an intended trust boundary that the code never enforces. This is the same root cause as the `VaultFactory::createVault` finding: a deterministic, permissionless creation entry point whose collision key (`T` alone, via `derived_object::claim(..., CurrencyKey<T>())`) does not bind to the caller's identity or the full set of parameters, letting any unprivileged address front-run the legitimate owner of `T` and seize the privileged capability (here, `TreasuryCap<T>`) instead of just DoS'ing the call.

### Finding Description
`new_currency` derives the `Currency<T>` object's address purely from `CurrencyKey<T>()` [1](#0-0) , and this slot can be claimed only once (`derived_object::claim` aborts on re-claim via `EObjectAlreadyExists`) [2](#0-1) . Unlike `new_currency_with_otw<T: drop>`, which requires `sui::types::is_one_time_witness(&otw)` as unforgeable proof that the caller is the module that just published/instantiated `T` [3](#0-2) , `new_currency<T: key>` has no such proof: any caller who can name a public type `T` (bearing only the `key` ability) may invoke it, receiving a freshly minted `TreasuryCap<T>` from `coin::new_treasury_cap` [4](#0-3) .

The intended usage pattern (documented in the framework's own test fixture) is for a project to define an object-ability coin type and, in a *separate, later* public entry function, call `coin_registry::new_currency<MyCoin>` to obtain the real `TreasuryCap` [5](#0-4) . Because this call happens in a transaction distinct from publishing the package, and because `coin_registry::new_currency` is itself `public fun` (not gated to the defining module or restricted by any witness), any attacker can:

1. Observe the published package defining `MyCoin` (type is public on-chain immediately after publish).
2. Front-run the legitimate `create_currency` call by directly invoking `coin_registry::new_currency<MyCoin>(registry, attacker_decimals, attacker_symbol, attacker_name, attacker_description, attacker_icon_url, ctx)`.
3. Because `CurrencyKey<T>()` depends only on `T`, the attacker's call succeeds first, permanently claims the single `Currency<MyCoin>` derived address, and — critically — the attacker receives the genuine `TreasuryCap<MyCoin>`, i.e. unlimited minting authority for `Coin<MyCoin>`.
4. The legitimate project's subsequent `create_currency` call reverts with `ECurrencyAlreadyExists`, permanently locking them out of ever registering `Currency<MyCoin>` or obtaining a canonical `TreasuryCap<MyCoin>` through this path.

Because `Coin<T>`/`Balance<T>` type-checking is purely nominal on `T` and not tied to which `Supply<T>`/`TreasuryCap<T>` instance produced it, any `Coin<MyCoin>` minted from the attacker's spurious `TreasuryCap<MyCoin>` is fully fungible with and indistinguishable from coins that would have been minted by the legitimate `TreasuryCap<MyCoin>`. The attacker thus gains a mint-anything primitive for the victim's coin type before the victim ever gets a cap, which can be used to mint arbitrary amounts of `Coin<MyCoin>` and deposit them into any pool, market, or bridge that treats `Coin<MyCoin>` as the legitimate asset — direct fund theft/dilution of the victim ecosystem's token.

### Impact Explanation
This is a Critical outcome: unauthorized creation of a privileged capability object (`TreasuryCap<T>`) for a type the caller does not own or define, enabling unlimited minting of a fungible asset that is indistinguishable on-chain from the "real" token. This is analogous to the report's role-hijack scenario but strictly worse — instead of hijacking a governance-style "curator" role, the attacker hijacks the actual minting authority for the coin, enabling direct theft/dilution of value once that coin is used anywhere (DEX pools, lending markets, bridges). It also permanently DoS's the legitimate project's ability to register the canonical `Currency<T>`/`TreasuryCap<T>` via this API (`ECurrencyAlreadyExists` can never be undone).

### Likelihood Explanation
Any unprivileged Sui account can trigger this at any time a project publishes a `key`-ability coin type intending to call `new_currency` in a later transaction (the pattern explicitly demonstrated in the framework's own `non_otw_coin` example). No special timing beyond normal transaction ordering/front-running is required — the attacker only needs to observe the published type and race a public call.

### Recommendation
Bind `new_currency<T>` to proof of authority over `T`, matching `new_currency_with_otw`'s model: require a witness/capability that only the defining module of `T` can produce (e.g., require a `Publisher` object for `T`'s package, or require the caller to supply an already-existing capability/object of type `T` that only the defining module can construct), rather than allowing an arbitrary caller to instantiate the generic with any externally visible `key`-ability type. At minimum, gate the call so it can only succeed when invoked from the module that declares `T` (module-address check via `type_name::get<T>()` compared against the calling module), closing the front-running window entirely.

### Proof of Concept
1. Publish a package `victim::victim_coin` defining `public struct VictimCoin has key { id: UID }` and a `create_currency` entry function that calls `coin_registry::new_currency<VictimCoin>(...)` in a later, separate transaction (mirrors `crates/sui-e2e-tests/tests/rpc/data/non_otw_coin/sources/non_otw_coin.move`).
2. After the publish transaction lands (and before the victim's `create_currency` transaction executes/lands), an attacker submits:
   ```move
   let (init, treasury_cap) = coin_registry::new_currency<victim::victim_coin::VictimCoin>(
       registry, 6, b"SCAM".to_string(), b"Scam".to_string(), b"".to_string(), b"".to_string(), ctx
   );
   let cap = init.finalize(ctx);
   transfer::public_transfer(treasury_cap, ctx.sender()); // attacker now owns TreasuryCap<VictimCoin>
   ```
3. Attacker's transaction lands first (or via standard front-running), succeeds, and claims `Currency<VictimCoin>`'s derived address plus the real `TreasuryCap<VictimCoin>`.
4. Victim's later `create_currency()` call now reverts with `ECurrencyAlreadyExists` [6](#0-5) , while the attacker freely mints `Coin<VictimCoin>` via `treasury_cap.mint(...)`.

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

**File:** crates/sui-framework/packages/sui-framework/sources/registries/coin_registry.move (L209-219)
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
    assert!(is_ascii_printable!(&symbol), EInvalidSymbol);
```

**File:** crates/sui-framework/packages/sui-framework/sources/derived_object.move (L37-44)
```text
/// Claim a deterministic UID, using the parent's UID & any key.
public fun claim<K: copy + drop + store>(parent: &mut UID, key: K): UID {
    let addr = derive_address(parent.to_inner(), key);
    let id = addr.to_id();
    assert!(!df::exists(parent, Claimed(id)), EObjectAlreadyExists);
    df::add(parent, Claimed(id), ClaimedStatus::Reserved);
    object::new_uid_from_hash(addr)
}
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

**File:** crates/sui-e2e-tests/tests/rpc/data/non_otw_coin/sources/non_otw_coin.move (L14-35)
```text
/// Create a new currency without requiring a one-time witness
/// This demonstrates using new_currency API that doesn't require OTW
#[allow(lint(self_transfer))]
public fun create_currency(registry: &mut CoinRegistry, ctx: &mut TxContext) {
    // Create the currency without OTW
    let (currency_init, treasury_cap) = coin_registry::new_currency<MyCoin>(
        registry,
        7, // decimals
        b"NONOTW".to_string(),
        b"Non-OTW Coin".to_string(),
        b"Non-OTW coin for testing GetCoinInfo with new_currency (without OTW)".to_string(),
        b"https://example.com/non_otw.png".to_string(),
        ctx,
    );

    // Finalize - this will transfer the Currency to the registry (0xc)
    let metadata_cap = currency_init.finalize(ctx);

    // Transfer caps to sender
    transfer::public_transfer(treasury_cap, ctx.sender());
    transfer::public_transfer(metadata_cap, ctx.sender());
}
```
