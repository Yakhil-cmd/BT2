### Title
Unprivileged front-running of `sui::coin_registry::new_currency<T>` permanently blocks legitimate `Currency<T>` registration (and can squat a second `TreasuryCap<T>`) - (File: `crates/sui-framework/packages/sui-framework/sources/registries/coin_registry.move`)

### Summary
`coin_registry::new_currency<T: key>` is the modern (non-OTW) entrypoint for registering a coin's `Currency<T>` metadata object in the shared `CoinRegistry`. It only guards against re-registration with `assert!(!registry.exists<T>(), ECurrencyAlreadyExists)` [1](#0-0) , and claims the singleton derived-object slot for `T` via `derived_object::claim(&mut registry.id, CurrencyKey<T>())` [2](#0-1) . Unlike `new_currency_with_otw`, which requires `sui::types::is_one_time_witness(&otw)` to prove the caller is the defining module of `T` at publish time [3](#0-2) , `new_currency<T>` has no such proof — it only requires `T: key`, which any caller can satisfy for any public object type visible to them, regardless of which module defines `T`. This is the same root cause as the Maia report: a privileged/legitimate one-time registration path (`addEcosystemToken`) is protected only by an "already exists" check, and a mapping key that any unprivileged actor can pre-populate through an unrelated public entrypoint (`setAddresses` / here, `new_currency`) permanently blocks the legitimate registration.

### Finding Description
`CoinRegistry` is the canonical `0xc` system registry mapping each coin type `T` to exactly one `Currency<T>` object, addressed by a derived id keyed on `CurrencyKey<T>()` [4](#0-3) . The intended invariant, per the function doc, is that `new_currency<T>` "can be called from the module that defines `T`" [5](#0-4) . However the implementation enforces nothing of the sort: the only ability bound is `T: key`, and the only checks are `!registry.exists<T>()` and that the symbol is ASCII-printable [1](#0-0) . Because Move generic type parameters can be instantiated with any publicly-visible type regardless of the caller's package, any unprivileged address can call:

```
sui::coin_registry::new_currency<other_pkg::mod::TheirType>(registry, decimals, symbol, name, description, icon_url, ctx)
```

for a `TheirType` defined and published by someone else (as long as `TheirType` has the `key` ability), before the legitimate publisher gets around to registering it. This:
1. Claims the one-and-only `CurrencyKey<TheirType>` derived slot in the shared registry via `derived_object::claim` [2](#0-1) , so any subsequent, legitimate `new_currency<TheirType>()` (or `migrate_legacy_metadata<TheirType>`, which has the analogous `!registry.exists<T>()` guard [6](#0-5) ) permanently reverts with `ECurrencyAlreadyExists`/`ECurrencyAlreadyRegistered`.
2. Mints a fresh `TreasuryCap<TheirType>` via `coin::new_treasury_cap(ctx)` [7](#0-6)  that is fully controlled by the attacker and typed as `TreasuryCap<TheirType>`, with no witness or ownership proof over `TheirType` required — breaking the "exactly one treasury cap per coin type" invariant that the OTW-gated path (`new_currency_with_otw`) is designed to preserve.
3. Lets the attacker claim `MetadataCap<TheirType>` and set the currency's public name/symbol/description/icon_url, i.e., squat and permanently control the on-chain "official" metadata surfaced for `TheirType` in the canonical registry that wallets/explorers will query.

This exactly mirrors the Maia analog: an unprivileged actor populates a "presence" mapping (`getLocalTokenFromUnderlying` there, the `CurrencyKey<T>` derived-object slot here) through a public, unauthenticated entrypoint before the legitimate/privileged registration call runs, and the legitimate call's only defense is a redundant "already exists" check that the attacker satisfies first.

### Impact Explanation
- Permanent denial-of-service on canonical coin metadata registration for any coin type whose defining module has not yet called `new_currency`/`migrate_legacy_metadata`: the real issuer can never register `Currency<T>` afterward once squatted, since the derived object slot is a singleton and the guard aborts unconditionally. This is a "harmful smart-contract behavior" / permanent-lock-style outcome against the system coin registry, which is intended to be the source of truth surfaced to the entire ecosystem (wallets, explorers, DeFi integrations reading `sui::coin_registry::Currency<T>`).
- Worse, because `new_currency<T>` mints an independent `TreasuryCap<T>` with no OTW/witness proof, if `T` is ever a real, already-in-use coin type whose defining struct has `key` (or any type an attacker anticipates will later be used as a coin type), the attacker obtains a spurious `TreasuryCap<TheirType>` disconnected from the legitimate treasury cap, undermining the "only the defining module can mint" trust assumption and squatting the public metadata (name/symbol/icon) an unsuspecting user/wallet will trust as canonical.

### Likelihood Explanation
Any address can call `new_currency<T>` for any `key`-ability struct visible on-chain; no coins, capabilities, or governance approval are required — only knowledge of the target type's fully-qualified name, which becomes public the moment the target package is published (and can be watched via the mempool/package-publish transaction before the target module's own `init`/registration call executes in a later transaction, or is simply never gotten around to because it is optional/deferred). This mirrors the confirmed likelihood rationale in the original Maia report ("attacker would have to act between token deployment and adding it").

### Recommendation
Require a proof of ownership analogous to the OTW check for `new_currency<T>`, e.g. a witness/capability parameter created only by `T`'s defining module (mirroring `new_currency_with_otw`'s `is_one_time_witness` check), or restrict `new_currency` to require passing the module's `Publisher` object (`sui::package::Publisher`) verified against `TypeName::get<T>()`'s package address, so only the actual publisher of `T` can claim its `CurrencyKey<T>` slot and mint its `TreasuryCap<T>`.

### Proof of Concept
1. Publisher `P` publishes package `pkg` containing `public struct MYCOIN has key { id: UID }` (intending to later call `coin_registry::new_currency<MYCOIN>` themselves) but has not yet done so.
2. Attacker `A`, in a subsequent transaction, calls `sui::coin_registry::new_currency<pkg::mod::MYCOIN>(registry, 6, b"MYC".to_string(), b"MyCoin".to_string(), b"desc".to_string(), b"".to_string(), ctx)`.
3. This succeeds because only `MYCOIN: key` is required — no proof of ownership. `A` receives a `TreasuryCap<MYCOIN>` and later a `MetadataCap<MYCOIN>` via `finalize`, and the `CurrencyKey<MYCOIN>` derived slot in the shared `CoinRegistry` is now occupied.
4. When `P` later calls `coin_registry::new_currency<MYCOIN>(...)` (or `migrate_legacy_metadata<MYCOIN>`), the call reverts with `ECurrencyAlreadyExists`/`ECurrencyAlreadyRegistered` permanently, since `registry.exists<MYCOIN>()` is now `true` [8](#0-7) .

### Citations

**File:** crates/sui-framework/packages/sui-framework/sources/registries/coin_registry.move (L70-84)
```text
/// System object found at address `0xc` that stores coin data for all
/// registered coin types. This is a shared object that acts as a central
/// registry for coin metadata, supply information, and regulatory status.
public struct CoinRegistry has key { id: UID }

/// Store only object that enables more flexible coin data
/// registration, allowing for additional fields to be added
/// without changing the `Currency` structure.
public struct ExtraField(TypeName, vector<u8>) has store;

/// Key used to derive addresses when creating `Currency<T>` objects.
public struct CurrencyKey<phantom T>() has copy, drop, store;

/// Key used to store the legacy `CoinMetadata` for a `Currency`.
public struct LegacyMetadataKey() has copy, drop, store;
```

**File:** crates/sui-framework/packages/sui-framework/sources/registries/coin_registry.move (L170-173)
```text
/// Creates a new currency.
///
/// Note: This constructor has no long term difference from `new_currency_with_otw`.
/// This can be called from the module that defines `T` any time after it has been published.
```

**File:** crates/sui-framework/packages/sui-framework/sources/registries/coin_registry.move (L174-196)
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
```

**File:** crates/sui-framework/packages/sui-framework/sources/registries/coin_registry.move (L209-220)
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

**File:** crates/sui-framework/packages/sui-framework/sources/registries/coin_registry.move (L640-643)
```text
/// Check if coin data exists for the given type T in the registry.
public fun exists<T>(registry: &CoinRegistry): bool {
    derived_object::exists(&registry.id, CurrencyKey<T>())
}
```

**File:** crates/sui-framework/packages/sui-framework/sources/registries/coin_registry.move (L696-705)
```text
/// Internal macro to keep implementation between build and test modes.
macro fun migrate_legacy_metadata_impl<$T>(
    $registry: &mut CoinRegistry,
    $legacy: &CoinMetadata<$T>,
): Currency<$T> {
    let registry = $registry;
    let legacy = $legacy;

    assert!(!registry.exists<$T>(), ECurrencyAlreadyRegistered);
    assert!(is_ascii_printable!(&legacy.get_symbol().to_string()), EInvalidSymbol);
```
