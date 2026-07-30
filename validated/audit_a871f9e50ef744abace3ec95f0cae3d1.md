### Title
Unrestricted `coin_registry::new_currency<T>` allows any caller to permanently squat a legitimate coin type's registry slot — ([File: crates/sui-framework/packages/sui-framework/sources/registries/coin_registry.move])

### Summary
`sui::coin_registry::new_currency<T: key>` is the on-chain analog of the AgentRegistryCore bug: it lets *any* caller "mint" (claim) the canonical registry record for an arbitrary identifier — here, a Move type `T` — without proving ownership of that type, and the claim is permanent and cannot be reclaimed. This mirrors the report's root cause exactly: unrestricted creation of an owner-bound record for a caller-chosen ID, exploitable by front-running the legitimate owner, with no recourse afterward.

### Finding Description
`CoinRegistry` is Sui's production system object at `0xc`, and it uses `sui::derived_object` to give each coin type `T` a single, deterministic `Currency<T>` slot keyed by `CurrencyKey<T>()`: [1](#0-0) 

`derived_object::claim` enforces "one claim per (parent, key)" and provides **no un-claim / reclaim path** — the doc explicitly states "Supports reclaiming? ❌ Currently no": [2](#0-1) 

The permissionless entry point `new_currency<T: /* internal */ key>` only requires `T: key` — the `/* internal */` annotation is a comment, not an enforced restriction. Nothing in the function checks that the caller published, owns, or otherwise controls `T`; any Move code that can name a public `key`-able type `T` can call it for any registry that has not yet registered `T`: [3](#0-2) 

The only guard is `assert!(!registry.exists<T>(), ECurrencyAlreadyExists)` — this prevents double-registration but does **not** restrict *who* may be the first to register, which is precisely the AgentRegistryCore flaw ("allows anyone to mint an `agentID` for the desired owner... prior commitment... front run"). Compare this to `new_currency_with_otw<T: drop>`, which correctly gates creation with a one-time-witness check: [4](#0-3) 

`new_currency` has no equivalent proof-of-ownership check for `T`.

### Impact Explanation
An attacker can observe (or simply predict, since coin type names are public and often used in test networks/pre-announcements) a coin type `T` that a legitimate project is about to register in the `CoinRegistry`, and front-run them by calling `new_currency<T>()` first with empty/garbage `name`, `symbol`, `description`, `icon_url`. Because `derived_object::claim` marks the `(registry, CurrencyKey<T>())` slot as permanently `Reserved`, the legitimate publisher's own subsequent `new_currency<T>` or `finalize_registration<T>` call will forever abort with `ECurrencyAlreadyExists`/collide with the claimed derived address. This is a **permanent** denial of the canonical, system-wide coin metadata/registry entry for that type — matching the "harmful smart-contract behavior" / permanent-lock class of impact for a production Sui system object (`0xc`), since every future indexer, wallet, or DeFi integration that queries `CoinRegistry` for `T`'s canonical `Currency<T>` will see attacker-controlled garbage metadata that can never be corrected or reclaimed by the real issuer.

A related, more severe concern is that `new_currency<T>` also mints a brand-new `TreasuryCap<T>` via `coin::new_treasury_cap(ctx)` for the attacker, without any witness/OTW check tying it to the real publisher of `T`. If this treasury cap is capable of independently minting spendable `Coin<T>` (same nominal type as the genuine coin), this could escalate to fund forgery. I was not able to verify the internals of `coin::new_treasury_cap` / its `Supply<T>` semantics in the time available, so this escalation is flagged as **unconfirmed** and should be investigated separately — the DoS/permanent-squatting impact above is the portion of this finding I can confirm from the code shown.

### Likelihood Explanation
High. `new_currency` is a `public fun` on the shared, well-known `CoinRegistry` object at `0xc`, callable by anyone with no capability, admin, or ownership check on `T`. The attack requires only observing a pending/likely coin type name and submitting a transaction before the legitimate publisher — a classic front-running scenario, identical in mechanics to the original AgentRegistryCore report.

### Recommendation
1. Restrict `new_currency<T>` to require proof of ownership of `T`, e.g., only allow it to run from within the module that defines `T` (module-scoped by publishing address check via `TypeName`), or require passing the type's `Publisher`/`TreasuryCap<T>` as proof, similar to how `display_registry::new_with_publisher` requires `publisher.from_package<T>()`.
2. Alternatively, require an OTW for all `new_currency` paths (as already done for `new_currency_with_otw`), eliminating the un-gated path entirely.
3. Consider adding a reclaim/override mechanism gated by proof-of-ownership so that a squatted slot with garbage metadata can be corrected by the legitimate publisher even if an attacker claimed it first.

### Proof of Concept
1. Publisher A prepares to publish a package defining `struct MYCOIN has key { ... }` and intends to call `coin_registry::new_currency<MYCOIN>(...)` after publishing.
2. Attacker observes the pending publish transaction (or the type name from A's source/announcement) in the mempool/public info.
3. Attacker submits `coin_registry::new_currency<MYCOIN>(registry, 0, b"", b"", b"", b"", ctx)` in a transaction that lands before A's registration transaction.
4. `derived_object::claim(&mut registry.id, CurrencyKey<MYCOIN>())` succeeds for the attacker, permanently marking the slot `Reserved`.
5. A's later call to `new_currency<MYCOIN>` (or `finalize_registration<MYCOIN>`) now fails `ECurrencyAlreadyExists` / cannot claim the derived address — permanently, with no recovery mechanism, corrupting the canonical on-chain metadata record for `MYCOIN`.

### Citations

**File:** crates/sui-framework/packages/sui-framework/sources/registries/coin_registry.move (L80-81)
```text
/// Key used to derive addresses when creating `Currency<T>` objects.
public struct CurrencyKey<phantom T>() has copy, drop, store;
```

**File:** crates/sui-framework/packages/sui-framework/sources/registries/coin_registry.move (L170-202)
```text
/// Creates a new currency.
///
/// Note: This constructor has no long term difference from `new_currency_with_otw`.
/// This can be called from the module that defines `T` any time after it has been published.
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
