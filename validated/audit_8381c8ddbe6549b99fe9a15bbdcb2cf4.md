## Analog Found

### Title
Unauthenticated `coin_registry::new_currency<T>` lets any caller front-run and permanently squat the canonical `Currency<T>` registry slot for a coin type it does not own - (File: `crates/sui-framework/packages/sui-framework/sources/registries/coin_registry.move`)

### Summary
The Velodrome bug is a missing-identity-binding griefing pattern: `proposalHash()` doesn't bind the caller/proposer, so anyone can front-run a legitimate proposal and then cancel it, permanently consuming the "slot" the legitimate actor wanted. The same root cause — a public, permissionless entry point that claims a deterministic, uniqueness-guaranteed identity slot without binding that claim to proof of ownership over the underlying identity — exists in Sui's `sui::coin_registry` module, and there it is *worse* than the original bug because the squatted slot can never be reclaimed.

### Finding Description
`sui::derived_object::claim` reserves a deterministic `(parent, key)` address forever: once claimed, `derived_object::exists` returns `true` permanently, even after the derived object is deleted [1](#0-0) , as explicitly confirmed by the framework's own test `test_marker_exists_even_after_deletion` [2](#0-1) . There is no "unclaim" or admin override anywhere in the module.

`sui::coin_registry::new_currency<T>` uses this primitive to reserve the canonical `Currency<T>` slot (`derived_object::claim(&mut registry.id, CurrencyKey<T>())`) inside the global, shared `CoinRegistry` object at `0xc`: [3](#0-2) 

Unlike the OTW-gated path (`new_currency_with_otw`, which requires a genuine one-time witness proven via `sui::types::is_one_time_witness`), `new_currency<T: key>` performs **no ownership check at all** over `T` — no `Publisher`, no `TreasuryCap`, no OTW. Its own doc comment only *assumes* callers will self-restrict ("This can be called from the module that defines `T`"), but Move's generic instantiation rules do not enforce that assumption: any address can invoke `new_currency<T>` for any already-published type `T` that merely has the `key` ability, regardless of who defined it [4](#0-3) .

By contrast, the sibling module `sui::display_registry` gets this right by requiring an `internal::Permit<T>` or a `Publisher` matching `T`'s package before claiming a derived slot [5](#0-4) , showing the intended, correctly-bound pattern that `coin_registry::new_currency` fails to apply.

### Impact Explanation
An attacker who observes (or predicts) a coin type `T` about to be registered can front-run the legitimate project by calling `new_currency<T>(registry, ...)` with spoofed name/symbol/icon metadata, then `finalize`/share it, permanently claiming the `CurrencyKey<T>` derived address. Because the claim marker in `derived_object` is irreversible:
- The legitimate publisher's later, properly OTW-gated `new_currency_with_otw<T>` → `finalize_registration<T>` flow will abort forever at `derived_object::claim` with `EObjectAlreadyExists` [6](#0-5) , so the real project can never publish its official `Currency<T>` in the canonical, deterministic registry slot that wallets/explorers/indexers are meant to treat as the single source of truth for type `T`.
- The attacker's spoofed `Currency<T>` (with attacker-chosen `name`/`symbol`/`icon_url`) permanently occupies that trusted, well-known address, enabling persistent metadata-spoofing/phishing against the type.

This is harmful, unrecoverable smart-contract behavior stemming from unauthorized object creation in a public system registry — a state-corruption analog of the report's griefing pattern, but permanent rather than merely a temporary blocker.

### Likelihood Explanation
The call requires only: (1) a reference to the public shared `CoinRegistry` object, and (2) any type `T` with the `key` ability that is already visible on-chain (including third-party or not-yet-fully-initialized coin modules). No capability, signature, or proof-of-ownership over `T` is required. This makes it trivially triggerable by an unprivileged, unauthenticated caller with ordinary gas-price front-running, matching the "unprivileged-user" attacker model. The main caveat, honestly noted: this specific function is only reachable when the coin's generic witness/marker type `T` also carries the `key` ability (typical OTW witnesses used by `new_currency_with_otw` normally only need `drop`), so the practical blast radius depends on how many coin-type designs choose the `new_currency<T: key>` (non-OTW, "dynamically created currencies") path documented in the module. I was not able to fully verify, within available context, how commonly this "dynamic" path (versus the OTW path) is used by real coin deployments in production, since that depends on external application code not present in this repository's indexed contents.

### Recommendation
Require proof of ownership over `T` in `new_currency`, mirroring `display_registry::new_with_publisher` (i.e., require a `Publisher` matching `T`'s package, or otherwise gate the call the same way `new_currency_with_otw` is gated). This binds the registry-slot claim to the actual owner of `T`, closing the missing-identity-binding gap — directly analogous to the report's fix of adding `proposer` to `proposalHash()`.

### Proof of Concept
```move
// Attacker observes module `victim::HERO` has been published (struct HERO has key {}),
// but victim has not yet registered it in the CoinRegistry.

// 1. Attacker front-runs with a higher gas price:
let (init, treasury_cap) = coin_registry::new_currency<victim::HERO>(
    &mut registry, 6,
    b"HERO".to_string(), b"Legit Hero Token".to_string(),
    b"official description".to_string(), b"https://spoofed-icon".to_string(),
    ctx,
);
let _cap = coin_registry::finalize(init, ctx); // shares malicious Currency<HERO>
                                                // at the canonical derived address

// 2. Victim later runs the intended, OTW-gated flow:
let (init2, real_cap) = coin_registry::new_currency_with_otw(otw, 6, ..., ctx);
coin_registry::finalize(init2, ctx); // transfers Currency<HERO> as TTO to registry

// 3. Anyone calls finalize_registration<HERO> to promote it to the canonical slot:
coin_registry::finalize_registration<victim::HERO>(&mut registry, receiving, ctx);
// ABORTS with EObjectAlreadyExists inside derived_object::claim — permanently,
// because the (registry, CurrencyKey<HERO>) slot was already claimed by the attacker
// and derived_object markers can never be reclaimed.
```

### Citations

**File:** crates/sui-framework/packages/sui-framework/sources/derived_object.move (L37-51)
```text
/// Claim a deterministic UID, using the parent's UID & any key.
public fun claim<K: copy + drop + store>(parent: &mut UID, key: K): UID {
    let addr = derive_address(parent.to_inner(), key);
    let id = addr.to_id();
    assert!(!df::exists(parent, Claimed(id)), EObjectAlreadyExists);
    df::add(parent, Claimed(id), ClaimedStatus::Reserved);
    object::new_uid_from_hash(addr)
}

/// Checks if a provided `key` has been claimed for the given parent.
/// Note: If the UID has been deleted through `object::delete`, this will always return true.
public fun exists<K: copy + drop + store>(parent: &UID, key: K): bool {
    let addr = derive_address(parent.to_inner(), key);
    df::exists(parent, Claimed(addr.to_id()))
}
```

**File:** crates/sui-framework/packages/sui-framework/tests/derived_object_tests.move (L66-81)
```text
#[test]
fun test_marker_exists_even_after_deletion() {
    let mut ctx = tx_context::dummy();
    let mut registry = Registry { id: ctx.new() };

    let key = b"persist_test".to_string();
    let derived_uid = derived_object::claim(&mut registry.id, key);

    assert!(derived_object::exists(&registry.id, key));

    derived_uid.delete();

    assert!(derived_object::exists(&registry.id, key));

    destroy(registry);
}
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

**File:** crates/sui-framework/packages/sui-framework/sources/registries/coin_registry.move (L353-389)
```text
public fun finalize_registration<T>(
    registry: &mut CoinRegistry,
    currency: Receiving<Currency<T>>,
    _ctx: &mut TxContext,
) {
    // 1. Consume Currency
    // 2. Re-create it with a "derived" address.
    let Currency {
        id,
        decimals,
        name,
        symbol,
        description,
        icon_url,
        supply,
        regulated,
        treasury_cap_id,
        metadata_cap_id,
        extra_fields,
    } = transfer::receive(&mut registry.id, currency);
    id.delete();

    // Now, create the derived version of the coin currency.
    transfer::share_object(Currency {
        id: derived_object::claim(&mut registry.id, CurrencyKey<T>()),
        decimals,
        name,
        symbol,
        description,
        icon_url,
        supply,
        regulated,
        treasury_cap_id,
        metadata_cap_id,
        extra_fields,
    })
}
```

**File:** crates/sui-framework/packages/sui-framework/sources/registries/display_registry.move (L54-72)
```text
public fun new<T>(
    registry: &mut DisplayRegistry,
    _: internal::Permit<T>,
    ctx: &mut TxContext,
): (Display<T>, DisplayCap<T>) {
    let (display, cap) = new_display<T>(registry, ctx);
    (display, cap)
}

/// Create a new display object using the `Publisher` object.
public fun new_with_publisher<T>(
    registry: &mut DisplayRegistry,
    publisher: &mut Publisher,
    ctx: &mut TxContext,
): (Display<T>, DisplayCap<T>) {
    assert!(publisher.from_package<T>(), ENotValidPublisher);
    let (display, cap) = new_display<T>(registry, ctx);
    (display, cap)
}
```
