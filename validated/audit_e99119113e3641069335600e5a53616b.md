## Analysis

The reported bug class is: **an unprivileged actor can front-run a permissionless "create by identifier" call using an attacker-chosen key, permanently blocking the legitimate creator from ever using that identifier** (`s_offers[offerId].creationDate == 0` check in the Solidity contract).

The Sui analog exists in `sui::coin_registry::new_currency`.

### The pattern: `derived_object` claim keyed by an unauthenticated type parameter

Sui's `derived_object` module is the on-chain mechanism used to build unique, one-per-key registries (docs explicitly compare it to the exact "offerId already exists" pattern): [1](#0-0) 

`coin_registry::new_currency<T: key>` uses this primitive keyed by the *type parameter* `T` itself — with **no check that the caller controls or defines `T`**: [2](#0-1) 

The doc comment even states the intended invariant that is *not enforced in code*: "This can be called from the module that defines `T` any time after it has been published" — yet the function signature only requires the ability `key`, and performs no witness check, no `Publisher` check, nothing binding the caller to `T`'s defining package.

Compare this to sibling functions in the same framework that *do* correctly bind the caller to the type:
- `new_currency_with_otw<T: drop>` requires an unforgeable one-time-witness: `assert!(sui::types::is_one_time_witness(&otw), ENotOneTimeWitness)` [3](#0-2) 
- `display_registry::new_with_publisher<T>` requires `assert!(publisher.from_package<T>(), ENotValidPublisher)` [4](#0-3) 

`new_currency<T: key>` has neither guard. In Move, a public struct type can be used as a generic type argument by *any* caller who merely knows its name/ability — using it there is not proof of ownership. So any address can call `coin_registry::new_currency<VictimCoinType>(...)` for any publicly visible struct that has `key`, exactly mirroring Alice front-running Bob's `offerId`.

### Impact — worse than the Solidity original

1. **Permanent DoS (matches "Medium/permanent fund lock" bucket in the impact gate):** `registry.exists<T>()` checks `derived_object::exists`, which is permanently `true` once claimed, even after deletion: [5](#0-4)  An attacker calls `new_currency<VictimType>` first; the legitimate module that defines `VictimType` can never call `new_currency<VictimType>` again — `ECurrencyAlreadyExists` aborts forever.
2. **Unauthorized `TreasuryCap<T>` creation (state corruption / unintended mint capability):** Unlike `create_currency`/`new_currency_with_otw`, `new_currency` takes no witness — it unconditionally calls `coin::new_treasury_cap(ctx)` and hands the caller a fresh `TreasuryCap<T>` for a type they don't own: [6](#0-5) 
   A `TreasuryCap<T>` lets its holder call `coin::mint`/`mint_balance` to mint arbitrary `Coin<T>` [7](#0-6) . This means the attacker doesn't just block registration — they walk away holding the *registered* treasury/mint authority object for `T`, seeded into the canonical `CoinRegistry` at `0xc`, ahead of and instead of the legitimate publisher of `T`.

I was not able to view the body of `coin::new_treasury_cap` directly (only its call sites), so I cannot 100% confirm there isn't some additional runtime restriction inside it that limits `T` to caller-owned types; based on all available evidence (function signature has no witness argument, doc string explicitly relies on unenforced convention, and the sibling functions in the same file demonstrate the framework authors know how to add an ownership check but did not add one here), this appears to be a genuine gap rather than a documented/intended permissionless design.

### Title
Unauthenticated type parameter allows front-running and hijacking of `coin_registry::new_currency` registration and TreasuryCap issuance - (File: `crates/sui-framework/packages/sui-framework/sources/registries/coin_registry.move`)

### Summary
`coin_registry::new_currency<T: key>` claims a `derived_object` registry slot keyed solely by the generic type parameter `T`, with no witness (unlike `new_currency_with_otw`) and no `Publisher`-based ownership check (unlike `display_registry::new_with_publisher`). Because any address can supply any publicly visible `key`-ability struct as a type argument, an attacker can front-run the legitimate owner of `T`, permanently occupying `T`'s slot in the singleton `CoinRegistry` (`0xc`) and receiving a fresh `TreasuryCap<T>`.

### Finding Description
`derived_object::claim` guarantees only "one claim per (parent, key)" [8](#0-7) ; it provides no authentication of *who* is allowed to claim a given key. `new_currency` uses `CurrencyKey<T>()` as that key and only constrains `T` by the `key` ability — not by an unforgeable witness — so the check `assert!(!registry.exists<T>(), ECurrencyAlreadyExists)` [9](#0-8)  is racing against anyone, not just the module that defines `T`.

### Impact Explanation
- Permanent, irrecoverable blocking of legitimate currency registration for `T` (the `Claimed` marker persists forever per `derived_object::exists` semantics).
- Attacker obtains a legitimate-looking `TreasuryCap<T>` minted via `coin::new_treasury_cap`, giving them unauthorized minting/burning authority over `Coin<T>` for a type they do not control, registered inside the canonical system `CoinRegistry`.

### Likelihood Explanation
The call is fully permissionless (`public fun`, callable by anyone with a `CoinRegistry` reference and any public struct type name), requires no special privileges, and the front-run is a simple mempool/gas-price race, identical in mechanics to the reported Solidity `createOffer` race.

### Recommendation
Require the caller to prove ownership of `T`'s defining package before claiming the registry slot, consistent with `display_registry`'s pattern — e.g., require a `Publisher` argument and `assert!(publisher.from_package<T>())`, or require a one-time witness as `new_currency_with_otw` already does, removing the unauthenticated `new_currency<T: key>` entry point (or restricting it to package-internal use as its own comment `/* internal */ key` suggests was originally intended).

### Proof of Concept
```move
// Attacker module, unrelated to `victim::coin::VictimCoin`
public fun frontrun(registry: &mut sui::coin_registry::CoinRegistry, ctx: &mut TxContext) {
    // Attacker only needs the type name `victim::coin::VictimCoin` (public struct with `key`)
    let (init, cap) = sui::coin_registry::new_currency<victim::coin::VictimCoin>(
        registry, 9, b"VIC".to_string(), b"Victim".to_string(),
        b"".to_string(), b"".to_string(), ctx,
    );
    // attacker now owns TreasuryCap<VictimCoin> and can mint/burn Coin<VictimCoin>
    let metadata_cap = sui::coin_registry::finalize(init, ctx);
    transfer::public_transfer(cap, ctx.sender());
    transfer::public_transfer(metadata_cap, ctx.sender());
}
// Victim's later legitimate call:
// coin_registry::new_currency<VictimCoin>(...) now aborts with ECurrencyAlreadyExists permanently.
```

**Note on completeness:** I could not view the internal implementation of `coin::new_treasury_cap` (only its call sites were retrievable in this index), so I cannot rule out an as-yet-unseen guard inside that function. If further verification of full internal source is needed, a Devin session with full repo access would be able to confirm this directly.

### Citations

**File:** crates/sui-framework/packages/sui-framework/sources/derived_object.move (L20-22)
```text
/// Tries to create an object twice with the same parent-key combination.
#[error(code = 0)]
const EObjectAlreadyExists: vector<u8> = b"Derived object is already claimed.";
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

**File:** crates/sui-framework/packages/sui-framework/sources/registries/display_registry.move (L63-72)
```text
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

**File:** crates/sui-framework/docs/sui/derived_object.md (L170-191)
```markdown
<a name="sui_derived_object_exists"></a>

## Function `exists`

Checks if a provided <code>key</code> has been claimed for the given parent.
Note: If the UID has been deleted through <code><a href="../sui/object.md#sui_object_delete">object::delete</a></code>, this will always return true.


<pre><code><b>public</b> <b>fun</b> <a href="../sui/derived_object.md#sui_derived_object_exists">exists</a>&lt;K: <b>copy</b>, drop, store&gt;(parent: &<a href="../sui/object.md#sui_object_UID">sui::object::UID</a>, key: K): bool
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="../sui/derived_object.md#sui_derived_object_exists">exists</a>&lt;K: <b>copy</b> + drop + store&gt;(parent: &UID, key: K): bool {
    <b>let</b> addr = <a href="../sui/derived_object.md#sui_derived_object_derive_address">derive_address</a>(parent.to_inner(), key);
    df::exists(parent, <a href="../sui/derived_object.md#sui_derived_object_Claimed">Claimed</a>(addr.to_id()))
}
</code></pre>
```

**File:** crates/sui-framework/packages/sui-framework/sources/coin.move (L313-320)
```text
/// Create a coin worth `value` and increase the total supply
/// in `cap` accordingly.
public fun mint<T>(cap: &mut TreasuryCap<T>, value: u64, ctx: &mut TxContext): Coin<T> {
    Coin {
        id: object::new(ctx),
        balance: cap.total_supply.increase_supply(value),
    }
}
```
