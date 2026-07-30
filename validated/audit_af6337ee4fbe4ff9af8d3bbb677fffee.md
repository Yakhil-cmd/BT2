### Title
Front-runnable Display V1→V2 migration lets any Publisher holder permanently hijack another type's Display metadata - (File: `crates/sui-framework/packages/sui-framework/sources/registries/display_registry.move`)

### Summary
`sui::display_registry::system_migration` — the framework's one-time bulk migrator that seeds V2 `Display<T>` objects from legacy V1 data — silently no-ops if a `Display<T>` derived object already exists for `T`, exactly the "skip-if-already-registered" pattern described in the external report. Because the derived-object slot for `T` can also be claimed by *any* caller who can satisfy `Publisher::from_package<T>()` via `new_with_publisher`, an attacker can pre-claim the slot for a type they do not otherwise control and permanently block the legitimate migration, walking away with exclusive control of that type's on-chain Display metadata.

### Finding Description
`system_migration<T>` is the only path meant to seed the canonical, system-verified V2 `Display<T>` for a type when migrating off the legacy `sui::display::Display<T>`: [1](#0-0) 

Notice the guard: `if (derived_object::exists(&registry.id, key)) return;` — a graceful, **silent** skip rather than an abort. This mirrors the reported anti-pattern precisely: a privileged "migrate" operation silently no-ops if the target slot is already occupied.

The slot for `DisplayKey<T>` can be claimed *before* the system script runs, by any account holding a `Publisher` object that passes `from_package<T>()`: [2](#0-1) [3](#0-2) 

`Publisher` is a transferable object (`has key, store`) and `from_package<T>` only checks that `T` originates from the same package as the `Publisher`, not that the caller is the "intended" owner of that specific type/module: [4](#0-3) 

So any address that legitimately holds (or acquires via trade) *some* `Publisher` object minted anywhere in a multi-module package can call `new_with_publisher<T>` for **any** type `T` defined in that package — including types whose display migration hasn't happened yet — and claim the `derived_object` slot with attacker-chosen (or empty) fields and an attacker-owned `DisplayCap<T>`.

Once claimed, the authoritative `system_migration<T>` call (run once by the `SystemMigrationCap` holder to backfill real V1 field data) hits the `derived_object::exists` check and returns without ever writing the legacy fields, and without any way to retroactively fix the record — there is no admin override to overwrite an already-derived `Display<T>`.

### Impact Explanation
This is "harmful smart-contract behavior" (per the Sui allowed-impact list) rather than direct fund theft: an attacker can permanently seize control of the canonical V2 `Display` object for a type they don't actually govern, holding the only `DisplayCap<T>` and thereby controlling `name`, `image_url`, `description`, and other display fields shown by wallets, explorers, and marketplaces for every object of that type. This enables persistent spoofing/phishing of NFT/asset metadata at the framework-registry level, and permanently strands the type's legitimate legacy V1 Display data (it can never be migrated, since `system_migration` will forever no-op for that `T`). This is a state-corruption outcome baked into system framework code (not application code), so it affects the shared, canonical `DisplayRegistry` object used ecosystem-wide.

### Likelihood Explanation
Exploitation requires only:
1. Holding any `Publisher` object minted from the same package as the target type `T` (achievable since `Publisher` is store-transferable and tradable, and many packages mint multiple `Publisher`s across modules), and
2. Submitting `new_with_publisher<T>` (or `migrate_v1_to_v2<T>`) before the one-time, presumably batched `system_migration<T>` transaction executes for that specific type.

Since the framework's migration is a bulk, per-type operation performed by an off-chain script issuing many separate `system_migration<T>` calls (not one atomic transaction covering every type at once), there is a real window in which an unprivileged (but Publisher-holding) party can race a specific `T` before its migration call lands.

### Recommendation
- Make `system_migration<T>` abort (not silently return) if the slot is already claimed, and expose a privileged, `SystemMigrationCap`-gated overwrite/adopt path so genuine legacy state is never dropped silently.
- Tighten `Publisher::from_package<T>` (or add a stricter check in `display_registry`) to require module-level ownership matching `T`'s defining module, not merely package-level matching, closing the "any Publisher in the package can claim any type's Display" gap.
- Consider pausing/gating `new`, `new_with_publisher`, and `migrate_v1_to_v2` for types pending system migration, or running the full migration atomically before enabling permissionless claim paths — directly analogous to the reported fix of pausing user-facing entrypoints until migration completes.

### Proof of Concept
The existing test suite already demonstrates the mechanics (not as an attack, but confirming the guard behavior) — `migrate_twice_returns_silently` shows `system_migration` performs a real state write only the first time and silently no-ops thereafter: [5](#0-4) 

An attacker analog would be: acquire/hold a `Publisher` from package `P` (which also defines target type `T`, not yet migrated) → call `registry.new_with_publisher<T>(&mut publisher, ctx)` to claim `DisplayKey<T>` and receive `DisplayCap<T>` → later, when the operator submits `registry.system_migration<T>(&migration_cap, real_keys, real_values, ctx)`, the `derived_object::exists` check causes it to return immediately, leaving the attacker's empty/attacker-controlled `Display<T>` and `DisplayCap<T>` as the permanent, unrecoverable V2 record for `T`.

**Uncertainty:** I could not verify the exact off-chain orchestration/atomicity of the one-time system migration script (e.g., whether all `system_migration<T>` calls for every legacy type are batched into a single atomic transaction or executed as many separate transactions), which affects how wide the front-running window actually is in production. This detail lives outside the indexed Move/Rust source and would need to be confirmed by inspecting Mysten's migration tooling/runbooks, which are not fully covered in this index.

### Citations

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

**File:** crates/sui-framework/packages/sui-framework/sources/registries/display_registry.move (L124-145)
```text
/// Allow the `SystemMigrationCap` holder to create display objects with supplied
/// values. The migration is performed once on launch of the DisplayRegistry,
/// further migrations will have to be performed for each object, and will only
/// be possible until legacy `display` methods are finally deprecated.
public fun system_migration<T: key>(
    registry: &mut DisplayRegistry,
    _: &SystemMigrationCap,
    keys: vector<String>,
    values: vector<String>,
    _ctx: &mut TxContext,
) {
    let key = DisplayKey<T>();

    // Gracefully return to avoid batching issues if someone migrates before our script.
    if (derived_object::exists(&registry.id, key)) return;

    transfer::share_object(Display<T> {
        id: derived_object::claim(&mut registry.id, key),
        fields: vec_map::from_keys_values(keys, values),
        cap_id: option::none(),
    });
}
```

**File:** crates/sui-framework/packages/sui-framework/sources/registries/display_registry.move (L191-204)
```text
fun new_display<T>(
    registry: &mut DisplayRegistry,
    ctx: &mut TxContext,
): (Display<T>, DisplayCap<T>) {
    let key = DisplayKey<T>();
    assert!(!derived_object::exists(&registry.id, key), EDisplayAlreadyExists);
    let cap = DisplayCap<T> { id: object::new(ctx) };
    let display = Display<T> {
        id: derived_object::claim(&mut registry.id, key),
        fields: vec_map::empty(),
        cap_id: option::some(cap.id.to_inner()),
    };
    (display, cap)
}
```

**File:** crates/sui-framework/packages/sui-framework/sources/package.move (L83-87)
```text
public struct Publisher has key, store {
    id: UID,
    package: String,
    module_name: String,
}
```

**File:** crates/sui-framework/packages/sui-framework/tests/registries/display_registry_tests.move (L184-222)
```text
#[test]
fun migrate_twice_returns_silently() {
    test_tx!(|registry, scenario| {
        scenario.next_tx(@0x5);
        let cap = take_migration_cap(scenario);
        registry.system_migration<MyKeyOnlyType>(
            &cap,
            vector[DEMO_NAME_KEY.to_string()],
            vector[DEMO_NAME_VALUE.to_string()],
            scenario.ctx(),
        );
        let effects = scenario.next_tx(@0x5);

        // we created Display for `MyKeyOnlyType`
        assert_eq!(effects.shared().length(), 1);
        assert_eq!(effects.created().length(), 1);

        // try to migrate again, should have no object creations.
        registry.system_migration<MyKeyOnlyType>(
            &cap,
            vector[],
            vector[],
            scenario.ctx(),
        );
        let effects = scenario.next_tx(@0x5);

        assert_eq!(effects.shared().length(), 0);
        assert_eq!(effects.created().length(), 0);

        // We should have the state of the first migration.
        let display = scenario.take_shared<Display<MyKeyOnlyType>>();
        assert_eq!(display.fields().length(), 1);
        assert_eq!(*display.fields().get(&DEMO_NAME_KEY.to_string()), DEMO_NAME_VALUE.to_string());

        test_scenario::return_shared(display);

        cap.destroy_system_migration_cap();
    });
}
```
