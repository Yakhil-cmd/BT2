### Title
Missing persistent position map silently defaults to empty, erasing debt or collateral after TTL expiry - (File: contracts/controller/src/storage/account.rs)

### Summary
Like `platform_get_resource_byname()` returning NULL that is then consumed as if valid, `get_debt_positions` and `get_supply_positions` treat an absent `ControllerKey::BorrowPositions`/`SupplyPositions` persistent entry as "no positions" instead of failing. Because each persistent key carries its own user TTL and position-map writes deliberately do not renew it (`write_side_map` calls `persistent.set` with no `extend_ttl`), a position map can archive while `AccountMeta` (written via `set_user`, which renews) remains live. Any subsequent call then reads a silently-empty map. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

### Finding Description
- `get_debt_positions`/`get_supply_positions` do `get_user(...).unwrap_or_else(|| Map::new(env))`: a missing/archived entry is indistinguishable from a genuinely empty position set.
- `get_user` renews TTL only when the value is present, and `renew_user_account` only extends keys that `has(key)` — nothing distinguishes "never existed" from "expired".
- `set_supply_positions`/`set_debt_positions` write without TTL renewal, so position maps can drift to shorter TTLs than `AccountMeta`, which is renewed on every `set_user` write and every `get_user` read of the meta key itself.
- Reachable path (insolvency): a borrower opens debt, lets the `BorrowPositions(account_id)` entry lapse while keeping `AccountMeta` alive (meta is renewed by unrelated account calls), then calls `withdraw`/`borrow` — risk evaluation iterates `get_debt_positions`, sees zero debt, computes infinite health factor, and releases collateral that should back outstanding debt. The pool's actual token cash is then drained against debt the controller no longer records.
- Symmetric path (frozen/lost funds): a lapsed `SupplyPositions` map makes a lender's collateral invisible; `withdraw` sees nothing to release while the shares' backing was already accounted, and `liquidate`/`clean_bad_debt` on that account miscompute positions. Even though the ledger entry may be restorable via `restore`, the contract itself performs no presence check or restore — the divergent meta/positions state is committed silently.

### Impact Explanation
Protocol insolvency: a borrower whose `BorrowPositions` entry archives can withdraw or borrow against collateral with an effectively debt-free account, leaving unbacked debt once the entry is restored or simply abandoning the NFT. Permanent freezing/loss of user funds: a lender whose `SupplyPositions` entry archives loses all claim to deposited shares through every user-facing path, since reads return an empty map rather than reverting.

### Likelihood Explanation
Medium. Soroban persistent entries expire independently at `TTL_BUMP_USER`; the code explicitly avoids renewing position-map TTL on writes, so the preconditions arise naturally for dormant accounts — exactly the leveraged/borrow positions most likely to be left untouched. The attacker only needs patience on their own account (no privilege, no third party), and the failure is silent rather than a fail-closed panic: state is mutated based on fabricated "empty" data.

### Recommendation
Fail closed on absence, mirroring the upstream fix ("validate the resource before dereference"). In `get_supply_positions`/`get_debt_positions`, distinguish "entry absent but `AccountMeta` exists" from "account never had positions" — e.g., panic with a dedicated error when `AccountMeta` is present but a position key that should exist is missing, or track a position-count/has-positions flag in `AccountMeta` so an empty map is provable. Alternatively, renew position-map TTL inside `write_side_map` and inside `renew_user_account` unconditionally for live accounts, keeping all four account keys on a single expiry schedule.

### Proof of Concept
1. User calls `controller.supply` + `borrow` for `(spoke_id, hub_asset)`; `AccountMeta` is written via `set_user` (TTL renewed), `BorrowPositions`/`SupplyPositions` via `write_side_map` (TTL not renewed).
2. Ledger advances past the position keys' TTL while the user (or delegate/liquidation-adjacent calls) keeps `AccountMeta` renewed; `env.storage().persistent().get(&ControllerKey::BorrowPositions(id))` returns `None` / archives.
3. User calls `controller.withdraw(account_id, [(hub_asset, 0 /* MeansAll */)])`; `get_debt_positions` returns `Map::new`, health-factor check over zero debt passes, collateral is paid out.
4. Result: tokens leave the pool while debt either remains recorded nowhere (permanent bad debt absorbed by suppliers) or reappears if the entry is later restored — either way, insolvency.

### Citations

**File:** contracts/controller/src/storage/account.rs (L62-73)
```rust
/// Returns raw supply positions, defaulting to an empty map.
pub(crate) fn get_supply_positions(
    env: &Env,
    account_id: u64,
) -> Map<HubAssetKey, AccountPositionRaw> {
    get_user(env, &ControllerKey::SupplyPositions(account_id)).unwrap_or_else(|| Map::new(env))
}

/// Returns raw debt positions, defaulting to an empty map.
pub(crate) fn get_debt_positions(env: &Env, account_id: u64) -> Map<HubAssetKey, DebtPositionRaw> {
    get_user(env, &ControllerKey::BorrowPositions(account_id)).unwrap_or_else(|| Map::new(env))
}
```

**File:** contracts/controller/src/storage/account.rs (L94-105)
```rust
fn write_side_map<V: TryFromVal<Env, Val> + IntoVal<Env, Val>>(
    env: &Env,
    key: &ControllerKey,
    map: &Map<HubAssetKey, V>,
) {
    let persistent = env.storage().persistent();
    if map.is_empty() {
        persistent.remove(key);
    } else {
        persistent.set(key, map);
    }
}
```

**File:** contracts/controller/src/storage/account.rs (L258-272)
```rust
/// Renews user TTL for each existing account entry; does not renew the NFT.
pub(crate) fn renew_user_account(env: &Env, account_id: u64) {
    let persistent = env.storage().persistent();
    let keys = [
        ControllerKey::AccountMeta(account_id),
        ControllerKey::SupplyPositions(account_id),
        ControllerKey::BorrowPositions(account_id),
        ControllerKey::Delegates(account_id),
    ];
    for key in &keys {
        if persistent.has(key) {
            renew_user_key(env, key);
        }
    }
}
```

**File:** contracts/controller/src/storage/protocol.rs (L189-201)
```rust
/// Reads a persistent value and renews user TTL only when present.
pub(super) fn get_user<V: TryFromVal<Env, Val>>(env: &Env, key: &ControllerKey) -> Option<V> {
    let value: Option<V> = env.storage().persistent().get(key);
    if value.is_some() {
        renew_persistent_key(env, key, TTL_THRESHOLD_USER, TTL_BUMP_USER);
    }
    value
}

/// Writes a persistent value and renews user TTL.
pub(super) fn set_user<V: IntoVal<Env, Val>>(env: &Env, key: &ControllerKey, value: &V) {
    env.storage().persistent().set(key, value);
    renew_persistent_key(env, key, TTL_THRESHOLD_USER, TTL_BUMP_USER);
```
