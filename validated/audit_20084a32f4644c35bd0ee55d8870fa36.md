### Title
Expired position-map entries are read as empty maps, letting `clean_bad_debt` socialize debt and destroy an account whose collateral still exists - (contracts/controller/src/storage/account.rs)

### Summary
CVE-2017-15107 is a false proof-of-non-existence bug: a synthesized NSEC record "proved" a hostname did not exist when it did. The analog in the controller is the missing-entry-is-empty pattern for account position maps. `get_supply_positions` and `get_debt_positions` return `Map::new(env)` when the persistent `SupplyPositions(account_id)` / `BorrowPositions(account_id)` entries are absent, so an expired (but restorable) position map is indistinguishable from "account has no collateral." Permissionless `clean_bad_debt` then evaluates the insolvency gate against a phantom zero collateral total and deletes the account and its NFT while the pool-side supply shares still exist.

### Finding Description
`try_get_account` requires only `AccountMeta` and a resolvable NFT owner; the two position maps are loaded with a default-empty fallback rather than failing closed:

- `get_supply_positions` → `get_user(...).unwrap_or_else(|| Map::new(env))` — `contracts/controller/src/storage/account.rs:63-73`
- `try_get_account` assembles meta + owner + those maps — `storage/account.rs:153-162`

TTL discipline is asymmetric: docs and code state that metadata reads/writes renew their own TTL while position-map writes do not, and `account_exists(id)` explicitly "checks and extends only `AccountMeta(id)`" — it does not prove or renew the position maps (`skills/xoxno-lending-contracts/abi.md`, `storage/account.rs:1-2`). Once a `SupplyPositions` entry expires past its live window while `AccountMeta` and the NFT stay live (e.g., via keepers calling `account_exists`/`renew_account`, or `repay` writing only the debt side per `persist_account_positions` with `PositionSides::Debt` in `positions/mod.rs:153-170`), every load of that account sees `supply_positions` as empty.

`socialize_bad_debt` then computes `total_collateral = 0` over the empty map, and `is_socializable_bad_debt(debt, 0)` trivially returns true for any live debt (`positions/liquidation/curve.rs:25-27`, `positions/liquidation/mod.rs:212-238`). `execute_bad_debt_cleanup` reclassifies the *map's* (empty) collateral, writes off the debt against the pool's supply index, removes the account entries, and burns the NFT — while the real supply shares remain inside the pool's `supplied` totals with no claimant.

The same pattern lets the owner trigger it: any `withdraw`/`repay`-family call loaded during the expiry window sees the position as non-existent and `cleanup_account_if_empty` removes the account (`persist_account_positions` with `remove_if_empty`, `positions/mod.rs:167-169`).

### Impact Explanation
Two harms, both reachable by an unprivileged caller when only the supply map has lapsed:

1. Permanent freezing/theft of user funds: the victim's collateral shares remain booked in pool `supplied` totals but the only key able to claim them (the account's position map + NFT) is destroyed via `clean_bad_debt` or empty-account cleanup. There is no endpoint to resurrect an account id — token ids are never reused and `burn` is controller-only (`contracts/position-nft/README.md`).
2. Protocol insolvency accounting: `clean_bad_debt` applies a supply-index write-down sized to the recorded debt, but the stranded collateral shares are not reclassified as revenue (cleanup only reclassifies shares present in the map), leaving `supplied`/`cash`/`borrowed` inconsistent with any recoverable claim.

### Likelihood Explanation
The trigger is ordinary TTL expiry, not attacker action. The protocol documents that `repay` writes only the debt side and does not remove an empty account, that position-map writes do not renew their own TTL, and that `account_exists` renews only `AccountMeta`. An account whose debt stays open (so keepers/`repay`/`clean_bad_debt` attempts renew meta and the debt map) but whose supply map is never read or written can have exactly the asymmetric expiry required — most naturally on accounts being kept alive for debt servicing while their collateral entry goes stale. The attacker path is then a single `clean_bad_debt(caller, account_id)` call, which is permissionless, callable during global pause, and bypasses listing flags (INV-LIQ-04, INV-HALT-02).

### Recommendation
Fail closed on the proof-of-non-existence path: distinguish "entry absent" from "position empty." `get_supply_positions`/`get_debt_positions` should not silently default to an empty map for an account that passed the meta+owner existence check; `socialize_bad_debt` and `cleanup_account_if_empty` should require positively-loaded (non-defaulted) maps, or at minimum refuse to run when a position-map key is expired-but-restorable. Alternatively, renew `SupplyPositions`/`BorrowPositions` TTLs wherever `AccountMeta` is renewed (`renew_account`, `account_exists`, `repay`) so the maps cannot lapse while the account exists.

### Proof of Concept
1. Victim supplies collateral in market A and borrows in market B (two maps written, meta live).
2. Over time only `AccountMeta` and `BorrowPositions` are touched (`repay`, `account_exists`, keeper `renew_account`); `SupplyPositions(id)` expires past its live TTL.
3. Debt stays outstanding. Attacker calls `controller.clean_bad_debt(attacker, account_id)`.
4. `try_get_account` returns `Some(account)` with `supply_positions = Map::new`. `calculate_account_risk_totals` yields `total_collateral = 0`, `total_debt > 0`; `is_socializable_bad_debt` passes.
5. `execute_bad_debt_cleanup` socializes the debt, deletes all account entries, and burns the NFT. The victim's collateral shares remain in pool `supplied` but are permanently unclaimable.

Caveat: this assumes expired-but-unrestored persistent entries read as `None` under `get_user` rather than trapping. If the host traps on expired-entry reads instead, the path reverts rather than misbehaving; that behavior could not be confirmed from the indexed sources, but the default-empty fallback means there is no defense if it reads as absent. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** contracts/controller/src/storage/account.rs (L63-73)
```rust
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

**File:** contracts/controller/src/storage/account.rs (L153-162)
```rust
pub(crate) fn try_get_account(env: &Env, account_id: u64) -> Option<Account> {
    let meta = try_get_account_meta(env, account_id)?;
    let owner = try_account_owner(env, account_id)?;
    Some(account_from_parts(
        owner,
        meta,
        get_supply_positions(env, account_id),
        get_debt_positions(env, account_id),
    ))
}
```

**File:** contracts/controller/src/positions/liquidation/mod.rs (L212-243)
```rust
fn socialize_bad_debt(env: &Env, account_id: u64, gate: BadDebtGate) {
    let mut cache = Context::new(env);
    let account = storage::get_account(env, account_id);

    assert_with_error!(
        env,
        !account.borrow_positions.is_empty(),
        CollateralError::DebtPositionNotFound
    );

    let totals = risk::calculate_account_risk_totals(
        env,
        &mut cache,
        &account.supply_positions,
        &account.borrow_positions,
    );

    let admits = match gate {
        BadDebtGate::DustCapped => {
            is_socializable_bad_debt(totals.total_debt, totals.total_collateral)
        }
        BadDebtGate::InsolventOnly => totals.total_debt > totals.total_collateral,
    };
    assert_with_error!(env, admits, CollateralError::CannotCleanBadDebt);

    bad_debt::execute_bad_debt_cleanup(env, &mut cache, account_id, &account, &totals);
}

/// Socializes insolvent debt when remaining collateral is at or below the dust cap.
pub(crate) fn clean_bad_debt_standalone(env: &Env, account_id: u64) {
    socialize_bad_debt(env, account_id, BadDebtGate::DustCapped);
}
```

**File:** contracts/controller/src/positions/liquidation/curve.rs (L25-27)
```rust
pub(crate) fn is_socializable_bad_debt(total_debt: Wad, total_collateral: Wad) -> bool {
    total_debt > total_collateral && total_collateral <= Wad::from(BAD_DEBT_USD_THRESHOLD)
}
```

**File:** contracts/controller/src/positions/mod.rs (L153-170)
```rust
pub(crate) fn persist_account_positions(
    env: &Env,
    account_id: u64,
    account: &Account,
    sides: PositionSides,
    remove_if_empty: bool,
) {
    if sides != PositionSides::Debt {
        storage::set_supply_positions(env, account_id, &account.supply_positions);
    }
    if sides != PositionSides::Supply {
        storage::set_debt_positions(env, account_id, &account.borrow_positions);
    }
    storage::renew_user_account(env, account_id);
    if remove_if_empty {
        account::cleanup_account_if_empty(env, account, account_id);
    }
}
```

**File:** skills/xoxno-lending-contracts/abi.md (L65-70)
```markdown
- `account_exists(id)` checks and extends only `AccountMeta(id)`. It does not
  prove that supply maps, borrow maps, delegates, or NFT storage are live.
  Before a privileged action, also validate NFT ownership and
  `get_account_attributes`.
- `get_health_factor(id)` returns WAD and uses `i128::MAX` when there is no
  debt or no account.
```
