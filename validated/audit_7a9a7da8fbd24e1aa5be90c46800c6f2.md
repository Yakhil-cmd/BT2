### Title
Supply-index floor clamp resurrects wiped-out supplier claims, draining the next depositor's cash - (File: contracts/pool/src/interest.rs)

### Summary
The kernel bug class is *deriving live state from an object that is actually dead/negative* (`nfs_d_automount` used a negative dentry as if it had a real inode). The analog in XOXNO Lending is `apply_bad_debt_to_supply_index` in `contracts/pool/src/interest.rs`: when socialized bad debt covers the entire supplied value, the reduction factor is zero but the new `supply_index` is clamped **up** to `SUPPLY_INDEX_FLOOR_RAW` (`RAY/1000`) instead of zero [1](#0-0) . A fully wiped supply book is therefore treated as a live book: every wiped supplier's `scaled_amount` retains a positive floor-denominated token claim that pays out against whatever cash arrives in the pool next — i.e., subsequent depositors' funds.

### Finding Description
`apply_bad_debt_to_supply_index` computes `remaining = total_supplied_value − capped_bad_debt` and multiplies `supply_index` by `remaining / total_supplied_value`. When `bad_debt >= total_supplied_value` (full wipeout), `remaining = 0`, so the index would be 0 — a "dead" book. Instead the code applies `.max(Ray::from(SUPPLY_INDEX_FLOOR_RAW))`, so the index is resurrected to `RAY/1000` [2](#0-1) . Positions that should be worthless (`scaled_amount` × `index/RAY`) keep a claim equal to ~`scaled/1000` tokens, because withdraw unscales with the same floored index.

The path is fully permissionless: any address calls `controller::clean_bad_debt(account_id)` → `process_clean_bad_debt` (requires only `caller.require_auth` and no flash loan) → `clean_bad_debt_standalone` → `socialize_bad_debt(env, account_id, BadDebtGate::DustCapped)` [3](#0-2) . The cleanup emits `PoolSeizeEntry` legs with `AccountPositionType::Borrow`, which the pool executes in `ops/seize.rs::apply`: `bad_debt = unscale_borrow_ceil_ray(position)` then `apply_bad_debt_to_supply_index` then `burn_debt` [4](#0-3) . No supply guard distinguishes a wiped book from a shrunken one — `withdraw` only checks `require_reserves` against current `cash` [5](#0-4) .

The repository's own tests demonstrate the drain: `test_raw_cache_floor_residual_can_consume_fresh_cash_without_supply_guard` and `test_raw_cache_floor_clamp_strands_claim_without_supply_guard` show a wiped supplier withdrawing `gross` exactly equal to a fresh deposit `c`, leaving the pool unable to cover the honest supplier's claim [6](#0-5) .

### Impact Explanation
Theft of user funds / pool insolvency. After a wipeout-scale `clean_bad_debt`, the market looks empty of debt but every previously-wiped supplier retains a positive withdrawable claim. The first new `supply` deposits become instantly exfiltrable by the phantom claimants (including the attacker, who can hold wiped supply shares). Loss equals the fresh deposits, not capped by real backing — classic dead-object-treated-as-live accounting, matching the dentry analog.

### Likelihood Explanation
Medium-High. `clean_bad_debt` is permissionless and dust-gated, so any user triggers it the moment an insolvent account qualifies. Full wipeout requires socialized debt ≥ total supplied value for that (hub, token) book — achievable in an illiquid spoke after a price crash or oracle move, and the attacker can engineer it by leaving their own dust-collateral insolvent account plus holding wiped supply shares pre-cleanup. No privilege, timing race, or external dependency is needed once the market conditions exist.

### Recommendation
In `apply_bad_debt_to_supply_index`, when `remaining == 0` (full wipeout), set `supply_index = 0` and treat the book as dead (or zero out `supplied` so `unscale_supply` returns nothing), rather than clamping to `SUPPLY_INDEX_FLOOR_RAW`. Alternatively, gate the floor: only clamp when `remaining > 0`, so a genuine wipeout zeros claims instead of minting a residual claim on future deposits.

### Proof of Concept
```text
1. Spoke market M (hub H, token T): attacker supplies S shares (index ≈ RAY),
   victim/other borrow positions exist. Attacker creates account A that borrows
   max LTV against minimal collateral in M (or another spoke market mapped to M).
2. Collateral price drops (or attacker lets it sit until debt > dust-threshold
   collateral). Account A's remaining collateral is below the dust cap.
3. Any unprivileged caller invokes:
       controller.clean_bad_debt(account_id = A)
   → socialize_bad_debt passes BadDebtGate::DustCapped
   → bad_debt::execute_bad_debt_cleanup emits PoolSeizeEntry{side: Borrow}
   → pool ops/seize.rs::apply calls apply_bad_debt_to_supply_index(bad_debt)
   with bad_debt >= total_supplied_value ⇒ supply_index := RAY/1000 (floor).
4. Attacker's wiped supply position scaled_amount now unscales to
   scaled_amount * (RAY/1000)/RAY = scaled_amount/1000 tokens > 0,
   though it should be zero.
5. Attacker (or anyone) supplies `c = scaled_amount/1000` tokens to M,
   then immediately `withdraw(i128::MAX)` on the wiped position:
   resolve_withdrawal returns gross = c, require_reserves passes on the fresh
   cash, transfer_out sends `c` tokens. The pool is left unable to honor the
   honest new supplier's claim.
```
This mirrors the test at `contracts/pool/tests/interest.rs:351-369`, which asserts `gross == c` and `cash < b_claim` after the floor clamp [7](#0-6) .

*Uncertainty noted:* `bad_debt::execute_bad_debt_cleanup`'s exact leg construction was not fully read; the report assumes it socializes each borrow leg's full scaled position via `PoolSeizeEntry{side: Borrow}` as `seize.rs::apply` indicates. If the repo intentionally documents the `SUPPLY_INDEX_FLOOR_RAW` clamp as an ADR choice, this finding may be downgraded under the "documented ADR" exclusion — the README documents the floor's existence but does not justify the wipeout-drain consequence.

### Citations

**File:** contracts/pool/src/interest.rs (L80-89)
```rust
    let capped = bad_debt.min(total_supplied_value);
    let remaining = total_supplied_value.checked_sub(cache.env(), capped);

    let reduction_factor = remaining.div_floor(cache.env(), total_supplied_value);
    let new_supply_index = cache
        .supply_index()
        .mul_floor(cache.env(), reduction_factor);

    cache.set_supply_index(new_supply_index.max(Ray::from(SUPPLY_INDEX_FLOOR_RAW)));
}
```

**File:** contracts/controller/src/positions/liquidation/mod.rs (L196-243)
```rust
pub(crate) fn process_clean_bad_debt(env: &Env, caller: &Address, account_id: u64) {
    caller.require_auth();
    validation::require_not_flash_loaning(env);
    clean_bad_debt_standalone(env, account_id);
}

/// Admission condition for bad-debt socialization.
#[derive(Clone, Copy, PartialEq)]
enum BadDebtGate {
    /// Permissionless: insolvent *and* collateral at or below the dust threshold.
    DustCapped,
    /// Owner-only: insolvent alone, with no cap on the collateral left behind.
    InsolventOnly,
}

/// Requires open debt and the selected insolvency gate, then cleans up the account.
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

**File:** contracts/pool/src/ops/seize.rs (L24-28)
```rust
        AccountPositionType::Borrow => {
            let bad_debt = cache.unscale_borrow_ceil_ray(position);
            interest::apply_bad_debt_to_supply_index(&mut cache, bad_debt);
            cache.burn_debt(position);
        }
```

**File:** contracts/pool/src/cache/cash.rs (L15-21)
```rust
    pub(crate) fn require_reserves(&self, amount: i128) {
        assert_with_error!(
            self.env,
            self.cash >= amount,
            CollateralError::InsufficientLiquidity
        );
    }
```

**File:** contracts/pool/tests/interest.rs (L351-369)
```rust
        let (burn, gross) = cache.resolve_withdrawal(i128::MAX, scaled_a);
        cache.require_reserves(gross);
        cache.burn_supply(burn);
        cache.debit_cash(gross);

        assert!(gross > 0, "stranded position pays out non-zero");
        assert_eq!(
            gross, c,
            "userA drains exactly userB's fresh deposit out of the pool"
        );

        assert!(
            cache.cash() < b_claim,
            "pool cash ({}) can no longer cover userB's claim ({}): honest supplier lost funds",
            cache.cash(),
            b_claim
        );
        assert_eq!(cache.cash(), 0, "userA drained the pool to empty");
    });
```
