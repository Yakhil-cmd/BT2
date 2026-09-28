### Title
Bad-debt wipeout leaves uncleared scaled supply shares that drain future deposits - (File: contracts/pool/src/interest.rs)

### Summary
`apply_bad_debt_to_supply_index` socializes bad debt by scaling down `supply_index`, but clamps the result at `SUPPLY_INDEX_FLOOR_RAW` instead of zeroing or clearing supplier share records. On a full wipeout (`bad_debt >= total_supplied_value`), every supplier keeps their old scaled shares, which remain redeemable at the floored index. These uncleared "phantom" claims are later paid out of cash contributed by new depositors — the direct analog of failing to clear allocated memory: wiped positions retain a residual, dereferenceable claim.

### Finding Description
`contracts/pool/src/interest.rs:73-89`: when `bad_debt` is capped at `total_supplied_value`, `remaining` is zero, so `reduction_factor = 0` and the computed index is 0 — but line 88 clamps it UP to `SUPPLY_INDEX_FLOOR_RAW` (`RAY/1000`).

Consequences:
- `supplied` (total scaled shares) is untouched; every holder's `scaled_amount` remains in controller storage.
- `unscale_supply_floor(scaled)` still returns `scaled * SUPPLY_INDEX_FLOOR_RAW > 0` for any previously non-trivial supplier.
- Because the index is positive and `borrowed` is burned to zero, `require_backed_market` / `require_utilization_below_max` still admit new supply (confirmed by `tests/test-harness/tests/controller/bad_debt_index.rs:647-689`), and `require_reserves` only checks that cash covers the withdrawal — it cannot tell a phantom claim from a real one.

Reachable path (single unprivileged address): attacker supplies dust collateral, borrows against a thin market, price crash makes the account deeply insolvent (debt ≥ total supplied value of the debt market), then anyone calls `clean_bad_debt(account_id)` (permissionless once below the dust gate) or a liquidation seizes the position — `ops::seize` invokes `apply_bad_debt_to_supply_index` and clamps the index to the floor while leaving all scaled supply records uncleared.

### Impact Explanation
After the wipeout, wiped suppliers can call `withdraw` and receive real tokens for claims that should be zero. A fresh supplier deposits, mints shares at the floored index, and the old phantom holders immediately drain that cash — the pool can no longer cover the fresh supplier's claim. This is theft of user funds / protocol insolvency. The mechanism is proven by `contracts/pool/tests/interest.rs:373-427` (`test_raw_cache_floor_clamp_strands_claim_without_supply_guard`): the stranded claim "drains exactly the fresh deposit" and `cache.cash() < fresh_claim`.

### Likelihood Explanation
Requires a wipeout-scale bad-debt event on one market: the socialized debt must reach the full supplied value. Normally `require_utilization_below_max` keeps borrows under ~95% of supply value, so a single liquidation stays far from the floor — but accrued interest, a severe collateral crash, or repeated partial socializations on a thin market can reach it. When it does happen the loss transfer is deterministic and total for new depositors. Medium-to-High likelihood, High severity.

### Recommendation
On a full wipeout, do not clamp the index upward — either allow the index to reach a state where all existing scaled shares unscale to zero and explicitly clear `supplied`/`revenue` share accounting, or introduce an epoch/generation reset (e.g., zero the index and require positions to be migrated/zeroed via a new share base) so wiped shares carry no residual claim. The clamp should only apply to partial write-downs; at `reduction_factor == 0` the pool must zero the share supply rather than preserve it at `SUPPLY_INDEX_FLOOR_RAW`.

### Proof of Concept
```rust
// contracts/pool/tests/interest.rs:373-427 already demonstrates the primitive:
let old_scaled = Ray::from(1_000 * RAY);           // pre-wipeout supplier shares
apply_bad_debt_to_supply_index(&mut cache, Ray::from(5_000 * RAY)); // full wipeout
assert_eq!(cache.supply_index().raw(), SUPPLY_INDEX_FLOOR_RAW);     // clamped, not cleared
assert!(cache.unscale_supply_floor(old_scaled) > 0);                // phantom claim survives

// fresh depositor funds the pool
cache.mint_supply(cache.calculate_scaled_supply(stranded));
cache.credit_cash(stranded);

// wiped supplier withdraws real tokens
let (burn, gross) = cache.resolve_withdrawal(i128::MAX, old_scaled);
cache.require_reserves(gross);   // passes once fresh cash exists
// gross == fresh deposit; fresh supplier's claim now exceeds pool cash
```

User-level flow: `supply` → `borrow` → price crash → `clean_bad_debt`/`liquidate` (unprivileged) triggers `apply_bad_debt_to_supply_index` → index clamped to floor, shares uncleared → victim `supply` → attacker/wiped supplier `withdraw` drains the deposit. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** contracts/pool/src/interest.rs (L73-89)
```rust
pub(crate) fn apply_bad_debt_to_supply_index(cache: &mut Cache, bad_debt: Ray) {
    let total_supplied_value = cache.supplied().mul(cache.env(), cache.supply_index());

    if total_supplied_value == Ray::ZERO {
        return;
    }

    let capped = bad_debt.min(total_supplied_value);
    let remaining = total_supplied_value.checked_sub(cache.env(), capped);

    let reduction_factor = remaining.div_floor(cache.env(), total_supplied_value);
    let new_supply_index = cache
        .supply_index()
        .mul_floor(cache.env(), reduction_factor);

    cache.set_supply_index(new_supply_index.max(Ray::from(SUPPLY_INDEX_FLOOR_RAW)));
}
```

**File:** contracts/pool/tests/interest.rs (L388-426)
```rust
        apply_bad_debt_to_supply_index(&mut cache, Ray::from(5_000 * RAY));
        assert_eq!(
            cache.supply_index().raw(),
            SUPPLY_INDEX_FLOOR_RAW,
            "wipeout clamps supply_index UP to RAY/1000 instead of resetting shares to 0",
        );

        let stranded = cache.unscale_supply_floor(old_scaled);
        assert!(stranded > 0, "floor clamp leaves S_old a phantom claim");
        assert_eq!(
            cache.cash(),
            0,
            "no cash yet: invariant only masked by require_reserves"
        );

        let fresh_cash = stranded;
        let fresh_scaled = cache.calculate_scaled_supply(fresh_cash);
        cache.mint_supply(fresh_scaled);
        cache.credit_cash(fresh_cash);

        let fresh_claim = cache.unscale_supply_floor(fresh_scaled);
        assert_eq!(
            fresh_claim, fresh_cash,
            "fresh supplier's claim equals deposit"
        );

        let (burn, gross) = cache.resolve_withdrawal(i128::MAX, old_scaled);
        cache.require_reserves(gross);
        cache.burn_supply(burn);
        cache.debit_cash(gross);

        assert!(gross > 0, "stranded wiped position pays out real tokens");
        assert_eq!(gross, fresh_cash, "S_old drains exactly the fresh deposit");
        assert!(
            cache.cash() < fresh_claim,
            "pool cash ({}) can no longer cover fresh supplier claim ({}): funds lost",
            cache.cash(),
            fresh_claim,
        );
```

**File:** tests/test-harness/tests/controller/bad_debt_index.rs (L647-689)
```rust
#[test]
fn test_socialization_leaves_the_market_backed_and_open() {
    let mut t = setup();

    // Alice borrows half the ETH supply, so one liquidation makes a large write-down.
    t.supply(BOB, "ETH", 0.01);
    t.supply(ALICE, "USDC", 100.0);
    t.borrow(ALICE, "ETH", 0.005);

    let eth_before = market_state(&t, "ETH");

    t.set_price("USDC", usd_cents(1));
    t.liquidate(LIQUIDATOR, ALICE, "ETH", 0.001);

    let eth_after = market_state(&t, "ETH");
    let (si_after, _) = get_indexes(&t, "ETH");

    assert!(
        si_after < eth_before.supply_index,
        "fixture must actually socialize: before={} after={si_after}",
        eth_before.supply_index
    );

    // The utilization ceiling keeps one liquidation far from the index floor.
    assert!(
        si_after > controller::constants::SUPPLY_INDEX_FLOOR_RAW * 100,
        "one liquidation should not approach the index floor: si={si_after} floor={}",
        controller::constants::SUPPLY_INDEX_FLOOR_RAW
    );

    // The INV-ACCT-09 shape holds on the seize path: no debt without supply.
    assert!(
        !(eth_after.supplied == 0 && eth_after.borrowed != 0),
        "seize left debt with zero supply"
    );

    // INV-ACCT-04: the market is still backed, so it accepts new supply.
    t.supply(DAVE, "ETH", 1.0);
    assert!(
        t.supply_balance(DAVE, "ETH") > 0.0,
        "a solvent post-socialization market must still accept supply"
    );
}
```

**File:** contracts/pool/src/cache/scale.rs (L59-67)
```rust
    /// Unscales supply shares rounding **down** (conservative claim value).
    pub(crate) fn unscale_supply_floor(&self, scaled: Ray) -> i128 {
        unscale_supply_floor(
            &self.env,
            scaled,
            self.supply_index,
            self.params.asset_decimals,
        )
    }
```
