### Title
Bad-debt wipeout clamps `supply_index` up to `SUPPLY_INDEX_FLOOR_RAW`, leaving stranded supply shares that drain later pool cash via unguarded withdrawals - (File: contracts/pool/src/interest.rs, contracts/pool/src/ops/withdraw.rs)

### Summary
Analogous to a memory-corruption bug, the pool's share accounting is silently corrupted on a total bad-debt write-down: `apply_bad_debt_to_supply_index` floors the supply index at `RAY/1000` instead of letting it reach zero, so every wiped supply position retains a residual asset-denominated claim with no backing. Withdrawals only check `require_reserves` (cash on hand), never `require_backed_market`, so once any cash re-enters the market — surviving borrowers' repayments or a `recapitalize` donation — wiped-out holders can withdraw real tokens they are no longer entitled to.

### Finding Description
When `seize_positions` processes a borrow-side entry, it computes the unpaid debt and calls `apply_bad_debt_to_supply_index` to socialize the loss: [1](#0-0) 

The write-down computes `new_supply_index = supply_index * (1 - bad_debt/total_supplied)`, but then clamps it to a nonzero floor: [2](#0-1) 

When `bad_debt >= total_supplied_value` (a full wipeout), `remaining = 0`, `reduction_factor = 0`, and the index should become zero — yet it is clamped *up* to `SUPPLY_INDEX_FLOOR_RAW` (`RAY/1000`). Supply shares are never burned, so each supplier's `scaled_amount * RAY/1000` remains a positive claim. `require_supply_for_debt` only fires when `supplied == 0`, which never happens because shares persist.

The pool's own tests prove the stranded claim pays out real tokens: [3](#0-2) 

The withdrawal path is the enabler: `gate_and_debit` enforces `require_reserves` (only that `cash >= net_transfer`), utilization, and `require_supply_for_debt` — but **not** `require_backed_market`: [4](#0-3) [5](#0-4) 

The flow that reaches this from an unprivileged address: `controller::liquidate` on an underwater account leaves residual debt; `controller::clean_bad_debt` → `execute_bad_debt_cleanup` → `pool_seize_positions_call` performs the borrow-side seize: [6](#0-5) 

### Impact Explanation
After a wipeout, the market's books are insolvent: floored supply claims exceed cash + debt. New supply is blocked by the backing gate (as `docs/reference/formulas.md` notes), but withdrawals are not. Any cash that enters — repayments from surviving borrowers in the same market, or a `recapitalize` call — can be withdrawn pro-rata-race by wiped-out suppliers whose claims should be worth zero. Early withdrawers steal cash that backs remaining claims; later claimants and protocol revenue are left permanently unbacked. Result: theft/freezing of user funds and protocol insolvency, reachable entirely through unprivileged entrypoints (`borrow`, `liquidate`, `clean_bad_debt`, `withdraw`).

### Likelihood Explanation
Requires a market wipeout: bad debt ≥ total supplied value on the seize, meaning collateral seized was insufficient — plausible during sharp price moves or thin collateral markets, and an attacker can engineer it by opening an underwater position whose collateral leg liquidates for less than the debt (whole-unit sub-3-decimal legs and bonus caps limit recovery). `clean_bad_debt` is permissionless once the account is below the dust threshold. Exploitation afterwards is a simple `withdraw` race whenever cash re-enters.

### Recommendation
Either burn the wiped supply shares to zero (or proportionally) when the write-down caps at total supplied value, or gate withdrawals with `require_backed_market`/`backing_shortfall` so stranded residual claims cannot extract cash that was never theirs. At minimum, when `remaining == 0`, set `supply_index` to zero and zero out `supplied`/`revenue` shares rather than clamping to `SUPPLY_INDEX_FLOOR_RAW`.

### Proof of Concept
1. Supplier Alice supplies X units; borrower Bob borrows the market; Bob's collateral crashes so liquidation leaves unpaid debt ≥ total supplied value.
2. Anyone calls `controller.clean_bad_debt(bob_account)`: `seize_positions` runs `apply_bad_debt_to_supply_index`, clamping `supply_index` to `RAY/1000` (should be 0). Alice's `scaled_amount` is untouched.
3. Surviving borrower repays, or a `recapitalize` adds cash C to the market.
4. Alice calls `controller.withdraw(i128::MAX)`: `resolve_withdrawal` computes `gross = scaled_amount * RAY/1000 > 0`; `require_reserves` passes since `cash >= gross`; no backing check runs. Alice receives real tokens despite being fully wiped.
5. Repeat per wiped supplier until cash is exhausted; remaining claims and revenue are permanently unbacked — later withdrawers' funds are frozen. This mirrors `test_raw_cache_floor_clamp_strands_claim_without_supply_guard` in `contracts/pool/tests/interest.rs:372-427`, which already demonstrates the drain at the cache level.

### Citations

**File:** contracts/pool/src/ops/seize.rs (L23-31)
```rust
    match entry.side {
        AccountPositionType::Borrow => {
            let bad_debt = cache.unscale_borrow_ceil_ray(position);
            interest::apply_bad_debt_to_supply_index(&mut cache, bad_debt);
            cache.burn_debt(position);
        }
        AccountPositionType::Deposit => {
            cache.absorb_supply_as_revenue(position);
        }
```

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

**File:** contracts/pool/tests/interest.rs (L372-427)
```rust
#[test]
fn test_raw_cache_floor_clamp_strands_claim_without_supply_guard() {
    let t = TestSetup::new();
    t.as_contract(|| {
        let old_scaled_raw = 1_000 * RAY;
        let mut cache = t.fresh_cache(PoolStateRaw {
            supplied: old_scaled_raw,
            borrowed: 0,
            revenue: 0,
            borrow_index: RAY,
            supply_index: RAY,
            last_timestamp: 0,
            cash: 0,
        });
        let old_scaled = Ray::from(old_scaled_raw);

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
    });
```

**File:** contracts/pool/src/ops/withdraw.rs (L111-119)
```rust
fn gate_and_debit(env: &Env, cache: &mut Cache, net_transfer: i128, skip_utilization_check: bool) {
    cache.require_reserves(net_transfer);

    if !skip_utilization_check {
        guards::require_utilization_below_max(env, cache);
    }
    guards::require_supply_for_debt(env, cache);
    cache.debit_cash(net_transfer);
}
```

**File:** contracts/pool/src/guards.rs (L49-66)
```rust
/// Panics with `PoolInsolvent` if the market has a positive backing shortfall.
///
/// Backing = cash + ceiled debt value; claims = floored supply value.
pub(crate) fn require_backed_market(env: &Env, cache: &Cache) {
    assert_with_error!(
        env,
        backing_shortfall(cache) == 0,
        CollateralError::PoolInsolvent
    );
}

/// Asset units by which supplier claims exceed cash + debt (0 if solvent).
pub(crate) fn backing_shortfall(cache: &Cache) -> i128 {
    let supplied_claim = cache.unscale_supply_floor(cache.supplied());
    let outstanding_debt = cache.unscale_borrow_ceil(cache.borrowed());
    let backing = cache.cash().saturating_add(outstanding_debt);
    supplied_claim.saturating_sub(backing).max(0)
}
```

**File:** contracts/controller/src/positions/liquidation/bad_debt.rs (L35-49)
```rust
    for (hub_asset, position) in iter_debt_positions(&account.borrow_positions) {
        cache.apply_spoke_exit(
            account.spoke_id,
            UsageSide::Borrow,
            &hub_asset,
            position.scaled_amount,
        );
        entries.push_back(PoolSeizeEntry {
            hub_asset,
            side: AccountPositionType::Borrow,
            position: (&position).into(),
        });
    }
    let pool_addr = cache.cached_pool_address();
    pool_seize_positions_call(env, &pool_addr, &entries);
```
