### Title
Bad-debt write-down clamps `supply_index` to a floor, leaving wiped-out supply shares a residual claim that drains fresh deposits - ([File: contracts/pool/src/interest.rs](contracts/pool/src/interest.rs))

### Summary
The external bug class is an unchecked signed intermediate: `UTF8_putc` returns `-1`, the negative value is added to an output length, and the NUL terminator lands before the buffer — a value that should have been rejected silently wraps into a corrupted write. The analog in XOXNO Lending is `apply_bad_debt_to_supply_index`: when bad debt exceeds the supply-side capacity to absorb it, the write-down does not zero out supply shares — it clamps `supply_index` up to `SUPPLY_INDEX_FLOOR_RAW` (`RAY/1000`), which is the same shape of "value hits a bound and the leftover is written somewhere it doesn't belong." The stranded residual on unburned supply shares is later paid out of fresh deposits.

### Finding Description
During `clean_bad_debt`, the controller calls `seize_positions` on the pool with `AccountPositionType::Borrow` entries. In `contracts/pool/src/ops/seize.rs` the borrow-side arm computes `bad_debt = cache.unscale_borrow_ceil_ray(position)`, calls `interest::apply_bad_debt_to_supply_index(&mut cache, bad_debt)`, and burns the debt shares [1](#0-0) .

When the write-down would push `supply_index` below `SUPPLY_INDEX_FLOOR_RAW`, it is clamped at the floor instead of zeroing the supply side. The pool's own regression test `test_raw_cache_seizure_residual_would_drain_fresh_cash_without_supply_guard` proves the consequence: after a wipeout, `cache.unscale_supply_floor(alice_scaled) > 0` — a wiped survivor keeps a stranded claim with `cash == 0`. When Bob deposits `alice_stranded` units, `resolve_withdrawal(i128::MAX, alice_scaled)` returns `gross == deposit` and `debit_cash` pays it out, leaving `cash < bob_claim` — Bob's honest deposit is unbacked [2](#0-1) .

The repayment boundary is the mirror image of the OpenSSL flaw: `resolve_repay` adds an unchecked signed delta (`amount - current_debt_ceil`) and `net_repay = amount.checked_sub(overpayment)` [3](#0-2) , while the bad-debt path writes the clamped residue into `supply_index` where it corrupts later accounting — the "one byte before the buffer" is a claim written before the market's real backing.

### Impact Explanation
Theft of user funds / protocol insolvency. An attacker who holds supply shares in a market that undergoes a full bad-debt wipeout retains a residual floor-valued claim (`unscale_supply_floor > 0` at `supply_index = RAY/1000`). Any subsequent depositor's cash can be withdrawn against that claim even though the market's books are insolvent (`total_owed > cash`), directly transferring the new depositor's funds to the wiped survivor. This is exactly the scenario asserted in the pool's own test.

### Likelihood Explanation
`clean_bad_debt` is unprivileged — any address can trigger cleanup of an account whose debt is below the dust threshold. An attacker can engineer the state: supply a small amount in a market, open a borrow position that becomes unbacked bad debt (via price movement across their own positions or naturally occurring liquidation failures), let cleanup socialize the debt and clamp the index, then wait for (or solicit) fresh supply and withdraw the residual. The cost is the dust debt and a small supply position; the payout is bounded only by the next deposit size. Medium likelihood, High impact.

### Recommendation
When the bad-debt write-down reaches `SUPPLY_INDEX_FLOOR_RAW`, the surviving supply shares are economically zeroed — the code should reflect that instead of leaving a claim on the floor. Either burn all supply shares in the wiped market alongside the debt burn, or track the clamped remainder as explicit written-off claims that cannot withdraw against new cash (e.g., gate withdrawals on `backing_shortfall == 0` via `require_backed_market` for survivors of a floor-clamped market, not just `require_reserves`). The current `require_reserves` check only verifies cash exists, not that the cash belongs to the claimant [4](#0-3) .

### Proof of Concept
1. Market M: attacker supplies amount `s`, a position accrues debt `d` that becomes bad debt (collateral exhausted below dust threshold).
2. Unprivileged caller invokes `clean_bad_debt` → `execute_bad_debt_cleanup` builds a `PoolSeizeEntry` with `side = Borrow` [5](#0-4)  → `seize::apply` calls `apply_bad_debt_to_supply_index`, which clamps `supply_index` to `SUPPLY_INDEX_FLOOR_RAW` and burns the debt.
3. Attacker's `scaled_amount` shares now value at `floor(scaled × RAY/1000)` — positive but unbacked (`cash == 0`).
4. Victim supplies `v` to market M; `credit_cash(v)` funds the pool.
5. Attacker calls `withdraw(0)` (withdraw-all): `resolve_withdrawal` pays `gross = v`, `require_reserves` passes because cash exists, `debit_cash` transfers the victim's deposit to the attacker.
6. Victim's supply claim `unscale_supply_floor(bob_scaled)` now exceeds remaining `cash` — permanent loss.

The harness test at `contracts/pool/tests/interest.rs:430-495` reproduces steps 2–5 in-contract and asserts the stranded claim pays out the fresh deposit in full.

### Citations

**File:** contracts/pool/src/ops/seize.rs (L24-28)
```rust
        AccountPositionType::Borrow => {
            let bad_debt = cache.unscale_borrow_ceil_ray(position);
            interest::apply_bad_debt_to_supply_index(&mut cache, bad_debt);
            cache.burn_debt(position);
        }
```

**File:** contracts/pool/tests/interest.rs (L448-493)
```rust
        let bad_debt = cache.unscale_borrow_ceil_ray(borrow_scaled);
        apply_bad_debt_to_supply_index(&mut cache, bad_debt);
        cache.burn_debt(borrow_scaled);

        assert_eq!(
            cache.supply_index().raw(),
            SUPPLY_INDEX_FLOOR_RAW,
            "seize wipeout clamps supply_index UP to RAY/1000, leaving unburned shares a residual"
        );

        let alice_stranded = cache.unscale_supply_floor(alice_scaled);
        assert!(alice_stranded > 0, "wiped survivor keeps a stranded claim");
        assert_eq!(
            cache.cash(),
            0,
            "empty market: claim masked by require_reserves"
        );

        let deposit = alice_stranded;
        let bob_scaled = cache.calculate_scaled_supply(deposit);
        cache.mint_supply(bob_scaled);
        cache.credit_cash(deposit);

        let total_owed = cache.unscale_supply_floor(cache.supplied());
        assert!(
            total_owed > cache.cash(),
            "post-deposit books insolvent: owed {} > cash {}",
            total_owed,
            cache.cash()
        );

        let (burn, gross) = cache.resolve_withdrawal(i128::MAX, alice_scaled);
        cache.require_reserves(gross);
        cache.burn_supply(burn);
        cache.debit_cash(gross);

        assert!(gross > 0, "wiped position pays out real cash");
        assert_eq!(gross, deposit, "Alice extracts exactly Bob's fresh deposit");

        let bob_claim = cache.unscale_supply_floor(bob_scaled);
        assert!(
            cache.cash() < bob_claim,
            "cash {} cannot cover Bob's honest claim {}: fresh depositor lost funds",
            cache.cash(),
            bob_claim
        );
```

**File:** contracts/pool/src/ops/repay.rs (L44-52)
```rust
    let (burned, overpayment) = cache.resolve_repay(amount, position);
    let net_repay = amount
        .checked_sub(overpayment)
        .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow));
    assert_with_error!(
        env,
        net_repay == 0 || burned.raw() > 0,
        GenericError::RepayRoundsToZeroShares
    );
```

**File:** contracts/pool/src/guards.rs (L52-66)
```rust
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
