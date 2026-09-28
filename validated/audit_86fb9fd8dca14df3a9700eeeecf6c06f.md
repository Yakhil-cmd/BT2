### Title
Suppliers can withdraw at the pre-write-down index after bad debt is economically realized - ([File: contracts/pool/src/ops/withdraw.rs](contracts/pool/src/ops/withdraw.rs))

### Summary
A supplier can exit at the old supply index after a borrower's collateral has crashed but before `clean_bad_debt` or liquidation socializes the loss. The withdrawal path pays the full floor-valued claim because it still counts the unrecoverable debt as backing, leaving later suppliers to absorb the entire write-down.

### Finding Description
XOXNO Lending does not mark down `supply_index` when an account becomes insolvent. The write-down occurs only when `seize` processes the borrow position: `seize::apply` calculates the debt at the live borrow index, calls `apply_bad_debt_to_supply_index`, and burns the debt shares. [1](#0-0)  Before that operation, withdrawals use the unchanged `supply_index` through `resolve_withdrawal`, which pays the position's floor-valued claim and burns all shares on a full withdrawal. [2](#0-1) 

The withdrawal guard checks available cash, utilization, and the zero-supply/nonzero-debt shape, but does not call `require_backed_market`. [3](#0-2)  Consequently, `backing_shortfall`'s face-value treatment of outstanding debt does not prevent an exit while the debt is still recorded but is no longer collateral-backed. [4](#0-3)  When cleanup later executes, the loss is socialized across the smaller set of remaining supply shares by lowering `supply_index`. [5](#0-4) 

### Impact Explanation
An unprivileged supplier can withdraw its full token amount after bad debt exists economically but before it is reflected in the supply index. This transfers the loss to suppliers who remain in the market. If enough suppliers exit first, the later write-down can leave the remaining supplier claims under-backed or cause protocol insolvency.

This is directly demonstrated by the repository's regression test `supplier_can_exit_ahead_of_bad_debt_writedown`: after the collateral price crashes, Bob calls `withdraw_all` before liquidation, recovers his entire balance, and Carol's subsequent bad-debt loss is amplified by more than three times. [6](#0-5) 

### Likelihood Explanation
The sequence requires a public price movement that makes an account insolvent and a supplier withdrawal before a liquidation or bad-debt cleanup transaction. Both actions are unprivileged. Suppliers monitoring oracle prices can submit `withdraw` immediately after the crash, while cleanup depends on the normal liquidation/cleanup path executing afterward. No privileged action, leaked key, oracle failure, or parameter misconfiguration is required.

### Recommendation
Do not allow ordinary withdrawals to treat economically uncollectible debt as face-value backing. Apply a bad-debt reserve or haircut before non-liquidation withdrawals, or synchronously socialize eligible bad debt before paying withdrawals. At minimum, run `require_backed_market` or an equivalent economic-backing check in `withdraw::gate_and_debit` rather than checking only cash, utilization, and `require_supply_for_debt`.

### Proof of Concept
1. Bob supplies 75% of the ETH market and Carol supplies 25%.
2. Alice supplies USDC collateral and borrows ETH.
3. The USDC price crashes so Alice's ETH debt exceeds the collateral value. Alice is now liquidatable, but the ETH market's `supply_index` has not yet been written down.
4. Bob calls the controller `withdraw` entrypoint with an ETH withdrawal amount of `0`, which the controller maps to withdraw-all (`i128::MAX` at the pool layer).
5. The pool resolves Bob's withdrawal using the unchanged `supply_index`, transfers his full balance, and burns his supply shares.
6. A liquidator subsequently liquidates Alice or calls `clean_bad_debt`.
7. `seize::apply` calls `apply_bad_debt_to_supply_index`, reducing the ETH `supply_index` over only Carol's remaining shares. Carol absorbs the bad debt that economically should have been shared with Bob.
8. Repeating the withdrawal for enough suppliers can leave the final claim holders with insufficient cash plus collectible debt, producing market insolvency.

### Citations

**File:** contracts/pool/src/ops/seize.rs (L20-28)
```rust
    let mut cache = ops::synced_market(env, &entry.hub_asset);
    let position = Ray::from(entry.position.scaled_amount);

    match entry.side {
        AccountPositionType::Borrow => {
            let bad_debt = cache.unscale_borrow_ceil_ray(position);
            interest::apply_bad_debt_to_supply_index(&mut cache, bad_debt);
            cache.burn_debt(position);
        }
```

**File:** common/src/rates/scaling.rs (L112-119)
```rust
    let current_supply_actual = unscale_supply(env, pos_scaled, supply_index, decimals);
    let current_supply_floor = unscale_supply_floor(env, pos_scaled, supply_index, decimals);
    if amount >= current_supply_actual {
        return (pos_scaled, current_supply_floor);
    }
    (
        calculate_scaled_supply_ceil(env, amount, decimals, supply_index),
        amount,
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

**File:** contracts/pool/src/guards.rs (L61-65)
```rust
pub(crate) fn backing_shortfall(cache: &Cache) -> i128 {
    let supplied_claim = cache.unscale_supply_floor(cache.supplied());
    let outstanding_debt = cache.unscale_borrow_ceil(cache.borrowed());
    let backing = cache.cash().saturating_add(outstanding_debt);
    supplied_claim.saturating_sub(backing).max(0)
```

**File:** contracts/pool/src/interest.rs (L73-88)
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
```

**File:** tests/test-harness/tests/controller/bad_debt_index.rs (L402-461)
```rust
fn supplier_can_exit_ahead_of_bad_debt_writedown() {
    // Scenario A: nobody dodges. Bob 75%, Carol 25% of the ETH supply.
    let mut a = setup();
    a.supply(BOB, "ETH", 75.0);
    a.supply(CAROL, "ETH", 25.0);
    a.supply(ALICE, "USDC", 10.0);
    a.borrow(ALICE, "ETH", 0.003);

    let carol_before_a = a.supply_balance(CAROL, "ETH");
    a.set_price("USDC", usd_cents(10));
    a.liquidate(LIQUIDATOR, ALICE, "ETH", 0.001);
    let carol_loss_a = carol_before_a - a.supply_balance(CAROL, "ETH");

    // Scenario B: identical state, but Bob withdraws before the write-down.
    let mut b = setup();
    b.supply(BOB, "ETH", 75.0);
    b.supply(CAROL, "ETH", 25.0);
    b.supply(ALICE, "USDC", 10.0);
    b.borrow(ALICE, "ETH", 0.003);

    let carol_before_b = b.supply_balance(CAROL, "ETH");
    let bob_before_b = b.supply_balance(BOB, "ETH");
    let bob_wallet_before = b.token_balance(BOB, "ETH");

    // The crash is public state. Alice is insolvent from here on, but no
    // write-down has been applied yet.
    b.set_price("USDC", usd_cents(10));
    b.assert_liquidatable(ALICE);

    // Bob exits at the un-written-down index. No gate stops him: the
    // liquidation buffer only guards borrow draws, and `backing_shortfall`
    // still values Alice's uncollateralised debt at face.
    b.withdraw_all(BOB, "ETH");
    let bob_recovered = b.token_balance(BOB, "ETH") - bob_wallet_before;

    b.liquidate(LIQUIDATOR, ALICE, "ETH", 0.001);
    let carol_loss_b = carol_before_b - b.supply_balance(CAROL, "ETH");

    assert!(
        bob_recovered >= bob_before_b,
        "Bob exits whole: supplied={:.9} recovered={:.9}",
        bob_before_b,
        bob_recovered
    );
    assert!(
        carol_loss_b > carol_loss_a,
        "dodging must push loss onto Carol: A={:.9} B={:.9}",
        carol_loss_a,
        carol_loss_b
    );

    // Carol holds 25% of supply, so passing the whole loss to her is ~4x.
    let amplification = carol_loss_b / carol_loss_a;
    assert!(
        amplification > 3.0,
        "expected ~4x concentration onto the remaining supplier, got {:.3}x \
         (A={:.9} B={:.9})",
        amplification,
        carol_loss_a,
        carol_loss_b
```
