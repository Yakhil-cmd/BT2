### Title
Suppliers can withdraw at the pre-write-down index after bad debt exists, leaving remaining suppliers' claims underfunded - (File: contracts/pool/src/guards.rs)

### Summary
Bad debt in a market only becomes real once a later call (liquidation `seize_positions` or `clean_bad_debt`) runs `apply_bad_debt_to_supply_index` and lowers `supply_index`. Between the moment a borrower becomes unrecoverably insolvent (publicly visible via prices/HF) and the moment the write-down executes, `backing_shortfall` still counts the doomed debt at face value and no guard stops suppliers from exiting. `require_backed_market` gates `supply` only; `withdraw` runs `require_reserves`, `require_utilization_below_max` (which may be disabled or not yet breached), and `require_supply_for_debt`, but never checks backing. A supplier who exits first is paid in full at the stale index; the write-down then concentrates the entire loss onto whoever remains.

### Finding Description
`withdraw::gate_and_debit` enforces only `require_reserves` (cash on hand), `require_utilization_below_max`, and `require_supply_for_debt` — `require_backed_market` is deliberately not called on exits [1](#0-0) . `backing_shortfall` values outstanding debt with `unscale_borrow_ceil`, i.e. at face, until a seize burns it [2](#0-1) . The write-down that socializes the loss happens only inside `seize_positions` for `AccountPositionType::Borrow` [3](#0-2) . So the sequence:

1. Borrower's collateral crashes; the position is deeply insolvent — bad debt exists economically but is not yet booked.
2. Attacker calls `controller::withdraw` (pool `withdraw` with `is_liquidation = false`) and redeems all supply shares at the un-written-down `supply_index`, draining real cash.
3. A liquidator calls `liquidate`/`clean_bad_debt`; `apply_bad_debt_to_supply_index` writes `supply_index` down (floored at `SUPPLY_INDEX_FLOOR_RAW`), and the entire loss lands on the suppliers who did not exit.

This is directly demonstrated by `tests/test-harness/tests/controller/bad_debt_index.rs::supplier_can_exit_ahead_of_bad_debt_writedown`: Bob exits whole before the write-down and Carol's loss is amplified ~4x (proportional to her share of remaining supply) [4](#0-3) .

### Impact Explanation
Loss transfer / partial theft of user funds. The early withdrawer recovers tokens that economically belong to the bad-debt loss, while remaining suppliers absorb more than their pro-rata share — in the wipeout limit they are left with stranded floor-clamped claims that cannot be paid without `recapitalize`. This is the exact analog of the OpenQ issue: after the market's fate is sealed (competition closed / borrower irrecoverably insolvent), a refund-style exit leaves the contract underfunded for the parties still entitled to claim.

### Likelihood Explanation
Reachable by any unprivileged supplier via `controller::withdraw`. The trigger condition — a collateral crash creating insolvency — is routine market volatility, and the window between crash and write-down persists until any liquidator or keeper calls `liquidate`/`clean_bad_debt`. Large, fast suppliers (or anyone monitoring the oracle) are systematically incentivized to dodge, so in stressed markets the race to exit is the expected behavior. The attacker needs only an existing supply position, which they can hold passively.

### Recommendation
Apply the write-down at exit time, not only at seize time. Options:

- Before processing a `withdraw`, have the pool (or controller batch) socialize any debt whose collateral book can no longer cover it — i.e., run the bad-debt leg synchronously rather than waiting for a liquidation call, so exits always price at the post-write-down index.
- Alternatively, gate `withdraw` (and `net_settle`, `claim_revenue`) with `require_backed_market`, so no supplier can exit while the book carries face-valued unrecoverable debt; exits resume once `clean_bad_debt`/`seize_positions` books the loss. This mirrors the report's recommendation that exit be blocked until entitled claims are settled.
- Document that `require_supply_for_debt` and the utilization gate do not substitute for a backing check on exits [5](#0-4) .

### Proof of Concept
See `tests/test-harness/tests/controller/bad_debt_index.rs:401-473` (`supplier_can_exit_ahead_of_bad_debt_writedown`):

```rust
// Bob 75% + Carol 25% of ETH supply; Alice borrows ETH vs USDC.
b.set_price("USDC", usd_cents(10));   // Alice irrecoverably insolvent
b.assert_liquidatable(ALICE);

b.withdraw_all(BOB, "ETH");           // exit at pre-write-down index
b.liquidate(LIQUIDATOR, ALICE, "ETH", 0.001); // write-down hits Carol alone

assert!(carol_loss_b > carol_loss_a); // ~4x amplification
assert!(bob_recovered >= bob_before_b); // Bob exits whole
```

The same mechanism underlies `contracts/pool/tests/flows.rs:3170-3250` and `contracts/pool/tests/interest.rs:316-495`, which show stranded floor-clamped claims draining fresh cash once `require_reserves` is the only gate between a wiped book and a withdrawal.

### Citations

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

**File:** contracts/pool/src/guards.rs (L61-66)
```rust
pub(crate) fn backing_shortfall(cache: &Cache) -> i128 {
    let supplied_claim = cache.unscale_supply_floor(cache.supplied());
    let outstanding_debt = cache.unscale_borrow_ceil(cache.borrowed());
    let backing = cache.cash().saturating_add(outstanding_debt);
    supplied_claim.saturating_sub(backing).max(0)
}
```

**File:** contracts/pool/src/guards.rs (L69-73)
```rust
pub(crate) fn require_supply_for_debt(env: &Env, cache: &Cache) {
    if cache.supplied() == Ray::ZERO && cache.borrowed() != Ray::ZERO {
        panic_with_error!(env, CollateralError::PoolInsolvent);
    }
}
```

**File:** contracts/pool/src/ops/seize.rs (L23-28)
```rust
    match entry.side {
        AccountPositionType::Borrow => {
            let bad_debt = cache.unscale_borrow_ceil_ray(position);
            interest::apply_bad_debt_to_supply_index(&mut cache, bad_debt);
            cache.burn_debt(position);
        }
```

**File:** tests/test-harness/tests/controller/bad_debt_index.rs (L401-462)
```rust
#[test]
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
    );
```
