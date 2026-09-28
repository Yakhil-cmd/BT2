### Title
Withdraw is not gated on real backing: a supplier can exit at the pre-write-down index while `backing_shortfall` still values unrecoverable debt at face, socializing the full loss onto remaining suppliers - (File: contracts/pool/src/guards.rs)

### Summary

The Fei report concerns three different valuations of the same position (deposit, withdrawal, `resistantBalanceAndFei`) so that total PCV/collateralization shifts discontinuously depending on which path runs. XOXNO Lending has the same shape: a market's backing check (`backing_shortfall` in `contracts/pool/src/guards.rs`) counts outstanding debt at face value (ceiled) even after the borrower is provably insolvent, and the supply index is only written down when `seize_positions` runs inside `liquidate`/`clean_bad_debt`. `withdraw` performs no backing check at all, so a supplier who exits before the write-down is paid at the unimpaired index while the loss is later concentrated onto whoever stays.

### Finding Description

`backing_shortfall` values claims as `unscale_supply_floor(supplied)` and backing as `cash + unscale_borrow_ceil(borrowed)` — i.e., all debt is treated as fully recoverable even when the borrower's collateral has collapsed [1](#0-0) . The only caller of `require_backed_market` is `supply` [2](#0-1) ; `withdraw` never invokes it. The loss only becomes real when the controller calls `seize_positions` on the borrow side, which lowers `supply_index` via `interest::apply_bad_debt_to_supply_index` [3](#0-2) . `require_liquidation_buffer` guards only debt minting, not exits [4](#0-3) .

So between the price crash that makes an account insolvent and the clean-up/liquidation that socializes the debt, the pool's reported backing and the realizable backing diverge — the exact inconsistency class from the Fei report. The repo's own test `supplier_can_exit_ahead_of_bad_debt_writedown` demonstrates the value transfer: Bob withdraws whole after the crash, and Carol's loss is amplified ~4x relative to the passive case [5](#0-4) .

### Impact Explanation

Theft of user funds / unfair socialized loss: an unprivileged supplier (or any user who can open a supply position, subject to the supply gate being pre-crash) monitors for a crash, calls `controller::withdraw` to exit at the pre-write-down index, and pulls real cash out of the pool. When `clean_bad_debt` or `liquidate` later runs `seize_positions`, the entire bad debt is written down onto the reduced `supplied` base, concentrating the loss onto remaining suppliers who recover proportionally less than pro-rata. The test pins `bob_recovered >= bob_before_b` and `carol_loss_b > 3 * carol_loss_a` [6](#0-5) .

### Likelihood Explanation

Reachable by a single unprivileged address through `controller::withdraw`; the trigger (a public price crash leaving an insolvent account) is externally visible before any keeper executes cleanup, and `clean_bad_debt` is permissionless only for ≤$5 dust collateral — larger bad debt waits for liquidation timing, leaving a wider exit window [7](#0-6) . No privileged role or timing privilege is needed; any holder of supply shares in the debt market can dodge.

### Recommendation

Gate `withdraw` (at least the portion that would leave claims unbacked) on `require_backed_market`, or count insolvent debt conservatively in `backing_shortfall` — e.g., cap the debt valuation at the collateral actually backing it using cached position/threshold data — so that the same liability value is used at entry, exit, and write-down. Alternatively, perform the write-down eagerly during withdrawal-triggered accrual, or apply the socialized-loss factor to withdrawal proceeds rather than to the index only at cleanup time.

### Proof of Concept

1. Bob supplies 75 ETH and Carol supplies 25 ETH to market ETH; Alice supplies USDC collateral and borrows 0.003 ETH.
2. USDC price crashes (test uses `usd_cents(10)`), making Alice's ETH debt unrecoverable. No write-down has run; `backing_shortfall` still counts Alice's debt at face (`unscale_borrow_ceil`), so the book claims full backing.
3. Bob calls `withdraw` for his whole ETH position and is paid out at the pre-write-down supply index (`bob_recovered >= bob_before_b`).
4. Anyone calls `liquidate`/`clean_bad_debt`; `seize_positions` writes Alice's debt down onto the now-smaller `supplied` base, so Carol's claim absorbs the entire loss — ~4x her pro-rata share. This exact sequence is implemented and asserted in `supplier_can_exit_ahead_of_bad_debt_writedown` [8](#0-7) .

### Citations

**File:** contracts/pool/src/guards.rs (L36-47)
```rust
/// Panics with `InsufficientLiquidity` if drawing `draw` leaves cash below the liquidation buffer.
///
/// Every debt mint checks it, borrows and strategy openings alike (INV-ACCT-07). Exits do not.
pub(crate) fn require_liquidation_buffer(env: &Env, cache: &Cache, draw: i128) {
    let supplied = cache.unscale_supply_floor(cache.supplied());
    let reserved = mul_div_ceil(env, supplied, LIQUIDATION_BUFFER_BPS, BPS);
    assert_with_error!(
        env,
        cache.cash().saturating_sub(draw) >= reserved,
        CollateralError::InsufficientLiquidity
    );
}
```

**File:** contracts/pool/src/guards.rs (L60-66)
```rust
/// Asset units by which supplier claims exceed cash + debt (0 if solvent).
pub(crate) fn backing_shortfall(cache: &Cache) -> i128 {
    let supplied_claim = cache.unscale_supply_floor(cache.supplied());
    let outstanding_debt = cache.unscale_borrow_ceil(cache.borrowed());
    let backing = cache.cash().saturating_add(outstanding_debt);
    supplied_claim.saturating_sub(backing).max(0)
}
```

**File:** contracts/pool/src/ops/supply.rs (L26-26)
```rust
    guards::require_backed_market(env, &cache);
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

**File:** tests/test-harness/tests/controller/bad_debt_index.rs (L401-474)
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

    std::println!(
        "A4-econ dodge: bob_supplied={:.9} bob_recovered={:.9} \
         carol_loss_passive={:.9} carol_loss_after_dodge={:.9} amplification={:.3}x",
        bob_before_b,
        bob_recovered,
        carol_loss_a,
        carol_loss_b,
        amplification
    );
}

```

**File:** docs/reference/invariants.md (L463-475)
```markdown
### INV-LIQ-04 — Bad-debt socialization is explicit and total

Permissionless cleanup requires ceil risk debt greater than half-up unweighted
collateral and collateral at or below the fixed $5 dust threshold. Owner-only
forced cleanup omits the dust cap. Both require debt, readable account and NFT
state, valid required prices and no active flash guard. Listing flags and
global pause do not block standalone cleanup.

Cleanup reclassifies all remaining collateral shares as revenue and writes off
all remaining debt against each debt's market. It releases spoke usage and
atomically removes account entries and the NFT. It does not net same-market
supply against debt. Standalone cleanup emits `CleanBadDebtEvent` with
pre-cleanup USD totals, without a controller position-update batch.
```
