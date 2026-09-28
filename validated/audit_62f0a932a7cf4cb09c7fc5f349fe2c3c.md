### Title
Sustained high-utilization whale debt overflows accrual valuation and permanently freezes a market - ([File: common/src/rates/simulate.rs](common/src/rates/simulate.rs))

### Summary
Market accrual converts scaled debt and supply shares back to RAY-denominated token values before applying the bounded borrow-index update. A large borrowed book can therefore overflow `i128` before `update_borrow_index` reaches its configured ceiling. Because every pool mutation synchronizes the market first, once that boundary is crossed, repayment, withdrawal, liquidation, and further index updates all revert.

### Finding Description
`contracts/pool/src/interest.rs::global_sync` loops over elapsed time and calls `accrue_chunk` for each interval before marking the market accrued. [1](#0-0) 

Each chunk calls `common::rates::accrue_step`, which first computes `scaled_to_original(env, borrowed, borrow_index)` and `scaled_to_original(env, supplied, supply_index)` before calculating the interest-rate factor and applying `update_borrow_index`. [2](#0-1) 

The borrow index is capped only inside the later index update; it does not prevent the earlier scaled-value calculation from exceeding `i128`. Thus, a sufficiently large debt share balance multiplied by a sufficiently grown borrow index can panic with `MathOverflow` before the index ceiling is reached. [3](#0-2) 

An unprivileged user can establish the precondition through normal controller operations: supply a very large amount of the market token as pool liquidity, supply sufficient collateral in another listed asset, and borrow the target market at sustained high utilization. The harness test creates a one-billion-token 18-decimal market, lifts the configured caps to the supported literal limit, supplies the full amount, and borrows 98% of it. [4](#0-3) 

The test then advances time yearly until `update_indexes` fails with `MathOverflow`; at that point the stored borrow index remains below `MAX_BORROW_INDEX_RAY`, proving the failure occurs at the value-overflow cliff rather than at the intended index bound. [5](#0-4) 

Because accrual precedes pool mutations, the same panic then rejects both withdrawal and repayment; the test explicitly asserts that both calls fail with `MathOverflow` after the cliff is reached. [6](#0-5) 

### Impact Explanation
This permanently freezes the affected market's funds. Suppliers cannot withdraw, borrowers cannot repay, and liquidators cannot process debt because those paths must first complete market accrual. The market cannot recover through `update_indexes`, since the accrual calculation itself panics.

The attacker does not need a privileged role, leaked key, oracle manipulation, malformed token, or callback. They only need enough assets to create the oversized high-utilization book permitted by the market's configured caps and enough collateral to borrow it.

### Likelihood Explanation
Likelihood is constrained by capital requirements and market configuration: an attacker must be able to supply or cause the existence of approximately billion-whole-token scale liquidity and borrow it at sustained high utilization for enough time for the index to multiply the debt beyond the `i128` domain. Governance-configured caps and realistic token supply can prevent the condition on a particular deployment.

Nevertheless, the reachable sequence uses ordinary `supply`, `borrow`, and `update_indexes` functionality, and the repository's own regression test reaches the cliff and demonstrates that withdrawal and repayment are subsequently bricked. [7](#0-6) 

### Recommendation
Do not calculate utilization through an `i128` RAY-token value that can overflow before the index bound is applied. Options include:

- compute utilization with `I256` intermediates or a ratio-preserving scaled-share calculation that does not require full token value;
- clamp or early-return when the borrow index reaches `MAX_BORROW_INDEX_RAY` before evaluating `scaled_to_original`;
- add explicit checked-domain handling that treats value overflow as an accrual-safe saturation rather than reverting;
- enforce market caps using worst-case `scaled_shares * MAX_BORROW_INDEX_RAY`, not only token-unit exposure;
- add a migration or emergency path that can advance `last_timestamp`/cap indexes without evaluating the overflowing value, so repayment and withdrawal remain possible.

The fix should preserve the invariant that `update_indexes`, `repay`, `withdraw`, `liquidate`, and `recapitalize` remain callable even for the largest admitted share balances and index values.

### Proof of Concept
The repository contains a deterministic proof in `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs`.

1. Create an 18-decimal market using the steep stress curve and a separate collateral market.
2. Raise market caps to the supported literal maximum.
3. Supply `1_000_000_000 * 10^18` units of `BIG18` to the pool.
4. Supply enough collateral and borrow 98% of that liquidity.
5. Advance ledger time year by year and call `update_indexes` for `BIG18`.
6. The accrual eventually panics with `MathOverflow` while `borrow_index < MAX_BORROW_INDEX_RAY`.
7. Subsequent `withdraw` and `repay` calls also revert with `MathOverflow`.

The critical sequence and assertions are implemented in the existing test. [8](#0-7)

### Citations

**File:** contracts/pool/src/interest.rs (L20-32)
```rust
pub(crate) fn global_sync(env: &Env, cache: &mut Cache) {
    if !cache.needs_accrual() {
        return;
    }

    let mut remaining = cache.elapsed_ms();
    while let Some(nonzero) = NonZeroU64::new(remaining) {
        let chunk = nonzero.get().min(MAX_COMPOUND_DELTA_MS);
        accrue_chunk(env, cache, chunk);
        remaining = remaining.saturating_sub(chunk);
    }

    cache.mark_accrued();
```

**File:** common/src/rates/simulate.rs (L51-67)
```rust
pub fn accrue_step(
    env: &Env,
    params: &MarketParams,
    borrowed: Ray,
    supplied: Ray,
    borrow_index: Ray,
    supply_index: Ray,
    delta_ms: u64,
) -> AccrualStep {
    let borrowed_original = scaled_to_original(env, borrowed, borrow_index);
    let supplied_original = scaled_to_original(env, supplied, supply_index);
    let util = utilization(env, borrowed_original, supplied_original);
    let borrow_rate = calculate_borrow_rate(env, util, params);
    let interest_factor = compound_interest(env, borrow_rate, delta_ms);

    let new_borrow_index = update_borrow_index(env, borrow_index, interest_factor);

```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L315-356)
```rust
/// The cliff. A billion whole tokens is `1e36` raw ray; the value ceiling is
/// `i128::MAX`, 170 times that. At the XLM curve's steep segment the index
/// grows past 170x in a few years, and the next accrual panics inside
/// `scaled_to_original`. Every verb accrues first, so the market freezes:
/// no repay, no withdraw, no liquidation. The index cap never engages.
#[test]
fn a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap() {
    let mut t = LendingTest::new()
        .with_market(big("BIG18", 18, xlm_curve()))
        .with_market(col())
        .with_max_utilization_disabled_all_markets()
        .build();
    lift_caps(&t, "BIG18", 18);
    lift_caps(&t, "COL", 7);
    let principal = BILLION * 10i128.pow(18);
    t.supply_raw(BOB, "BIG18", principal);
    let debt = principal / 100 * 98;
    t.supply_raw(ALICE, "COL", BILLION * 10_000_000 * 3);
    t.borrow_raw(ALICE, "BIG18", debt);

    let mut years = 0u32;
    let failure = loop {
        years += 1;
        assert!(
            years <= 40,
            "no cliff within 40 years; the bound in docs/reference/formulas.md is wrong"
        );
        t.advance_time(YEAR_SECS);
        if let Err(e) = t.try_update_indexes_for(&["BIG18"]) {
            break e;
        }
    };
    let failed: Result<(), soroban_sdk::Error> = Err(failure);
    assert_contract_error(failed, errors::MATH_OVERFLOW);
    let last = book(&t, "BIG18");
    assert!(
        last.borrow_index < MAX_BORROW_INDEX_RAY,
        "the index cap did not engage before the value overflow"
    );
    // The market is frozen: exits and repayments accrue first and hit the same panic.
    assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
    assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);
```
