### Title
RAY-scaled debt value overflows `i128` inside accrual, permanently freezing a whale market (all verbs revert) - (File: common/src/rates/scaling.rs)

### Summary
The pool indexes all supply and debt in RAY (1e27) scaled shares, and every controller verb (supply, withdraw, repay, borrow, liquidate, update_indexes, claim_revenue, flash paths) runs `global_sync` accrual first. Accrual computes `borrowed * borrow_index` via `scaled_to_original`, which panics with `GenericError::MathOverflow` when the product exceeds `i128::MAX`. An unprivileged attacker can seed a market with ~1 billion whole tokens of an 18-decimal asset (within the admitted cap domain), borrow ~98% of it from a separately collateralized account, and let interest compound until the RAY debt value crosses the `i128` ceiling — which happens before the `MAX_BORROW_INDEX_RAY` index cap can engage. From that point the market is permanently frozen: accrual reverts on every call, so no supplier can withdraw, no borrower can repay, and no liquidator can seize.

### Finding Description
The accrual loop in `contracts/pool/src/interest.rs::global_sync` calls `accrue_chunk`, which calls `common::rates::accrue_step`. Its first operation is `scaled_to_original(env, borrowed, borrow_index)` at `common/src/rates/scaling.rs:14-16`, implemented as `scaled.mul(env, index)` — a half-up `x*y/RAY` that panics via `fp_core` when the quotient does not fit `i128`. Separately, `calculate_supplier_rewards` at `common/src/rates/index.rs:80-83` multiplies `borrowed` by both the old and new borrow index.

The borrow index is capped only *after* the multiply, at `MAX_BORROW_INDEX_RAY` (1e36, i.e. 1e9 × initial index) in `update_borrow_index` (`common/src/rates/index.rs:13-19`). But the *value* ceiling is much lower: with `borrowed` scaled shares near `i128::MAX / index`, accrual overflows while the index is still far below its cap. The harness test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321-361`) demonstrates exactly this: after advancing time on a 1-billion-token book at 98% utilization on the steep XLM curve (max_borrow_rate = 1.75×RAY), `update_indexes` fails with `MathOverflow` with `borrow_index < MAX_BORROW_INDEX_RAY`, and subsequent `withdraw` and `repay` fail with the same error — because the failed accrual never advances `last_timestamp`, every future call re-executes the same overflowing multiplication.

The reachable path for a single unprivileged address:
1. `supply(caller=A, account_id=0, spoke_id, assets=[(hub, BIG), 1e9 whole tokens])` — the admitted cap domain allows up to `i128::MAX / 10^(27-d)` ≈ 170 billion whole tokens for 18 decimals, so a governance-admitted cap near the domain maximum permits this deposit; `require_backed_market` and position limits pass.
2. On a second account, supply collateral in another listed market and `borrow(caller=A, account_id=B, borrows=[(hub, BIG), ~0.98 × supply])` — passes `require_liquidation_buffer`/`require_utilization_below_max` if `max_utilization` permits high utilization (governance can set it up to `RAY`), and the borrower's HF is safe because the debt is fully collateralized in the collateral market.
3. Do nothing (or periodically keep the position solvent via the collateral leg). Time — not any transaction — pushes `borrowed × borrow_index` past `i128::MAX`. The attacker can then call the permissionless `update_indexes` to trigger the panic, but the freeze is inevitable: *any* user's next interaction with the market runs the same accrual and panics.

Note the attacker does not need to be liquidated: the debt is overcollateralized in a *different* market, so HF > 1 blocks `liquidate`, and `clean_bad_debt` requires insolvency. Even if the account later becomes liquidatable, liquidation itself accrues first and reverts.

### Impact Explanation
Permanent freezing of funds for every supplier in the market. Once the RAY debt value overflows, `global_sync` panics inside `scaled_to_original`/`calculate_supplier_rewards` before writing `last_timestamp`, so the panic is repeatable forever: `withdraw`, `repay`, `borrow`, `liquidate`, `claim_revenue`, `flash_loan`, `recapitalize`, and `update_indexes` all accrue first and all revert. Suppliers' tokens (including honest third-party suppliers in the same hub-spoke market) are locked in the pool contract with no exit path, and borrowers cannot repay — a permanent freeze and de facto protocol insolvency for that market. `recapitalize` cannot rescue it because it also accrues first. This maps the CVE's "overflow → denial of service" class onto a persistent, funds-freezing DoS rather than a transient crash.

### Likelihood Explanation
The attack requires a very large token position (~1 billion whole units of an 18-decimal token) and a market admitted with both a near-maximum cap and a steep rate curve (the demonstrated curve uses 175% max borrow rate; the protocol maximum is 200% APR). Those are governance-admission conditions, not privileged actions — once a cap and curve exist, the attacker needs only tokens and patience. The sequence is realistic for high-decimal, low-unit-price tokens (e.g., memecoins or LP tokens) where a billion whole units is affordable. Accrual is millisecond-chunked at `MAX_COMPOUND_DELTA_MS` (one year), but chunking does not help: each chunk recomputes `borrowed × borrow_index` and overflows on the same multiplication. The condition is self-sustaining because no one can intervene — repay, liquidate, and recapitalize all revert on the same overflow. Likelihood is constrained by the capital requirement and dependence on admitted cap/curve configuration, consistent with Medium severity.

### Recommendation
Saturate rather than panic on debt/supply value overflow inside accrual. Concretely:

- In `accrue_step` (`common/src/rates/simulate.rs:51-94`), compute `borrowed × borrow_index` with a saturating variant (e.g., reuse `mul_div_floor_saturating` semantics for `scaled_to_original` on the accrual path, or pre-check `borrowed > i128::MAX / new_borrow_index` and clamp the effective index for the debt valuation). The borrow-index cap at `update_borrow_index` is ineffective because it engages after the multiply; check `old_index > MAX / factor` and clamp `factor` before multiplying.
- Alternatively, advance `last_timestamp` even when a chunk's arithmetic would overflow — e.g., catch the overflowed chunk, write `borrow_index = MAX_BORROW_INDEX_RAY` and move the timestamp forward — so the market degrades to a capped-index state (no further interest, per INV-IDX-01) instead of a hard freeze.
- At listing/admission time, bound `cap × MAX_BORROW_INDEX_RAY × 10^27` to fit `i128` with margin, so an admitted cap can never produce a debt value that overflows before the index cap engages.

### Proof of Concept
The existing harness test demonstrates the full reachable sequence and its consequences (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321-361`):

```rust
// Setup: 18-decimal token "BIG18" on the steep XLM curve
// (max_borrow_rate = 1.75*RAY, optimal_utilization = 0.75*RAY),
// caps lifted to the admitted domain maximum.
let principal = BILLION * 10i128.pow(18);          // 1e9 whole tokens
t.supply_raw(BOB, "BIG18", principal);             // attacker/supplier book
let debt = principal / 100 * 98;                   // ~98% utilization
t.supply_raw(ALICE, "COL", BILLION * 10_000_000 * 3); // separate collateral
t.borrow_raw(ALICE, "BIG18", debt);                // attacker debt leg

// Advance time year-by-year until accrual panics:
loop {
    t.advance_time(YEAR_SECS);
    if let Err(e) = t.try_update_indexes_for(&["BIG18"]) { break e; }
}
// => GenericError::MathOverflow, with borrow_index still < MAX_BORROW_INDEX_RAY
//    (the index cap never engages — the value multiply overflows first).

// Permanent freeze: every verb re-runs the same overflowing accrual.
assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);
```

Supporting code:

- Panicking multiply used by accrual: `scaled_to_original` → `scaled.mul(env, index)` (`common/src/rates/scaling.rs:14-16`), which routes to `fp_core::mul_div_floor` panicking with `MathOverflow` on result overflow (`common/src/math/fp_core.rs:148-159` via `to_i128`).
- Accrual runs on every mutation: `global_sync` loops `accrue_chunk` → `accrue_step` (`contracts/pool/src/interest.rs:20-53`); `accrue_step`'s first lines are the two `scaled_to_original`/`calculate_supplier_rewards` multiplications (`common/src/rates/simulate.rs:60-69`, `common/src/rates/index.rs:80-81`).
- Index cap applied too late: `update_borrow_index` caps only the *result* of `old_index.mul(interest_factor)` at `MAX_BORROW_INDEX_RAY` (`common/src/rates/index.rs:13-19`).
- Because the panic occurs before `cache.mark_accrued()`, `last_timestamp` never advances, so the same chunk overflows on every subsequent call — the freeze is permanent, not transient.