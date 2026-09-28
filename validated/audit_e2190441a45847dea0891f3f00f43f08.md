### Title
Interest accrual panics on i128 overflow once `borrowed × borrow_index` exceeds representable debt, permanently bricking the market - (File: common/src/rates/simulate.rs)

### Summary
The crafted-input crash class of CVE-2017-11640 (address-access exception on hostile data) maps onto Soroban as an unhandled arithmetic panic on attacker-influenced state. In `accrue_step`, the very first operation unscales the debt book with `borrowed.mul(env, borrow_index)` via `scaled_to_original`, which bottoms out in `mul_div_half_up` and panics with `GenericError::MathOverflow` when the product exceeds `i128`. `update_borrow_index` multiplies the index by the growth factor *before* clamping to `MAX_BORROW_INDEX_RAY`, so the clamp does not prevent the intermediate overflow. Because `interest::global_sync` runs this step at the head of every pool mutation (`supply`, `withdraw`, `borrow`, `repay`, `flash_loan`, `claim_revenue`, `net_settle`, `seize_positions`, and the permissionless `update_indexes`), once the product overflows the market can never accrue again and every entrypoint reverts forever.

### Finding Description
- `common/src/rates/simulate.rs:60` — `scaled_to_original(env, borrowed, borrow_index)` computes `half_up(borrowed * borrow_index / RAY)`. `mul_div_half_up` (`common/src/math/fp_core.rs:108-118`) widens to `I256` and then `to_i128()` returns `None` on overflow, producing a `MathOverflow` panic — a revert, not a clamp.
- `common/src/rates/index.rs:13-18` — `update_borrow_index` computes `old_index.mul(interest_factor)` and only afterwards caps at `MAX_BORROW_INDEX_RAY` (1e36). A scaled debt book of moderate size therefore overflows well before the index reaches the cap: `borrowed_scaled * 1e36 > i128::MAX ≈ 1.7e38` is crossed once the outstanding scaled debt exceeds roughly `1.7e29` RAY-units (≈170 units of a 7-decimal token's RAY-scaled shares) while the index is near the cap, and proportionally earlier for larger books.
- The protocol's own invariant documentation acknowledges the hole: "Debt-value overflow can still revert accrual before that ceiling is reached. Bounded indexes do not guarantee representable position or market values" (`docs/reference/invariants.md`, INV-IDX-01).
- `contracts/pool/src/interest.rs:20-33` — `global_sync` loops `accrue_chunk` until the elapsed time is consumed; there is no try/catch or skip path. A panic in any chunk aborts the entire transaction, and since `last_timestamp` is never advanced past the failing window, the condition is permanent.
- The same exposure exists on the supply side at `simulate.rs:61` (`supplied.mul(supply_index)`) and inside `update_supply_index`, reachable by an account supplying a very large scaled position.
- There is no recovery lever: accrual is embedded inside every mutating op rather than a separate step governance could bypass, and no entrypoint writes `borrow_index`/`borrowed` down except `repay`/`seize`/`clean_bad_debt`, all of which call `global_sync` first and therefore revert too.

### Impact Explanation
Permanent freezing of funds. Once `borrowed × borrow_index` (or `supplied × supply_index`) crosses the `i128` bound, every pool operation on that market — withdrawals of all suppliers' principal and yield, repayments, liquidations, `update_indexes`, `claim_revenue`, `recapitalize`, and `clean_bad_debt` — reverts unconditionally inside `accrue_step`. All cash held by the pool for that (hub, token) book is permanently locked; there is no privileged escape hatch because the index can only be changed by code paths that themselves accrue first.

### Likelihood Explanation
Reachable by a single unprivileged address using only the sanctioned surface: `supply` + `borrow` (to create a large fixed scaled-debt book) plus passage of time, optionally accelerated by keeping utilization pinned at the rate-cap end of the curve so `borrow_rate` approaches `MAX_BORROW_RATE_RAY` (2 RAY, i.e. ~200% APR, compounding ≈7.39× per year-chunk). No governance action, oracle manipulation, or leaked key is required — the attacker merely originates debt and lets interest accrue. The triggering condition requires either a large borrow book or years of accrual at high rates, so likelihood is moderate rather than high; however the attacker bears no cost beyond their own position, and nobody — including governance — can avert or reverse the freeze once the threshold is crossed.

### Recommendation
Make the unscale paths saturating or cap-aware inside accrual:
- In `accrue_step`, compute `borrowed_original` / `supplied_original` through a saturating variant (analogous to `mul_div_floor_saturating` already used by `update_supply_index`/`protocol_fee_shares`), or detect overflow and clamp utilization to `RAY`.
- In `calculate_supplier_rewards`, clamp `new_borrow_index` to the largest value for which `borrowed * new_index` fits `i128`, and advance `last_timestamp` even on the clamped step so the market cannot be stuck.
- Alternatively, bound `borrowed`/`supplied` scaled totals at mint time (`supply`, `borrow`, revenue share minting) so that `scaled * MAX_INDEX` provably stays within `i128`.
- Add a regression test that drives `global_sync` with `borrowed` such that `borrowed * MAX_BORROW_INDEX_RAY > i128::MAX` and asserts the call completes rather than reverting.

### Proof of Concept
1. Via controller `supply` + `borrow`, attacker opens a position with scaled debt `B` such that `B > i128::MAX / MAX_BORROW_INDEX_RAY` (≈170 RAY-scaled units of a 7-decimal token at the cap; smaller indexes admit proportionally larger `B`). Alternatively a whale supplies `S` with `S * supply_index` near the bound.
2. Utilization on the market is driven high (attacker's own borrow does this), pushing `borrow_rate` toward `MAX_BORROW_RATE_RAY`.
3. Time elapses. Each permissionless `update_indexes` call raises `borrow_index` toward `1e36`. The call where `B * new_index` exceeds `i128::MAX` reverts in `scaled_to_original` (`simulate.rs:60` → `fp_core::mul_div_half_up` → `MathOverflow`).
4. Every subsequent `withdraw`, `repay`, `liquidate`, `clean_bad_debt`, `claim_revenue`, and `update_indexes` transaction reverts in the same `global_sync` → `accrue_step` → `scaled_to_original` sequence. The pool's cash for that market is frozen permanently; suppliers cannot exit and liquidators cannot unwind the attacker's (now liquidatable) position. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** common/src/rates/simulate.rs (L60-69)
```rust
    let borrowed_original = scaled_to_original(env, borrowed, borrow_index);
    let supplied_original = scaled_to_original(env, supplied, supply_index);
    let util = utilization(env, borrowed_original, supplied_original);
    let borrow_rate = calculate_borrow_rate(env, util, params);
    let interest_factor = compound_interest(env, borrow_rate, delta_ms);

    let new_borrow_index = update_borrow_index(env, borrow_index, interest_factor);

    let (supplier_rewards, protocol_fee) =
        calculate_supplier_rewards(env, params, borrowed, new_borrow_index, borrow_index);
```

**File:** common/src/rates/index.rs (L13-18)
```rust
pub fn update_borrow_index(env: &Env, old_index: Ray, interest_factor: Ray) -> Ray {
    let new_index = old_index.mul(env, interest_factor);
    if new_index.raw() > MAX_BORROW_INDEX_RAY {
        return Ray::from(MAX_BORROW_INDEX_RAY);
    }
    new_index
```

**File:** contracts/pool/src/interest.rs (L20-33)
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
}
```

**File:** common/src/math/fp_core.rs (L108-118)
```rust
pub fn mul_div_half_up(env: &Env, x: i128, y: i128, d: i128) -> i128 {
    // The zero check runs first so debug and release builds agree on a zero
    // divisor: both surface `DivisionByZero` rather than tripping the assert.
    require_nonzero_divisor(env, d);
    debug_assert!(
        x >= 0 && y >= 0 && d > 0,
        "mul_div_half_up: non-negative x, y and positive d"
    );
    try_mul_div_half_up(env, x, y, d)
        .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow))
}
```

**File:** docs/reference/invariants.md (L229-237)
```markdown
### INV-IDX-01 — Borrow index is monotone and bounded

Both indexes start at one RAY. Successful accrual with validated rate parameters
cannot lower the borrow index and caps it at the protocol constant 10^36 raw
RAY. At the ceiling, further accrual produces no borrower interest.

Debt-value overflow can still revert accrual before that ceiling is reached.
Bounded indexes do not guarantee representable position or market values.

```
