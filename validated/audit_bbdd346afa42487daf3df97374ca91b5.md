The external report is an integer overflow → DoS in a resize function. In this codebase the multiply-divide primitives in `common/src/math/fp_core.rs` widen to `I256` correctly, so intermediate products cannot wrap — but the *result* must still fit `i128`. That maps onto the RAY share-value computations: `scaled_to_original(borrowed, borrow_index)` panics with `MathOverflow` when `borrowed_scaled * borrow_index / RAY > i128::MAX`, and every pool verb accrues before acting.

### Title
Overflow of RAY debt value permanently freezes a market — an attacker can pin `borrowed_scaled` near `i128::MAX` so the first accrual past index 1.0 bricks supply, borrow, withdraw, repay and liquidation - (File: common/src/rates/scaling.rs)

### Summary
`scaled_to_original` computes `scaled * index` in RAY and panics with `GenericError::MathOverflow` when the result exceeds `i128`. Because `global_sync` runs `accrue_step` before every mutating entrypoint, a market whose scaled borrow shares sit close enough to `i128::MAX` that index growth beyond `1.0` overflows becomes permanently unusable: the accrual always reverts, so no exit, repayment, or liquidation can ever execute. Unlike the multi-year scenario documented in the test suite, an attacker can reach this state immediately by supplying and borrowing a near-cap position in a low-decimals asset, since scaled share amounts are allowed to approach `i128::MAX` while the index starts at exactly `RAY` and only grows.

### Finding Description
`accrue_step` in `common/src/rates/simulate.rs` (lines 51–94) calls `scaled_to_original(env, borrowed, borrow_index)` and `scaled_to_original(env, supplied, supply_index)`. `scaled_to_original` in `common/src/rates/scaling.rs` is `scaled.mul(env, index)`, which resolves to `fp_core::mul_div_half_up`; that function returns `MathOverflow` when the quotient does not fit `i128` (`fp_core.rs:108–118`, `try_mul_div_half_up` returning `None` when `.to_i128()` fails at line 142).

`update_borrow_index` is monotone and capped at `MAX_BORROW_INDEX_RAY` (10^36 raw), so the index always lands above `RAY` after any elapsed time. If `borrowed_scaled > i128::MAX * RAY / borrow_index'`, the very first `accrue_step` reverts. `PoolState.supplied`/`borrowed` are RAY-scaled share counts (`amount * 10^(27 - decimals)`), and `require_cap_within_asset_domain` / `max_cap_for_decimals` (`common/src/validation.rs:48–56`) permit scaled caps up to `i128::MAX` itself — for a 0-decimal asset the cap domain allows ~1.7e11 whole tokens, i.e. scaled shares up to ~1.7e38 ≈ `i128::MAX`.

`contracts/pool/src/interest.rs::global_sync` (lines 20–33) runs before every mutating op, so once `borrowed_scaled * borrow_index' / RAY > i128::MAX` every subsequent call reverts in accrual — permanently. The project's own harness test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:316–362`) proves the freeze: once `scaled_to_original` overflows inside accrual, `try_withdraw_raw` and `try_repay` revert with `MATH_OVERFLOW` and `update_indexes` can never commit. That test reaches the cliff via index growth over years; the same cliff is reachable immediately by making the scaled share count itself huge, because the index cap at `MAX_BORROW_INDEX_RAY` does not prevent `scaled * index` from exceeding `i128`.

### Impact Explanation
Permanent freezing of funds. All suppliers' deposits and all borrower collateral routed through the frozen market's books become unrecoverable: `withdraw`, `repay`, `liquidate`, `clean_bad_debt`, `recapitalize`, and `update_indexes` all begin with accrual and all revert with `MathOverflow`. There is no admin escape hatch that bypasses `global_sync`. This is not a fail-closed reverting-input issue — the state transition itself is poisoned, so no transaction touching the market can ever succeed again.

### Likelihood Explanation
A single unprivileged address can set this up with `controller.supply` and `controller.borrow` (or direct pool supply plus borrow). The attacker supplies a low-decimals asset with a high supply cap (e.g. decimals = 0, where the domain cap is ~1.7e11 tokens → scaled ~1.7e38 ≈ `i128::MAX`), then borrows as much as the borrow cap/LTV allows on the same or another book so `borrowed_scaled` is within a factor of `(1 + epsilon)` of `i128::MAX`. The next ledger timestamp advance makes `borrow_index' > RAY`, and `scaled_to_original(borrowed, borrow_index')` overflows on the very next touch — no multi-year wait is needed because the share count, not index growth, provides the magnitude. Feasibility depends on the attacker acquiring enough of a low-decimals token, which is capital-intensive for an established asset but trivial for a freshly listed high-supply token. Medium likelihood, permanent impact.

### Recommendation
Bound scaled share amounts far below the overflow cliff: enforce at mint time (`calculate_scaled_supply`, `calculate_scaled_borrow` in `common/src/rates/scaling.rs`) that `scaled_amount * MAX_*_INDEX_RAY / RAY` fits `i128`, i.e. cap shares at roughly `i128::MAX / 10^9` so that any index up to the 10^36 ceiling cannot overflow a share→value conversion. Alternatively, make `accrue_step` clamp `borrowed`/`supplied` valuations via `mul_div_floor_saturating` instead of panicking, and add a market-level check that rejects supply/borrow mutations that would push scaled totals past the representable-value bound.

### Proof of Concept
```
// Assuming a listed 0-decimals market "D0" whose cap domain permits ~1.7e11 tokens
// (max_cap_for_decimals(0) = i128::MAX / 10^27 ≈ 1.7e11).
// 1. Attacker supplies cap_max tokens:
//    controller.supply(hub(D0), attacker, 170_141_183_460)
//    scaled_supplied ≈ 1.7e11 * 10^27 ≈ i128::MAX
// 2. Attacker posts collateral in another market and borrows nearly all of it:
//    controller.borrow(hub(D0), attacker, ~cap_max)
//    scaled_borrowed ≈ i128::MAX  (debt minted at ceil)
// 3. Wait one ledger second and call controller.update_indexes([hub(D0)])
//    -> global_sync -> accrue_step
//    -> borrow_index' = update_borrow_index(RAY, factor > RAY) > RAY
//    -> scaled_to_original(borrowed, borrow_index')
//       = i128::MAX * (RAY + ε) / RAY  > i128::MAX
//    -> MathOverflow, state.last_timestamp NOT advanced
// 4. Every subsequent call — withdraw, repay, liquidate, clean_bad_debt,
//    update_indexes — re-runs the same accrue_step and reverts identically.
//    Market is permanently frozen; supplier funds are unrecoverable.
```
The harness test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` already demonstrates the same permanent-freeze mechanics (withdraw and repay both reverting with `MATH_OVERFLOW` after the index-accrual overflow), differing only in reaching the cliff via index growth rather than share magnitude.