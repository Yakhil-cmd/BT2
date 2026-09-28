### Title
Accrual math overflow permanently freezes a market before the borrow-index cap engages - (File: contracts/pool/src/interest.rs)

### Summary
The bug class is an availability failure: a reachable code path that panics on every subsequent call. On XOXNO Lending, interest accrual in `global_sync`/`accrue_chunk` runs before every state-changing pool verb, and it calls `scaled_to_original(borrowed, borrow_index)` / `scaled_to_original(supplied, supply_index)` to compute utilization. Once the RAY-scaled total value no longer fits in `i128`, these multiplications panic with `MathOverflow`. Because every entrypoint accrues first, the market becomes permanently unusable — no repay, withdraw, borrow, liquidation, or `update_indexes` succeeds — while the borrow index is still below `MAX_BORROW_INDEX_RAY`, so the intended cap never engages to stop accrual safely.

### Finding Description
- `global_sync` (`contracts/pool/src/interest.rs:20-33`) chunks elapsed time and calls `accrue_chunk`, which invokes `accrue_step` over `cache.borrowed()`, `cache.supplied()`, and the stored indexes (`contracts/pool/src/interest.rs:39-53`).
- Inside `accrue_step` (mirrored exactly in `tests/fuzz/fuzz_targets/rates_and_index.rs:282-324`), utilization is computed via `scaled_to_original(env, borrowed, borrow_index)` and `scaled_to_original(env, supplied, supply_index)`.
- `scaled_to_original` is `scaled.mul(env, index)` (`common/src/rates/scaling.rs:14-16`), which panics with `GenericError::MathOverflow` when `scaled * index / RAY` exceeds `i128` (`common/src/math/fp_core.rs:148-159`).
- The borrow index is only capped *after* the multiplication inside `update_borrow_index` (`common/src/rates/index.rs:13-19`); nothing bounds `borrowed * borrow_index` or `supplied * supply_index`. `docs/reference/formulas.md:432-437` acknowledges that "value overflow can occur before the index ceiling and block repayment/withdrawal because those operations accrue first."
- The pool cache wraps this for every verb: `calculate_utilization` (`contracts/pool/src/cache/scale.rs:19-27`) and `unscale_borrow`/`unscale_supply`/`resolve_repay`/`resolve_withdrawal` (`contracts/pool/src/cache/scale.rs:50-104`) all hit the same `i128` overflow once the market is past the value ceiling.
- The harness test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321-356`) demonstrates the end state concretely: `update_indexes` reverts with `MATH_OVERFLOW`, and subsequent `withdraw` and `repay` revert identically while `borrow_index < MAX_BORROW_INDEX_RAY`.

Reachability for a single unprivileged address: supply a large amount into a high-decimals market (`supply` on the controller), push utilization high via `borrow` (direct token transfers to the pool and self-borrowed positions are within the allowed actions), then call the permissionless `update_indexes` repeatedly to accrue. Once `supplied * supply_index` or `borrowed * borrow_index` crosses `i128::MAX`, every subsequent call — including other suppliers' `withdraw` and any liquidator's `liquidate` — panics. There is no recovery path: `recapitalize` and `clean_bad_debt` also pass through accrual/unscale math on the same cache.

### Impact Explanation
Permanent freezing of funds / contract unable to operate. After the value ceiling is crossed, the market is bricked in a terminal state: suppliers cannot withdraw, borrowers cannot repay, liquidators cannot clear positions, and protocol revenue cannot be claimed — every path accrues first and panics in `scaled_to_original`. Unlike the documented "fail-closed" rejection pattern, this is a latent arithmetic boundary that the borrow-index cap was designed to prevent but fails to, because the value-level overflow precedes the index-level clamp.

### Likelihood Explanation
Medium. Triggering requires a whale-scale position (on the order of `i128::MAX / 10^(27-decimals)` raw units, up to ~170 billion whole tokens) and sustained high utilization so indexes grow. That is capital-intensive but permissionless: any address can supply and borrow, and `update_indexes` is open to all callers. The protocol itself documents the bound and ships a test proving the cliff is reachable, confirming it is a real code path rather than a theoretical one. Once reached, the freeze is irreversible since no governance escape path bypasses accrual.

### Recommendation
- Bound accrual inputs, not just the index: cap `borrowed`/`supplied` growth or clamp `scaled_to_original` during utilization computation so accrual degrades gracefully instead of panicking.
- Engage the index cap *before* the value overflow can occur, or skip `calculate_utilization`/revenue-mint steps once `borrow_index == MAX_BORROW_INDEX_RAY` (the cap-sticky path in `update_borrow_index` already treats further accrual as no-op for interest).
- Alternatively, make `accrue_step` use saturating math for the utilization computation (as `mul_div_floor_saturating` in `common/src/math/fp_core.rs:180-201` already does for caps), so a saturated utilization clamps the rate curve instead of aborting the transaction.

### Proof of Concept
The existing test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321-361`) is a working PoC using only unprivileged flows:
1. Supply `1e9 * 10^18` raw units of an 18-decimal market and borrow ~98% of it.
2. Advance time and call the permissionless `update_indexes` until the call reverts.
3. Observe `MATH_OVERFLOW` from `scaled_to_original`, with `borrow_index < MAX_BORROW_INDEX_RAY`.
4. Subsequent `withdraw` and `repay` calls revert with the same error — the market is permanently frozen.