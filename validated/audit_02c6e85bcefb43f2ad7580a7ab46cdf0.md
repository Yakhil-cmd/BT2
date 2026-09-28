### Title
Borrow-index accrual overflows i128 before the index cap engages, permanently freezing every market verb - (File: common/src/rates/index.rs)

### Summary
The CVE class is an out-of-bounds memory access that crashes the process (`PreserveRegisterIfOccupied` in wasm3). The analog on Soroban is not memory corruption but an arithmetic overflow that traps the contract: the RAY-denominated debt value `borrowed * borrow_index` overflows `i128` inside accrual math *before* `update_borrow_index` can clamp the index to `MAX_BORROW_INDEX_RAY`. Every user-facing verb accrues interest first, so once the cliff is crossed the market traps on `GenericError::MathOverflow` for every subsequent call — withdraw, repay, borrow, liquidate — permanently.

### Finding Description
`update_borrow_index` multiplies the old index by the chunk growth factor and only clamps *after* the multiply (`common/src/rates/index.rs:13-19`). Separately, `calculate_supplier_rewards` computes `borrowed.mul(env, old_borrow_index)` and `borrowed.mul(env, new_borrow_index)` as RAY-scaled totals (`common/src/rates/index.rs:80-83`). `Ray::mul` widens to `I256` but converts back to `i128`, panicking with `MathOverflow` when the product does not fit (`common/src/math/fp_core.rs:300-303`). For a large market (whale-scale `borrowed` raw value), the product `borrowed * index` reaches `i128::MAX` while `index` is still well below `MAX_BORROW_INDEX_RAY`, so the documented cap never bounds the value computation.

The repository's own harness test proves the end-to-end freeze: `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` in `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321-360` supplies ~1e27 units of an 18-decimal asset, borrows at 98% utilization, advances time, and observes `update_indexes` fail with `MATH_OVERFLOW` while `borrow_index < MAX_BORROW_INDEX_RAY`. It then confirms `try_withdraw_raw` and `try_repay` both fail with the same error — "the market is frozen: exits and repayments accrue first and hit the same panic" and "the index cap never engages."

An unprivileged attacker can set this up alone: `controller::supply` a whale-sized amount, `controller::borrow` to ~98% utilization against self-supplied collateral in a second market, then let time (or repeated `update_indexes` calls, which are permissionless) carry the index toward the cliff. Once the product overflows, `clean_bad_debt`, `liquidate`, `repay`, `withdraw`, and even `recapitalize` cannot recover the market because accrual runs first and traps.

### Impact Explanation
Permanent freezing of funds for all suppliers and the impossibility of liquidation or repayment in the affected market — protocol insolvency in the practical sense, since bad debt can no longer be processed either. This matches the CVE's crash-only availability impact mapped onto contract state: a single overflow panic bricks the market's entry points.

### Likelihood Explanation
Requires a whale-scale deposit (the test uses 1e9 × 10^18 base units) plus sustained ~98% utilization for many years of accrual before the RAY value ceiling is hit — the test bounds the cliff within 40 years. Capital requirement is high but the path uses only unprivileged entrypoints (`supply`, `borrow`, `update_indexes`), and no governance action can rescue the market once the panic state is reached. Medium severity: high impact, demanding but unprivileged precondition, and the test notes the documented bound in `docs/reference/formulas.md` understates the risk.

### Recommendation
Bound the *value* product, not just the index: clamp `borrowed` or saturate `scaled_to_original`/`calculate_supplier_rewards` so accrual degrades gracefully (e.g., cap the effective index at the largest value where `borrowed * index` fits in `i128`, or compute accrual in `I256` and only clamp on write-back). Alternatively, enforce a per-market supply/borrow cap that keeps `borrowed * MAX_BORROW_INDEX_RAY` inside `i128` given `asset_decimals`, since the cap-validation domain (`require_cap_within_asset_domain`) currently does not account for index growth.

### Proof of Concept
`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321-360` — the existing test is the PoC: whale supply + 98% borrow + `advance_time` until `try_update_indexes_for` returns `MATH_OVERFLOW` with `borrow_index` still below `MAX_BORROW_INDEX_RAY`, after which `try_withdraw_raw` and `try_repay` both trap, demonstrating the permanent freeze.