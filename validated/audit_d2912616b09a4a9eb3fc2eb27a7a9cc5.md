### Title
Permanent market freeze via i128 overflow in interest accrual (`borrowed * borrow_index` exceeds `i128::MAX`) - (File: contracts/pool/src/interest.rs)

### Summary
The CVE-2021-4129 bug class is memory corruption leading to arbitrary code execution. In this Soroban/Rust codebase, memory corruption is not reachable; the direct analog is **arithmetic overflow that permanently halts contract execution**. `global_sync` runs at the top of every pool mutator (`contracts/pool/src/interest.rs:20`) and calls `accrue_step`, which computes the total debt value as `borrowed_shares * borrow_index` via `Ray::mul` → `mul_div_half_up` (`common/src/math/fp_core.rs:108`), which panics with `MathOverflow` when the product does not fit in `i128`. Because every verb accrues first, once the RAY-denominated debt value crosses `i128::MAX`, every subsequent call to the market — `withdraw`, `repay`, `liquidate`, `borrow`, `supply` — reverts. The borrow-index cap `MAX_BORROW_INDEX_RAY` in `update_borrow_index` (`common/src/rates/index.rs:13-19`) bounds the *index*, not the *share × index product*, so it cannot prevent the freeze. The test suite itself demonstrates this: `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321-361` drives an 18-decimal market to `MathOverflow` in `try_update_indexes_for`, then asserts `try_withdraw_raw` and `try_repay` both revert with `MATH_OVERFLOW`.

### Finding Description
- `Cache::global_sync` → `accrue_chunk` → `accrue_step` (`contracts/pool/src/interest.rs:39-53`) recomputes total debt/supply value each accrual. The same product appears in `calculate_utilization` via `scaled_to_original` (`contracts/pool/src/cache/scale.rs:19-27`).
- `Ray::mul` uses `mul_div_half_up`, which panics `MathOverflow` when `x * y / RAY` exceeds `i128` (`common/src/math/fp_core.rs:104-118`); only `mul_div_floor_saturating` (used in `update_supply_index` and `protocol_fee_shares`) saturates.
- Total borrowed is measured in **shares × index**, i.e. RAY² — an 18-decimal token market with ~10^27 base units borrowed at a steep curve segment reaches ~170× index before `MAX_BORROW_INDEX_RAY` engages, per the documented test.
- An unprivileged user reaches this purely via `supply` (huge deposit of a high-decimal asset, enabled if caps are lifted by parameter changes or absent) plus ordinary `borrow`; the freeze then requires only time — no further attacker action. `update_indexes` alone triggers it.

### Impact Explanation
Permanent freezing of funds and protocol insolvency for that market: suppliers can never withdraw, borrowers cannot repay, liquidators cannot liquidate (all paths accrue first). Accrued-but-unclaimed supplier yield and protocol revenue in that market are permanently unrecoverable.

### Likelihood Explanation
Requires a whale-scale position in a high-decimal asset and sustained high utilization over many years (the test needed ~40 years of advancing time), so likelihood is low in practice — but it is reachable without privileged roles, key compromise, or oracle manipulation, and once triggered it is irreversible. Severity: Medium (high impact, difficult preconditions).

### Recommendation
In `accrue_step` / `calculate_utilization` paths, evaluate `borrowed * index` and `supplied * index` through the saturating or `I256` path and, on exceeding `i128`, clamp total debt value instead of panicking — or enforce a conservative `total_borrowed` cap at borrow time that keeps `shares × MAX_BORROW_INDEX_RAY` below `i128::MAX`. Capping `borrowed` shares at `i128::MAX / MAX_BORROW_INDEX_RAY` at `borrow`/`supply` mint time makes the panic unreachable.

### Proof of Concept
See `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321-361` (`a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap`): supply `BILLION * 10^18` BIG18, borrow 98%, advance time in 1-year steps until `try_update_indexes_for` returns `MATH_OVERFLOW`; then `try_withdraw_raw(BOB, "BIG18", 1)` and `try_repay(ALICE, "BIG18", 1)` revert identically, confirming the market is frozen.