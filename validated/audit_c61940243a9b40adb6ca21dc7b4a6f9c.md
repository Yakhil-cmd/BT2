### Title
Interest accrual overflows before the borrow-index cap engages, permanently freezing a market - (File: common/src/rates/index.rs)

### Summary
The raw-cpuid advisory is about exposing an operation whose safety precondition ("the CPU supports this instruction") is never checked, producing a deterministic crash. The lending analog is the RAY index accrual path: `update_supply_index`/debt accrual compute `scaled * index` products via `mul_div_floor`/scaled unscaling assuming the result always fits `i128`, but on a large market at high utilization the product overflows and panics *before* the intended `MAX_BORROW_INDEX_RAY` cap can clamp the index. Every controller verb accrues indexes first (`Context::load_markets` / `cached_pool_sync_data` → `update_indexes`), so once the product overflows, `withdraw`, `repay`, `borrow`, `liquidate`, and `update_indexes` itself all revert deterministically — the market is permanently frozen with user funds inside.

### Finding Description
`mul_div_floor`/`scaled_to_original` in `common/src/math/fp_core.rs` panic with `GenericError::MathOverflow` on `i128` overflow rather than saturating or checking whether the index cap has been reached first. The repository's own harness test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:316-360`) proves the chain:

- a whale supplies ~10^28 units of an 18-decimal asset and borrows ~98% of it;
- repeated `update_indexes` accrual eventually panics with `MATH_OVERFLOW` inside `scaled_to_original` while `borrow_index < MAX_BORROW_INDEX_RAY` — i.e., the documented index cap never engages because the *value* computation `scaled_amount * index` overflows first;
- afterwards `withdraw` and `repay` both revert with `MATH_OVERFLOW`, since every entrypoint accrues before acting.

The precondition being violated — "the scaled amount times the RAY index must fit in `i128`" — is nowhere enforced at market creation, supply, or borrow time; supply caps and utilization caps can be lifted or are denominated per-market, and the cap check happens on the index, not on the overflowing product. The unsafe operation (the multiplication) is invoked unconditionally in the accrual path, exactly mirroring raw-cpuid calling `__cpuid_count` unconditionally.

### Impact Explanation
Permanent freezing of user funds for the affected (hub, token) market. Once the overflow threshold is crossed, no one — including the protocol — can repay, withdraw, liquidate, or even call `update_indexes` on that market, because accrual runs first and panics. Supplied collateral backing the borrow, the borrower's collateral in other positions that touch the market, and all lender principal become unrecoverable. This satisfies the "permanent freezing of funds" and "contract unable to operate" acceptance criteria.

### Likelihood Explanation
The trigger is reachable entirely by unprivileged calls: `supply`, `borrow`, and repeated `update_indexes` (permissionless index refresh). The practical barrier is capital: the harness test needed ~10^28 units of a high-decimal token and ~40 years of accrual at the XLM rate curve's steep segment. For tokens with large supplies and 18 decimals (e.g., memecoins), such scaled amounts are feasible, and the required accrual horizon shrinks with utilization and rate. Because accrual is chunked per invocation and time can only move forward, the failure is deterministic once the product crosses `i128::MAX`, just as the raw-cpuid fault is deterministic on unsupported CPUs.

### Recommendation
Compute the cap on the *product*, not only the index: in the accrual/index-update path (`common/src/rates/index.rs`, `update_supply_index`/`update_borrow_index` and `scaled_to_original` callers), use `try_mul_div_*` and, on overflow, clamp the index to `MAX_BORROW_INDEX_RAY` (and the analogous supply bound) instead of panicking. Alternatively, enforce a market-level cap on total scaled supply/debt at supply/borrow time so `scaled_amount * MAX_BORROW_INDEX_RAY` provably fits `i128`, mirroring how raw-cpuid 9.0.0 fails at build time rather than at runtime.

### Proof of Concept
See `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321-356`: with an 18-decimal market on `xlm_curve()`, supply `BILLION * 10^18`, borrow 98%, disable `max_utilization`, then loop `advance_time(YEAR_SECS)` + `try_update_indexes`. After at most ~40 iterations `try_update_indexes` returns `MATH_OVERFLOW` while `borrow_index < MAX_BORROW_INDEX_RAY`, and subsequent `try_withdraw_raw(BOB, "BIG18", 1)` and `try_repay(ALICE, "BIG18", 1.0)` both fail with `MATH_OVERFLOW` — demonstrating permanent, unprivileged-triggered freezing of the market.