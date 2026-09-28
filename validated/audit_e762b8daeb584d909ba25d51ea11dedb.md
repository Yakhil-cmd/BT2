### Title
Permanent market freeze: borrow-index accrual overflows `i128` in `scaled_to_original` before the index cap can engage - (File: contracts/pool/src/interest.rs)

### Summary
The reported bug class is a system-level panic escaping from a library call into a shared service, permanently (or crash-level) denying service. The analog in XOXNO Lending is a persistent, attacker-seeded `GenericError::MathOverflow` panic inside pool accrual: once the ray-scaled borrowed value `borrowed * borrow_index` exceeds `i128::MAX`, every subsequent accrual reverts inside `scaled_to_original`, and because all mutators accrue first (`global_sync`), the market is permanently frozen — no `withdraw`, `repay`, `liquidate`, `clean_bad_debt`, or `recapitalize` can execute for that `(hub, asset)` book.

### Finding Description
`global_sync` in `contracts/pool/src/interest.rs:20-33` chunks elapsed milliseconds through `accrue_chunk` → `accrue_step` (`common::rates`), which computes utilization by unscaling shares back to asset value. `Cache::calculate_utilization` calls `scaled_to_original(borrowed, borrow_index)` and `scaled_to_original(supplied, supply_index)` (`contracts/pool/src/cache/scale.rs:23-24`), i.e., `mul_div_floor(scaled_shares, index, RAY)`. The protocol intends `MAX_BORROW_INDEX_RAY` to cap index growth, but the cap is applied to the *index*, while the overflow happens in the *product* `shares * index`. For a high-decimals, whale-scale market the ray share count is large enough that the product overflows `i128` at an index well below the cap.

The codebase itself documents this. `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:316-360` creates an 18-decimal market, supplies `principal = 10^9 * 10^18`, borrows at 98% utilization, and advances time: `try_update_indexes` fails with `MATH_OVERFLOW` while `borrow_index < MAX_BORROW_INDEX_RAY` ("the index cap did not engage before the value overflow"), and the test then asserts `try_withdraw_raw` and `try_repay` both revert with `MATH_OVERFLOW` — "The market is frozen: exits and repayments accrue first and hit the same panic." The panic is a typed contract error raised via `panic_with_error!` in `common::math::fp_core::mul_div_floor` → `to_i128` (`common/src/math/fp_core.rs:148-159, 300-303`), and it is state-dependent, not input-dependent: once the index/share product crosses the ceiling there is no input any caller can submit that avoids it.

Root cause, concretely:
- `accrue_step` computes the next chunk's indexes from utilization, which requires unscaling `borrowed` at the *new* borrow index — the product overflows first (`contracts/pool/src/interest.rs:39-53`, `common/src/rates.rs` `accrue_step`/`scaled_to_original`).
- The index cap `MAX_BORROW_INDEX_RAY` is enforced on the index value, giving a false bound: `i128::MAX / shares < MAX_BORROW_INDEX_RAY` for whale-scale share counts, so the cliff arrives first (test comment at `large_positions_and_long_horizons.rs:316-319`, assertion at `:351-353`).
- Every controller verb (`supply`/`borrow`/`withdraw`/`repay`/`liquidate`/`clean_bad_debt`) and the permissionless keeper call `update_indexes` (`contracts/controller/src/markets.rs:119-125`, `contracts/controller/src/lib.rs:370-372`) routes through pool accrual before touching balances, so one poisoned market bricks the entire `(hub, asset)` book.

An unprivileged attacker can reach it purely through `controller::supply` (permissionless, `scripts/permissionless_entrypoints.txt:69`) and `controller::borrow`: list or choose a supported high-decimals asset, supply and borrow to push `borrowed` (in ray-scaled shares) above `i128::MAX / (index trajectory)`, then wait. The `update_indexes` keeper call — which *any* signer may invoke — is itself the trigger, exactly the report's "one unprivileged call throws a system error that takes the whole path down" shape. Time-to-trigger depends on utilization and curve, but the trigger transaction is a normal permissionless call with ordinary arguments.

### Impact Explanation
Permanent freezing of funds for every supplier and borrower in the affected `(hub, asset)` book: withdrawals, repayments, liquidations, bad-debt cleanup, and recapitalization all revert at the accrual prelude, forever. In-repo test confirms both withdraw and repay revert with `MATH_OVERFLOW` after the cliff (`large_positions_and_long_horizons.rs:355-356`). This maps to the accepted impact classes "permanent freezing of funds" and "contract unable to operate" for that market; it is not a fail-closed DoS — the revert is unconditional and unrecoverable, not input-rejectable.

### Likelihood Explanation
Medium. Triggering requires a high-supply, high-utilization market with large decimals sustained over a long horizon (the reproducer reaches the cliff within ~40 simulated years at 98% utilization on the steep XLM curve segment; steeper rates or larger whale supply shorten it). No privileged role, no oracle manipulation, and no privileged parameter is needed: an attacker supplies their own tokens and borrows at high utilization, or the state can arise organically in a whale-dominated market. Once `borrowed * borrow_index` approaches `i128::MAX`, any third party's routine `update_indexes` call permanently cements the freeze. The test explicitly flags the documented bound as wrong (`:338-341`), meaning the assumed safety margin does not exist.

### Recommendation
Two complementary fixes:

1. **Enforce the cap on the value domain, not only the index.** Before applying a new index in `accrue_step`/`accrue_chunk`, compute whether `borrowed * candidate_index` (and `supplied * candidate_supply_index`) fits `i128`; if not, clamp the index to `min(MAX_BORROW_INDEX_RAY, i128::MAX / borrowed)` rounded down to `RAY` multiples, rather than letting `scaled_to_original` panic. Alternatively check cap *before* each chunk inside `global_sync` so accrual stops at the last representable index instead of overflowing mid-chunk.
2. **Make unscale paths saturating for reads.** `scaled_to_original` inside `calculate_utilization` and fee/accrue flows should use a saturating variant (analogous to `mul_div_floor_saturating`, `common/src/math/fp_core.rs:180-201`) for utilization display, while hard value-mutation paths keep checked math — this prevents a near-ceiling market from failing closed on every call before the index cap logic ever runs.

### Proof of Concept
Already reproduced by the in-repo test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` in `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321-360`:

1. Create an 18-decimal market (`BIG18`) on the XLM rate curve with caps lifted.
2. `controller::supply` `principal = 10^9 * 10^18` base units (unprivileged).
3. `controller::borrow` `principal * 98 / 100` (unprivileged; requires collateral on a second market).
4. Advance ledger time in yearly steps calling permissionless `update_indexes`.
5. Observe `update_indexes` revert with `GenericError::MathOverflow` while `borrow_index < MAX_BORROW_INDEX_RAY`.
6. `controller::withdraw` and `controller::repay` now revert with the same error for any inputs — all supplier and borrower funds in that market are permanently locked.