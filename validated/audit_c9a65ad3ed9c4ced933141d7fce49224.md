### Title
Unchecked RAY debt valuation can permanently freeze an entire market - (File: `common/src/rates/simulate.rs`)

### Summary
Accrual first converts stored scaled debt and supply shares into RAY-denominated balances with `scaled_to_original` before computing utilization or interest. If that value exceeds `i128::MAX`, `Ray::mul` returns no representable value and accrual panics with `MathOverflow`. Because every market mutation and `update_indexes` runs `interest::global_sync` before performing its operation, crossing this arithmetic boundary makes repayment, withdrawal, liquidation support, revenue claims, and index updates unavailable for the affected hub asset.

### Finding Description
`accrue_step` reads the persisted scaled balances and computes:

- `borrowed_original = borrowed * borrow_index`
- `supplied_original = supplied * supply_index`

through `scaled_to_original` at `common/src/rates/simulate.rs:60-62`. The underlying `scaled_to_original` implementation performs an exact multiply-divide and rejects results that do not fit `i128` (`common/src/rates/scaling.rs:12-16`, `common/src/math/fp_core.rs:104-143`).

The panic occurs before the later borrow-index cap can prevent the market value from becoming unrepresentable (`common/src/rates/index.rs:13-18`). Accrual is invoked unconditionally whenever `last_timestamp` is behind the current ledger timestamp (`contracts/pool/src/interest.rs:20-33`), including by `update_indexes` (`contracts/pool/src/ops/market.rs:65-72`) and the shared `synced_market` loader used by ordinary market legs (`contracts/pool/src/ops/mod.rs:29-34`).

The repository’s long-horizon test demonstrates the boundary: a large 18-decimal market with approximately 98% utilization eventually reaches `MathOverflow` before `MAX_BORROW_INDEX_RAY`, after which both withdrawal and repayment revert with the same error (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:316-357`).

### Impact Explanation
The result is a permanent or at least indefinitely persistent market-level freeze. `last_timestamp` is only advanced after all accrual chunks complete (`contracts/pool/src/interest.rs:25-32`), so once a chunk panics, later calls recompute the same overflowing step and cannot advance the market past it. The panic rolls back the attempted state transition, leaving the same arithmetic inputs.

All subsequent operations that load and sync that market revert before their own repayment or withdrawal logic runs. Suppliers cannot retrieve remaining backing, borrowers cannot reduce debt, liquidators cannot process distressed accounts through the normal market path, and the protocol cannot claim revenue or apply accrued interest. This matches the accepted impact of permanent freezing of funds and a market unable to operate.

### Likelihood Explanation
An unprivileged caller can create its own account, supply collateral, borrow a large balance, and later call `update_indexes`. No leaked key or privileged endpoint is required. The exploit does require an extremely large admitted market and sustained high utilization, so the practical likelihood depends on token supply, configured caps, available collateral, and sustained demand/rate conditions. It is not merely a bounded one-unit rounding loss: once reached, the market cannot recover through the listed unprivileged operations.

The affected path is reachable through:

- `controller::supply(caller, account_id, spoke_id, assets)`
- `controller::borrow(caller, account_id, borrows, to)`
- `controller::update_indexes(caller, assets)`
- `controller::repay(caller, account_id, payments)`
- `controller::withdraw(caller, account_id, withdrawals, to)`
- `controller::liquidate(liquidator, account_id, debt_payments, seize_mode)`

The pool-side versions of these flows synchronize the market before mutation.

### Recommendation
Prevent debt/share valuation overflow during accrual rather than allowing a panic to become a terminal market state. Suitable changes include:

- Detect unrepresentable `borrowed * borrow_index` or `supplied * supply_index` values before multiplication.
- Cap or safely clamp the stored scaled balance and derived index so debt remains representable.
- Add a bounded deleveraging/write-down recovery path that can operate without first evaluating the overflowing balance.
- Enforce market-creation and cap limits so `scaled_balance * maximum_index` stays below `i128::MAX`.
- Add an explicit emergency market-freeze/write-off path rather than relying on an untyped arithmetic panic.

Any fix must cover both debt valuation and supplier-reward calculations, since multiple products inside `accrue_step` can become unrepresentable.

### Proof of Concept
1. Create or use a listed 18-decimal debt market and a separate collateral market whose caps permit an approximately billion-whole-token debt position.
2. As a single attacker, call `supply` to create an account and deposit the debt-market liquidity, then supply sufficient collateral in the second market.
3. Call `borrow` with a debt-market amount near maximum utilization, for example `debt = supplied_principal * 98 / 100`.
4. Allow time to pass while the market remains at high utilization. The repository test shows the index can remain below `MAX_BORROW_INDEX_RAY` while `borrowed * borrow_index` becomes larger than `i128::MAX`.
5. Any caller invokes `update_indexes(caller, vec![debt_hub_asset])`. The pool loads the market and calls `global_sync`, which calls `accrue_step`; `scaled_to_original` overflows and panics with `MathOverflow`.
6. Subsequent `repay`, `withdraw`, `liquidate`, `claim_revenue`, or further `update_indexes` calls for the same market load and sync it first, repeat the same overflowing calculation, and revert. No successful call advances `last_timestamp`, so the overflow remains on every later attempt.