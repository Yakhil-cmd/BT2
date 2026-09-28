### Title
Whale-scale markets freeze permanently when `borrowed * borrow_index` overflows `i128` before the index cap engages - (File: common/src/rates/index.rs)

### Summary
The bug class hinted by CVE-2016-9893 (memory corruption causing uncontrolled behavior) maps onto this codebase as uncontrolled `i128` arithmetic overflow. Every mutating controller/pool entrypoint accrues interest first via `global_sync` → `accrue_step`, which computes `borrowed.mul(borrow_index)` inside `calculate_supplier_rewards` and `scaled_to_original`. At whale scale (large `supplied`/`borrowed` RAY values) this product overflows `i128` and panics with `MathOverflow` **before** `update_borrow_index` reaches its `MAX_BORROW_INDEX_RAY` clamp. Since accrual runs at the head of every verb, the market becomes permanently frozen: no repay, withdraw, liquidate, or `update_indexes` ever succeeds again.

### Finding Description
`accrue_step` in `common/src/rates/simulate.rs:51-94` performs, in order:

1. `scaled_to_original(env, borrowed, borrow_index)` → `borrowed.mul(borrow_index)` (`scaled_to_original` at `common/src/rates/scaling.rs:14-16`, `Ray::mul` at `common/src/math/fp.rs:50-52` → `fp_core::mul_div_half_up` panics `MathOverflow` when even the `I256` quotient cannot fit `i128`).
2. `update_borrow_index` (`common/src/rates/index.rs:13-19`) — the `MAX_BORROW_INDEX_RAY` cap is applied only **after** the multiplication of the old index by the factor.
3. `calculate_supplier_rewards` (`index.rs:80-83`) computes `borrowed.mul(new_borrow_index)` and `borrowed.mul(old_borrow_index)` — another overflow site on the raw share count times a large index.

The pool's `global_sync` (`contracts/pool/src/interest.rs:20-33`) calls `accrue_step` before any user action, and every controller verb (`supply`, `withdraw`, `repay`, `liquidate`, `clean_bad_debt`, `update_indexes`, `recapitalize`, etc.) triggers accrual on the touched market. Once `borrowed * borrow_index / RAY` exceeds `i128::MAX`, all of these revert unconditionally.

The codebase's own harness proves reachability: `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:320-361`) supplies 10^9 whole 18-decimal tokens, borrows 98%, advances time, and observes `MATH_OVERFLOW` on `update_indexes` — after which `try_withdraw_raw` and `try_repay` both fail with `MATH_OVERFLOW`. The borrow index at the failure point is still below `MAX_BORROW_INDEX_RAY`, i.e., the value ceiling is hit before the designed index cap. The test even asserts the documented bound in `docs/reference/formulas.md` is wrong, meaning the freeze arrives earlier than documented.

### Impact Explanation
Permanent freezing of funds and protocol insolvency-adjacent lockup: all supplied liquidity in the affected market is unwithdrawable, all debt is unrepayable, liquidations and `clean_bad_debt` cannot execute, and `recapitalize` fails since it also accrues. Neither the owner nor governance has an unpause path that skips accrual — `global_sync` is unconditional. Every token in the market is permanently locked.

### Likelihood Explanation
Requires a very large market (RAY-scaled `borrowed` large enough that `borrowed * index / RAY` leaves `i128`, roughly total value ≳ 10^11 at index ~1, decreasing linearly as the index grows) plus sustained high utilization on a steep rate curve over many years of accrual without the index cap being reached. Any unprivileged whale can set this up via ordinary `supply`/`borrow` calls (caps permitting — `calculate_scaled_cap` even saturates rather than blocking oversized caps). No privileged action is needed to trigger it once the state exists; time alone does it. Capital requirements make it Medium rather than High likelihood.

### Recommendation
Make accrual overflow-safe rather than trapping:
- In `calculate_supplier_rewards` and `scaled_to_original`, detect when `borrowed * index` would overflow and clamp `borrow_index` to `MAX_BORROW_INDEX_RAY` first (the cap exists precisely to bound this), or compute interest via a saturating/I256 path that cannot trap.
- Ensure `update_borrow_index` is reached (and its cap applied) before any `borrowed * new_index` product is computed, so the index cap actually engages before the value ceiling.
- Alternatively, bound `supplied`/`borrowed` share totals at mint time (`calculate_scaled_supply`/`calculate_scaled_borrow`) so that `shares * MAX_BORROW_INDEX_RAY / RAY` is guaranteed to fit `i128`.

### Proof of Concept
Existing harness test demonstrates the full reachable path:

```rust
// tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:320
let principal = BILLION * 10i128.pow(18);
t.supply_raw(BOB, "BIG18", principal);
t.supply_raw(ALICE, "COL", BILLION * 10_000_000 * 3);
t.borrow_raw(ALICE, "BIG18", principal / 100 * 98);
// advance time yearly until:
assert_contract_error(t.try_update_indexes_for(&["BIG18"]), errors::MATH_OVERFLOW);
// market permanently frozen:
assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);
```

The panic originates in `Ray::mul` → `fp_core::mul_div_half_up` called from `scaled_to_original`/`calculate_supplier_rewards` inside `accrue_step`, which `interest::global_sync` runs before every market mutation.