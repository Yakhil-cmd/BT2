The memory-corruption bug class maps to arithmetic overflow in this Rust/Soroban codebase. I found a test asserting a permanent market freeze via overflow in accrual. Let me confirm the code path.### Title
Accrual `i128` overflow permanently freezes a whale-scale market before the borrow-index cap engages - (File: common/src/rates/index.rs)

### Summary
The memory-corruption bug class maps here to arithmetic overflow in `i128` fixed-point math. The RAY-denominated total debt value (`borrowed_shares * borrow_index`) is computed with exact `I256` intermediates but must fit `i128` in the quotient. When it does not, `Ray::mul` → `mul_div_half_up` panics with `MathOverflow` inside `calculate_supplier_rewards` (`common/src/rates/index.rs:80-83`). Because `MAX_BORROW_INDEX_RAY` is far above the value ceiling, the cap never engages first — the market dies from value overflow while the index is still ~170x.

### Finding Description
`global_sync` in `contracts/pool/src/interest.rs:20-33` runs unconditionally at the top of every state-changing pool op and calls `accrue_step`, which invokes `calculate_supplier_rewards`. That function computes `borrowed.mul(env, new_borrow_index)` (`index.rs:81`). For a high-decimals asset, a whale-scale book makes `borrowed` (RAY-scaled shares) ~10^36; once the borrow index exceeds ~`170 * RAY`, the quotient exceeds `i128::MAX` and `to_i128` panics. The repo's own test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:316-361`) demonstrates the panic and explicitly notes the index cap never engages and the documented bound in `docs/reference/formulas.md` is wrong.

An unprivileged attacker reaches this with only `supply` and `borrow`: supply a very large amount of a high-decimals asset, borrow ~98% of it (holding utilization on the steep part of the rate curve), and let time pass. Thereafter every entrypoint on that market — `withdraw`, `repay`, `liquidate`, `clean_bad_debt`, `update_indexes` — reverts in `global_sync` before doing any work.

### Impact Explanation
Permanent freezing of funds: all supplier principal and interest in the affected (hub, token) book become unrecoverable, borrowers cannot repay, and liquidations cannot execute, so underwater positions can never be resolved — an insolvency/freeze combination. The panic is in shared accrual state; there is no user-level escape since even `update_indexes` itself accrues first.

### Likelihood Explanation
Low-to-moderate. It requires whale-scale capital (≈10^9 whole units of an 18-decimal asset at ~10^27 base units), sustained ~98% utilization for multiple years against compounding interest, and a curve steep enough to push the index past ~170x. The attacker also pays real interest to keep utilization pinned, and caps/listing validation may bound the initial supply. The path needs no privilege, no oracle manipulation, and no third-party cooperation beyond the attacker's own positions.

### Recommendation
Order of operations in `accrue_step`: clamp the borrow index to `MAX_BORROW_INDEX_RAY` *before* computing `borrowed * new_borrow_index`, and/or compute the accrued interest on a saturating/`I256`-aware path (e.g., `mul_div_floor_saturating` or clamping `new_total_debt` to `i128::MAX` and deriving the delta from the capped index). Alternatively, set `MAX_BORROW_INDEX_RAY` low enough that `max_scaled * cap` provably fits `i128` for the maximum admissible book size, and enforce that bound via listing cap validation (`require_cap_within_asset_domain`). The same exposure exists in `update_supply_index` (`index.rs:34`) and `supply_index_reward_shortfall` (`index.rs:60-62`).

### Proof of Concept
```rust
// tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321-356
let principal = BILLION * 10i128.pow(18);          // whale supply, 18-dec asset
t.supply_raw(BOB, "BIG18", principal);
let debt = principal / 100 * 98;                   // ~98% utilization
t.supply_raw(ALICE, "COL", BILLION * 10_000_000 * 3);
t.borrow_raw(ALICE, "BIG18", debt);

// advance years; eventually update_indexes panics with MATH_OVERFLOW
// inside scaled_to_original while borrow_index < MAX_BORROW_INDEX_RAY.
// Afterwards every verb accrues first and panics:
assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);
```
Root cause: `calculate_supplier_rewards` multiplies scaled debt by the new index before any cap/bounds check on the resulting RAY value (`common/src/rates/index.rs:80-83`), and `global_sync` runs on every op (`contracts/pool/src/interest.rs:20-33`), so the single overflow permanently bricks the market.