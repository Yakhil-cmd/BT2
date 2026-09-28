### Title
Accrual panics on the RAY value ceiling before the borrow-index cap, permanently freezing a whale market — all pool verbs revert with `MathOverflow` (File: common/src/rates/simulate.rs)

### Summary
Interest accrual computes total debt as `borrowed_scaled * borrow_index` with the panicking `Ray::mul` inside `scaled_to_original` / `calculate_supplier_rewards`. For a market whose scaled debt is near the representable ceiling (~`i128::MAX / RAY` ≈ 170 billion whole tokens), sustained borrowing grows the product past `i128::MAX` before `update_borrow_index`'s `MAX_BORROW_INDEX_RAY` clamp can engage. Because `global_sync` runs at the head of every pool operation, the market then reverts on every entrypoint forever — withdrawals, repayments, liquidations, `clean_bad_debt`, `recapitalize`, and `update_indexes` all panic with `GenericError::MathOverflow`. This is the on-chain analog of CVE-2019-2805: a low-privileged network attacker steers shared state into a condition where routine processing crashes, causing a complete denial of service for all users of that market.

### Finding Description
`accrue_step` (common/src/rates/simulate.rs:51-94) performs, in order:

1. `borrowed_original = scaled_to_original(env, borrowed, borrow_index)` — `scaled.mul(env, index)` (common/src/rates/scaling.rs:14-16), a panicking `mul_div_half_up`.
2. `new_borrow_index = update_borrow_index(...)` which multiplies `old_index * interest_factor` and only then clamps to `MAX_BORROW_INDEX_RAY` (common/src/rates/index.rs:13-19).
3. `calculate_supplier_rewards` computes `borrowed.mul(env, new_borrow_index)` again (common/src/rates/index.rs:80-81).

The overflow site is the *value* product `borrowed_scaled * index`, not the index itself. `Ray::from_asset` caps scaled supply/debt near `i128::MAX / RAY` ≈ `170_141_183_460` whole tokens (common/tests/math/fp.rs:792-801). When a market holds scaled debt near that ceiling, the product `borrowed * new_borrow_index` exceeds `i128::MAX` at an index far below `MAX_BORROW_INDEX_RAY`, so `mul_div_half_up` widens to `I256`, fails `to_i128`, and panics with `GenericError::MathOverflow` (common/src/math/fp_core.rs:108-118, 300-303). The index cap never engages — the panic happens on the multiplication, before the clamped value could be stored. The same exposure exists in `update_supply_index`'s `supplied.mul(env, old_index)` for whale supply books (common/src/rates/index.rs:34).

`global_sync` (contracts/pool/src/interest.rs:20-33) is invoked before every pool operation (contracts/pool/src/ops/mod.rs, ops/market.rs), so once the stored `borrowed`/`borrow_index` pair crosses the cliff, every subsequent call re-enters `accrue_step`, recomputes the same overflowing product, and reverts. There is no path that skips accrual, and there is no mechanism to shrink `borrowed` without an accrual-completing operation — repaying requires accrual to succeed first. The repository's own test demonstrates the end state: `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` (tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:316-361) asserts `update_indexes`, `withdraw`, and `repay` all fail with `MATH_OVERFLOW`, and that `borrow_index < MAX_BORROW_INDEX_RAY` at the failure, confirming the cap cannot rescue the market.

Reachability for an unprivileged address: `supply` and `borrow` are permissionless controller verbs. Supply-cap validation only bounds caps to the asset domain (`require_cap_within_asset_domain`, referenced in common/src/rates/scaling.rs:20-25), so an admin-configured cap near the ~170B-whole-token representable ceiling is a legitimate configuration for high-decimal (e.g., 18-decimal) tokens. An attacker with sufficient capital supplies the market to near the cap and drives utilization high through ordinary borrows; time accrual then carries the market across the cliff without further attacker action.

### Impact Explanation
Permanent freezing of user funds for the affected market — the strongest impact class. Once the cliff is crossed, every supplier's deposit in that market is unrecoverable (`withdraw` reverts), every debt is unrepayable, liquidations and `clean_bad_debt` cannot run, and `recapitalize`/`update_indexes` cannot rescue it, because all of them accrue first. The loss falls on *other* suppliers and on the protocol's solvency accounting, not just the attacker: the attacker's own borrow becomes bad debt that can never be cleared, and honest suppliers' balances are bricked inside an unrecoverable market book. Soroban panics are typed contract errors, so there is no catch-and-skip; the state is unrecoverable absent a contract upgrade.

### Likelihood Explanation
Medium. The trigger requires (a) a listed market whose supply/borrow caps approach the ~170B-whole-token representable ceiling (plausible for 18-decimal assets, which `MIN_BORROWABLE_ASSET_DECIMALS`..18 are supported for), (b) whale-scale capital to fill the book — up to ~170 billion tokens, though a borrower only needs to hold the debt leg near the ceiling while supply can be marginally above it, and (c) sustained high utilization over a long accrual horizon (the harness reached the cliff after ~a decade at 98% utilization on a steep curve). The attacker cannot accelerate ledger time, and honest liquidations only postpone the state. However, no privileged action is needed at any point, the condition is self-sustaining once created (borrow interest alone pushes the product over the cliff), and partial freezes also hit supply-only whale books via `update_supply_index`. Capital cost is the main mitigant; protocol-level severity of a permanent freeze justifies Medium-to-High.

### Recommendation
Make the value products in the accrual step saturating rather than panicking, so accrual can always complete and the index caps remain the binding constraint:

- In `calculate_supplier_rewards` and `scaled_to_original` callers inside `accrue_step` (common/src/rates/simulate.rs:60-69, common/src/rates/index.rs:80-81), compute `borrowed * index` with `mul_div_floor_saturating` / a saturating `Ray::mul` variant instead of the panicking `mul`.
- Apply the same treatment to `supplied.mul(env, old_index)` in `update_supply_index` (common/src/rates/index.rs:34) and to `apply_bad_debt_to_supply_index`'s `supplied * supply_index` product (contracts/pool/src/interest.rs:74).
- Alternatively, cap `borrowed` (scaled debt shares) at `i128::MAX / MAX_BORROW_INDEX_RAY` at borrow time, guaranteeing `borrowed * index` can never overflow for any index below the cap — this converts the value ceiling from an emergent freeze into an explicit, fail-closed borrow limit.
- Add a regression test asserting that once `borrow_index` saturates at `MAX_BORROW_INDEX_RAY`, `update_indexes`, `withdraw`, `repay`, and `liquidate` still succeed on a near-ceiling market (the existing test at large_positions_and_long_horizons.rs:316 already encodes the current broken behavior).

### Proof of Concept
The repository's own harness test reproduces the freeze end-to-end (tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:316-361). Conceptual reproduction against production entrypoints:

```rust
// Requires a listed market for an 18-decimal token whose supply/borrow caps
// are set near the representable ceiling (an admin-legitimate configuration).
// Attacker (unprivileged):
// 1. controller.supply(attacker, hub, spoke, [(BIG18, ~1e18 * 10^18 units)])
//    -> scaled supply near i128::MAX / RAY (~170B whole tokens).
// 2. controller.borrow(attacker, acct, [(BIG18, ~98% of supplied)], None)
//    -> scaled debt near the same ceiling; utilization ~98%.

// After sustained high-utilization accrual (steep-segment rate), the next
// accrual step computes borrowed_scaled * new_borrow_index > i128::MAX
// while borrow_index is still below MAX_BORROW_INDEX_RAY:

controller.update_indexes(...) // -> Error(Contract, MathOverflow)

// The market is now permanently frozen; every verb accrues first:
controller.withdraw(supplier, acct, [(BIG18, 1)])   // MathOverflow
controller.repay(attacker, acct, [(BIG18, 1)], ..)  // MathOverflow
controller.liquidate(liq, victim, payments, SeizeMode::Transfer) // MathOverflow
controller.clean_bad_debt(...)                      // MathOverflow
controller.recapitalize(...)                        // MathOverflow
```

Root cause: `borrowed.mul(env, new_borrow_index)` in `calculate_supplier_rewards` (common/src/rates/index.rs:80-81) and `scaled_to_original` (common/src/rates/scaling.rs:14-16) use the panicking `mul_div_half_up` (common/src/math/fp_core.rs:108-118), so the debt-value product overflows before `update_borrow_index`'s `MAX_BORROW_INDEX_RAY` clamp (common/src/rates/index.rs:13-19) can take effect; since `global_sync` precedes every pool op (contracts/pool/src/interest.rs:20-33), the panic bricks the market for all users.