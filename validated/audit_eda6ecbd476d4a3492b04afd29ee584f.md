### Title
Uncapped RAY value overflow in interest accrual permanently freezes a market and all user funds — (`contracts/pool/src/cache/scale.rs`)

### Summary
The external report concerns a memory-corruption primitive (declared chunk size exceeding the real buffer) reachable by an unprivileged caller. On Soroban there is no raw heap to overflow, so the analogous class is an attacker-reachable numeric bound overflow that corrupts/halts protocol state. XOXNO Lending has exactly that shape in the pool's fixed-point accrual path: `scaled_to_original` multiplies RAY-scaled share amounts by a growing borrow/supply index inside `i128`, and the configured `MAX_BORROW_INDEX_RAY` cap engages too late to prevent the value ceiling from being hit. The repo's own harness test documents the resulting cliff: once a large market's index growth pushes `scaled_amount * index` past `i128::MAX`, accrual panics with `MathOverflow`, and because every verb accrues first, `supply`, `borrow`, `repay`, `withdraw`, `liquidate`, `clean_bad_debt`, and `recapitalize` on that market all revert permanently. The unprivileged entrypoints `update_indexes` (permissionless accrual trigger) and every user verb reach the panicking code; nothing in `apply_bad_debt_to_supply_index` or the index-cap logic rescues the market, since the panic occurs inside the shared unscale helper before any cap or write-down is applied. `contracts/pool/tests/flows.rs` and `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs` confirm the freeze extends to withdraw and repay, not just borrow.

### Finding Description
`pool/cache/scale.rs` unscales RAY shares via `scaled_amount.mul(env, index)` using the checked fixed-point helpers in `common/src/math/fp.rs` (`checked_add_raw`, `checked_sub_nonneg`, and `Wad/Ray::mul`), which panic with `GenericError::MathOverflow` on overflow. `scaled_amount` is a RAY-scaled value, so `scaled_amount * index` has `i128` headroom of roughly 170× the raw deposit: a market holding ~1 billion whole tokens at 18 decimals (`1e36` raw, `1e63` RAY-scaled) exhausts the ceiling once the borrow index exceeds ~170×. The interest path in `contracts/pool/src/interest.rs` is invoked at the top of every state-changing op, so the panic is not confined to one endpoint — the controller's `supply`/`borrow`/`withdraw`/`repay`/`liquidate`/`clean_bad_debt`/`flash_*` verbs and the keeper entrypoint `update_indexes` all accrue before doing their work, and each therefore reverts forever once the market's index growth crosses the value ceiling. The documented `MAX_BORROW_INDEX_RAY` bound does not protect this: the harness test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` asserts the panic fires *before* the cap engages ("the index cap never engages"; `last.borrow_index < MAX_BORROW_INDEX_RAY`), and shows `try_withdraw_raw` and `try_repay` both revert with `MATH_OVERFLOW` afterwards, leaving supplier principal and borrower collateral permanently locked in the pool.

### Impact Explanation
Permanent freezing of user funds. Once a market reaches the RAY-value ceiling, no supplier can withdraw, no borrower can repay, no liquidator can liquidate, and bad-debt cleanup/recapitalization cannot run, because accrual panics before any of those bodies execute. All cash held by the pool for that hub market is unreachable indefinitely — there is no admin escape hatch in-scope (upgrade paths are out of scope and cannot be assumed). Unlike a transient revert, this is a monotonic state: indexes only grow, so the overflow condition never self-heals.

### Likelihood Explanation
The trigger requires a genuinely large market (on the order of `i128::MAX / RAY / 170` in scaled terms — roughly a billion whole units at 18 decimals) combined with sustained high utilization on a steep interest curve so the borrow index compounds past the ~170× ceiling faster than the index cap can engage. An unprivileged borrower can maintain near-max utilization on their own book, and accrual advances with wall-clock time, so no privileged action is needed — `update_indexes` is callable by anyone to push the market over the cliff. The capital requirement is large, which lowers likelihood, but this is a real capacity bound the protocol's own documentation bound (`docs/reference/formulas.md`) mis-states, per the harness test comment ("the bound in docs/reference/formulas.md is wrong"). Impact is maximal (total market freeze), so the finding sits in the Critical/High band despite the capital barrier.

### Recommendation
- Make the index cap engage before the value ceiling: clamp `borrow_index`/`supply_index` in `interest.rs` accrual to a bound derived from `i128::MAX / max_expected_scaled_amount` (or a fixed, conservative RAY cap), not just `MAX_BORROW_INDEX_RAY`, so the cliff cannot be reached.
- Alternatively, downscale before multiplying: compute unscales as `scaled_amount * index / RAY` using a wider intermediate (or split multiply via `mul_div` on checked 256-bit-style decomposition) so that large books do not overflow `i128` mid-computation.
- Add a per-market `total_supply` cap enforcement sized to keep `scaled_amount * MAX_BORROW_INDEX_RAY` within `i128`, so deposits that would make the overflow reachable are rejected up front.
- Correct the documented bound in `docs/reference/formulas.md` to reflect the real cliff observed by the harness test.

### Proof of Concept
Reachable entirely through unprivileged calls:

```text
// Market BIG18: 18 decimals, XLM interest curve, caps lifted.
1. supplier calls controller.supply(account_id, spoke_id,
     [(HubAssetKey{hub_id, BIG18}, 1_000_000_000 * 1e18)])
2. borrower calls controller.borrow(..., [(BIG18, ~0.98 * supply)])  // ~98% util
3. anyone (attacker) calls controller.update_indexes([BIG18]) periodically
   as time advances; each call compounds the borrow index at the steep
   segment of the XLM curve.
4. Once scaled_to_original(debt_shares, borrow_index) exceeds i128::MAX,
   update_indexes panics with MathOverflow.
5. Every subsequent verb on the market reverts:
     controller.withdraw(supplier, BIG18, 1)  -> MathOverflow
     controller.repay(borrower, [(BIG18, ...)]) -> MathOverflow
     controller.liquidate(...)                -> MathOverflow
   Supplier principal and borrower collateral are permanently locked.
```

This is exactly the scenario encoded and asserted in `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:320-360` (`a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap`), which demonstrates `errors::MATH_OVERFLOW` from `try_update_indexes_for`, `try_withdraw_raw`, and `try_repay`, with `last.borrow_index < MAX_BORROW_INDEX_RAY` proving the index cap cannot prevent the freeze.