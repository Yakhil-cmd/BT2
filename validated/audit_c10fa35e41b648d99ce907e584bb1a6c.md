### Title
Index-scale value overflow in `scaled_to_original` permanently freezes a high-utilization market — (`common/src/rates/scaling.rs`)

### Summary
Like CVE-2017-7868 (index arithmetic walks past the buffer bound), the lending market's index arithmetic walks past the representable-value bound: `scaled_to_original` computes `borrowed * borrow_index / RAY` as a plain `Ray::mul` that panics with `MathOverflow` once the product leaves `i128`. The borrow-index cap `MAX_BORROW_INDEX_RAY` was meant to bound index growth, but the *value* ceiling (`borrowed_shares × index`) is hit first on whale-scale markets, so the cap never engages. Because `accrue_step` computes `scaled_to_original` on every compounding chunk and every pool verb accrues first, the panic permanently bricks the market — no supply, borrow, withdraw, repay, liquidate, or bad-debt cleanup ever succeeds again.

### Finding Description
`accrue_step` in `common/src/rates/simulate.rs` opens each step by unscaling the debt book:

```rust
let borrowed_original = scaled_to_original(env, borrowed, borrow_index);   // simulate.rs:60
let supplied_original = scaled_to_original(env, supplied, supply_index);   // simulate.rs:61
```

`scaled_to_original` is `scaled.mul(env, index)` — a half-up `mul_div` on `i128` that panics on overflow (`common/src/rates/scaling.rs:14-16`, `common/src/math/fp.rs`). The same product is computed again in `calculate_supplier_rewards` via `borrowed.mul(env, new_borrow_index)` (`common/src/rates/index.rs:80-81`). `update_borrow_index` multiplies *before* clamping to `MAX_BORROW_INDEX_RAY` (`index.rs:13-19`), so even the pre-clamp product can trap.

The reachable state: `borrowed` (RAY-scaled shares) times `borrow_index` exceeds `i128::MAX ≈ 1.7e38`. A billion-unit 18-decimal market is already `1e36` RAY of shares, so an index of ~170x — reachable in a few years on the steep segment of a jump-rate curve at sustained ~98% utilization — overflows. The pool's `global_sync` loop calls `accrue_chunk` → `accrue_step` before any mutation (`contracts/pool/src/interest.rs:20-53`), and `update_indexes` itself is permissionless (`contracts/pool/src/lib.rs:178`). Once the stored `borrowed`/`borrow_index` pair crosses the value ceiling, every subsequent accrual — and therefore every controller verb — reverts.

The repository's own harness test demonstrates exactly this: `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` asserts `MathOverflow` from `update_indexes`, then confirms `try_withdraw_raw` and `try_repay` both fail, and that `borrow_index < MAX_BORROW_INDEX_RAY` — the cap never engaged (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:315-356`).

### Impact Explanation
Permanent freezing of funds. Every asset held by the frozen market — all suppliers' deposits and all collateralized backing — becomes unreachable forever: `withdraw`, `repay`, `liquidate`, `clean_bad_debt`, and `flash_loan` all route through `global_sync`, which panics in the first `accrue_chunk`. There is no recovery path: the panic is deterministic on stored state, and `recapitalize`/`update_indexes` hit the same wall.

### Likelihood Explanation
Requires a large market (≈10³⁶ RAY scaled shares, e.g. ~1e9 whole tokens at 18 decimals) at sustained high utilization on a steep-rate curve for a few years. An unprivileged attacker can manufacture the precondition with their own capital: supply to a whitelisted high-decimals market, borrow to ~98% utilization, then simply let time pass — or grief an existing whale market by borrowing it into the steep segment. `update_indexes` is permissionless, so anyone can push the final accrual that trips the overflow. Notable that this is already encoded as an observed test, but it is a real defect, not an accepted bound — the docs claim the index cap bounds growth, and the test itself flags the documented bound as wrong.

### Recommendation
In `update_borrow_index`, clamp `old_index` (or early-return the cap) *before* multiplying so the pre-clamp product cannot trap; more fundamentally, saturate rather than panic in the `borrowed × index` / `supplied × index` value computations inside `accrue_step` — e.g. compute `scaled_to_original` via `mul_div_floor_saturating` or detect the would-overflow case and clamp the index to `MAX_BORROW_INDEX_RAY`/`MAX_SUPPLY_INDEX_RAY` (freezing *accrual* at the cap, not the market). Accrual ceasing at the cap is already the designed end state; the market should remain operable there so users can exit.

### Proof of Concept
Mirrors `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:320-361`:

1. Attacker (or whale) supplies `1e9` whole units of an 18-decimal asset (`BIG18`) to a hub market on the steep `xlm_curve`, with utilization caps lifted by governance configuration that permits it.
2. A borrower supplies collateral and borrows ~98% of the book (`principal * 98 / 100`).
3. Time advances (ledger timestamps); the permissionless `controller.update_indexes` / `pool.update_indexes` accrues in yearly chunks via `global_sync` → `accrue_chunk` → `accrue_step`.
4. Once `borrowed (≈9.8e35 RAY) × borrow_index` exceeds `i128::MAX`, `scaled_to_original` panics with `GenericError::MathOverflow` — while `borrow_index ≈ 170x` is still below `MAX_BORROW_INDEX_RAY`.
5. From that point every call that touches the market reverts: `try_update_indexes_for`, `try_withdraw_raw`, `try_repay` all return `MathOverflow`. Suppliers' funds are permanently locked.

Relevant code:
- `common/src/rates/simulate.rs` (`accrue_step`, lines 51-94) — overflow site at lines 60-61
- `common/src/rates/scaling.rs` (`scaled_to_original`, lines 14-16)
- `common/src/rates/index.rs` (`update_borrow_index` multiplies before clamping, lines 13-19; `calculate_supplier_rewards` `borrowed.mul(new_borrow_index)`, line 81)
- `contracts/pool/src/interest.rs` (`global_sync`/`accrue_chunk`, lines 20-53) — panic is hit before any state mutation