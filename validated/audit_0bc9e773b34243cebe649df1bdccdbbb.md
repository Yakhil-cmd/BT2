### Title
Accrual `Ray` value overflow permanently freezes a large high-utilization market — no repay, withdraw, or liquidation - (File: `common/src/rates/simulate.rs`)

### Summary
Every state-changing entrypoint on a pool market runs `interest::global_sync` first, which calls the shared `accrue_step` (`common/src/rates/simulate.rs:51`). That step unscales `borrowed` and `supplied` via `scaled_to_original`, a checked `Ray::mul` that panics with `MathOverflow` (33) once `scaled × index / RAY` exceeds `i128::MAX`. Because a market's scaled `borrowed`/`supplied` are fixed-size and the borrow index grows monotonically (capped only at `MAX_BORROW_INDEX_RAY = 1e36`, i.e. a ~1000x multiplier), a sufficiently large market at sustained high utilization crosses the ~170x index "value cliff" before the index cap ever engages. From that moment every accrual panics, so `supply`, `withdraw`, `repay`, `borrow`, `liquidate`, `clean_bad_debt`, `net_settle`, `flash_loan`, `claim_revenue`, and `recapitalize` on that market all revert permanently — the per-market analog of the chain halt in ISA-2025-001/002. `update_borrow_index` caps the index (`common/src/rates/index.rs:13-19`), but nothing caps the *value* product; `update_supply_index` also computes `supplied.mul(old_index)` and traps on the same product (`common/src/rates/index.rs:34`).

### Finding Description
- `accrue_step` line 60-61 computes `scaled_to_original(env, borrowed, borrow_index)` and `scaled_to_original(env, supplied, supply_index)` before doing anything else. `scaled_to_original` is `scaled.mul(env, index)` (`common/src/rates/scaling.rs:14-16`), a checked fixed-point multiply.
- `global_sync` (`contracts/pool/src/interest.rs:20-33`) loops `accrue_chunk` over elapsed time; every pool verb loads the `Cache` and accrues before mutating, so the panic precedes all repayment/exit logic.
- The index ceiling `MAX_BORROW_INDEX_RAY = 1e36` (1000x) is far above the i128 value ceiling: `i128::MAX ≈ 1.7e38` while a single market can hold scaled shares up to the admitted token-to-RAY maximum (~`1.7e38 / RAY` ≈ 170 billion whole tokens at index 1, and much more in raw share terms for low-index deposits). The product `borrowed × borrow_index` overflows at an index of roughly `i128::MAX / borrowed`, which for a ~1e36-scaled-debt market is ~170x — reachable in a few years on a steep curve at ~98% utilization, well before the 1000x cap.
- The failure is self-reinforcing: once `borrowed × borrow_index ≥ i128::MAX`, the index cannot be reduced (it is monotone), so the panic condition never clears. Even `clean_bad_debt`/`recapitalize`/`claim_revenue` cannot run because they too accrue first.

### Impact Explanation
Permanent freezing of funds and effective protocol insolvency on the affected market: suppliers cannot withdraw, borrowers cannot repay (their debt keeps notionally growing while liquidation is impossible — liquidations also accrue first), and bad debt cannot be cleaned or recapitalized. All cash backing that market is locked in the pool contract forever. This is precisely the "chain halt" impact class of the Cosmos advisory, mapped to a Soroban market halt.

### Likelihood Explanation
Reachable by unprivileged addresses: a whale supplies a very large principal (caps can be lifted only by admin, but admitted cap maxima already allow ~170B whole tokens; more realistically a high-decimals market with large cap) and a second account supplies collateral and borrows to ~98% utilization. After that, only time is needed — no further action, no governance, no price manipulation. The test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:320-361`) demonstrates exactly this: `update_indexes`, `withdraw`, and `repay` all fail with `MathOverflow`, and the index cap never engages. Note `docs/reference/formulas.md:432-437` acknowledges that "value overflow can occur before the index ceiling and block repayment/withdrawal," so this is a documented arithmetic limit — but the freeze remains an exploitable permanent-funds-freeze reachable by any large depositor.

### Recommendation
Break the panic path in accrual:
- In `accrue_step`/`update_borrow_index`, clamp the borrow index so that `borrowed × new_index / RAY ≤ i128::MAX` (a per-market value-aware cap), or
- Use a saturating/widened (256-bit) product for `scaled_to_original` on the totals path so accrual degrades to "cap reached, no further interest" instead of trapping, matching the sticky-cap behavior already implemented for `borrow_index == MAX_BORROW_INDEX_RAY`.
- Emit an event when the cap binds so indexers can flag a frozen-accrual market.

### Proof of Concept
The in-repo test is a complete PoC (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:320-361`):
1. Create market `BIG18` (18 decimals, XLM curve), lift caps.
2. `BOB.supply(BIG18, 1e9 * 1e18)`; `ALICE.supply(COL, …)` then `ALICE.borrow(BIG18, 0.98 * principal)`.
3. Advance ledger time one year per step and call `update_indexes(caller, [BIG18])` — permissionless.
4. After a few years the call fails `Error(Contract, #33)` (`MATH_OVERFLOW`) inside `scaled_to_original`; `borrow_index` is ~170x, far below `MAX_BORROW_INDEX_RAY`.
5. `withdraw(BOB, BIG18, 1)` and `repay(ALICE, BIG18, 1)` — and by extension `liquidate`, `supply`, `borrow`, `clean_bad_debt`, `recapitalize` — all fail identically and permanently.