### Title
Debt-value overflow inside interest accrual permanently freezes a market — no repay, withdraw, liquidate, or borrow possible - (File: common/src/rates/simulate.rs)

### Summary
CVE-2021-3580 is a crafted-input crash leading to denial of service. The analog here is a panic in the pool's mandatory interest-accrual step: `accrue_step` computes `scaled_to_original(borrowed, borrow_index)` before the borrow-index cap is applied, and when the RAY-scaled debt value exceeds `i128::MAX` the multiplication panics with `GenericError::MathOverflow`. Because every state-changing pool entrypoint runs `global_sync` (which calls `accrue_step`) before doing anything else, once this state is reached the market is permanently bricked — the panic is not a per-transaction abort but a durable freeze of all user funds in that market.

### Finding Description
`accrue_step` at `common/src/rates/simulate.rs:60-62` unscales total debt with `scaled_to_original` → `scaled.mul(env, index)` (`common/src/rates/scaling.rs:14-16`), a checked `i128` multiply that panics on overflow via `to_i128`/`MathOverflow` (`common/src/math/fp_core.rs:300-303`). The index ceiling `MAX_BORROW_INDEX_RAY` (10^36 RAY) is only applied inside `update_borrow_index` at line 66 — after the overflow-prone unscale. So a market whose `borrowed` scaled shares are large enough that `borrowed * borrow_index` exceeds `i128::MAX` (~1.7e38, i.e. RAY value > ~170) reverts inside accrual before the cap can stick.

`contracts/pool/src/interest.rs:20-33` shows `global_sync` runs `accrue_chunk` → `accrue_step` on every mutation when time has elapsed, and `contracts/pool/README.md` documents the fixed sequence `Cache::load → interest::global_sync → mutate → guards → commit`. Consequently `withdraw`, `repay`, `borrow`, `supply`, `net_settle`, liquidation repayments, `update_indexes`, `claim_revenue`, and `recapitalize` all hit the same panic. `clean_bad_debt` also accrues first, so it cannot recover the market either.

The state is reachable by unprivileged users: `supply` and `borrow` mint scaled shares in token units × 10^(27−decimals). For an 18-decimal asset a principal of ~10^9 tokens already produces ~10^36-scaled shares; at the steep end of a configured rate curve the borrow index crosses ~170× within a few years while below the 10^36 index cap. The repo's own harness test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321-361`) proves exactly this: `try_update_indexes_for`, `try_withdraw_raw`, and `try_repay` all fail with `MATH_OVERFLOW`, and the comment states "the market freezes: no repay, no withdraw, no liquidation. The index cap never engages."

### Impact Explanation
Permanent freezing of funds. Once `borrowed × borrow_index` crosses `i128::MAX`, every exit and every recovery path accrues first and panics. Suppliers cannot withdraw, borrowers cannot repay, liquidators cannot act, and recapitalize/clean_bad_debt (which also accrues) cannot unfreeze the market. All tokens held by the pool for that market are locked permanently. An attacker can deliberately trigger this on a market it helped grow, or it arises organically on a large high-utilization market — either way other users' deposits are frozen.

### Likelihood Explanation
Requires a market with RAY-scaled borrowed value approaching ~1.7e38, i.e. an asset with many decimals (up to 18 is allowed), large caps, and sustained high borrow rate for an extended period, or a whale deliberately supplying/borrowing enormous size. The entrypoints used (`supply`, `borrow`, `update_indexes`) are all permissionless, and no privileged action can prevent or fix the freeze. INV-IDX-01 in `docs/reference/invariants.md:235-236` acknowledges that "debt-value overflow can still revert accrual," so this is partly a documented limitation rather than a silent defect — severity is tempered accordingly, but the permanent-funds-freeze impact is real and demonstrated by an in-repo test.

### Recommendation
In `accrue_step`, cap the borrow index *before* unscaling debt, or compute `borrowed_original` with saturating/widened (`I256`) arithmetic so utilization is evaluated against a clamped value rather than panicking. Alternatively, clamp `borrowed` value used for utilization at the representable ceiling and continue accrual at `MAX_BORROW_INDEX_RAY`, which the invariants already define as the sticky "accrues nothing" state. At minimum, give repay/withdraw a path that skips or tolerates the overflow so user exits are never permanently blocked.

### Proof of Concept
```rust
// Condensed from tests/test-harness/tests/controller/
// large_positions_and_long_horizons.rs:321-361 (existing test)
let mut t = LendingTest::new()
    .with_market(big("BIG18", 18, xlm_curve()))
    .with_market(col())
    .with_max_utilization_disabled_all_markets()
    .build();
lift_caps(&t, "BIG18", 18);
lift_caps(&t, "COL", 7);
let principal = BILLION * 10i128.pow(18);        // unprivileged supply
t.supply_raw(BOB, "BIG18", principal);
t.supply_raw(ALICE, "COL", BILLION * 10_000_000 * 3);
t.borrow_raw(ALICE, "BIG18", principal / 100 * 98); // 98% utilization

loop {
    t.advance_time(YEAR_SECS);
    if t.try_update_indexes_for(&["BIG18"]).is_err() { break; }
}
// MathOverflow from scaled_to_original(borrowed, borrow_index)
// in accrue_step — borrow_index < MAX_BORROW_INDEX_RAY.
// Market is now frozen forever:
assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);
```

1. Supplier deposits a very large amount of an 18-decimal asset; borrower draws ~98% utilization (both unprivileged).
2. Time advances; each `update_indexes` (permissionless) grows `borrow_index` while `borrowed` shares stay ~10^36-scaled.
3. When `borrowed * borrow_index > i128::MAX`, `accrue_step` line 60 panics before the 10^36 cap engages.
4. Every subsequent `withdraw`, `repay`, `liquidate`, `recapitalize`, `clean_bad_debt` hits the same panic → permanent freeze of all funds in the market.