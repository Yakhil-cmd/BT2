### Title
Sustained high utilization on a whale-sized market pushes RAY-denominated totals past i128 and permanently freezes every verb on that market — (File: common/src/rates/index.rs)

### Summary
The gpac bug class is "crafted input drives a memory corruption that denies service." In this Soroban codebase, the analogous shape is arithmetic rather than memory: a single unprivileged address can size a market so that ordinary interest accrual overflows `i128` in RAY-denominated value calculations. Because every state-changing entrypoint accrues first, the resulting `MathOverflow` panic permanently bricks the market — no repay, no withdraw, no liquidation, no `update_indexes`. All user funds in that hub/token book are frozen forever.

### Finding Description
`global_sync` in `contracts/pool/src/interest.rs:20` runs `accrue_chunk`, which calls `accrue_step` → `calculate_supplier_rewards` (`common/src/rates/index.rs:73`) and `update_supply_index` (`common/src/rates/index.rs:29`). Both compute `borrowed.mul(new_borrow_index)` and `supplied.mul(old_index)` — products of two RAY-scaled values. `Ray::mul` raises `MathOverflow` when the result exceeds `i128::MAX`, even via the widened `I256` path, because the *result* (not the intermediate) is what does not fit.

The index ceilings (`MAX_BORROW_INDEX_RAY`, `MAX_SUPPLY_INDEX_RAY` ≈ 10^36) cap the *index*, but not the *value* `shares × index / RAY`. The protocol's own documentation admits this gap: "valid caps and bounded indexes do not guarantee that future accrual fits. Value overflow can occur before the index ceiling and block repayment/withdrawal because those operations accrue first" (`docs/reference/formulas.md:432-437`).

The harness test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321`) demonstrates reachability end-to-end: a ~1 billion whole-token supply with ~98% borrow utilization on the steep segment of the XLM rate curve drives `try_update_indexes_for` to `MathOverflow` before `borrow_index` reaches `MAX_BORROW_INDEX_RAY`, after which `withdraw` and `repay` also revert with the same error — the market is frozen with no recovery path (no escape hatch exists; `global_sync` runs before every op).

An attacker can construct this deliberately rather than waiting: supply the whale amount, then with a second account (or flash-minted collateral) borrow as much as possible to pin utilization near the steep part of the curve, maximizing index growth per unit time until the value ceiling trips. Once tripped, every other supplier's funds in that market are unrecoverable.

### Impact Explanation
Permanent freezing of funds: all suppliers' deposits, all borrowers' collateral seized via no liquidation path, and unclaimed revenue in that market become permanently locked. The protocol's own test asserts `withdraw` and `repay` revert with `MATH_OVERFLOW` and that the index cap "did not engage" — there is no in-protocol mechanism (no index write-down except `apply_bad_debt_to_supply_index`, which itself accrues first and also computes `supplied.mul(supply_index)` at `interest.rs:74`, so it panics too) to unstick the market.

### Likelihood Explanation
Requires whale-scale capital (≈170 billion token units is the cap max; the test uses ~1 billion whole tokens ≈ 1e18×10^9 base units at 18 decimals) and sustained near-max utilization for the accrual window, so it is a griefing attack with substantial capital lockup rather than a free trigger — but it is fully permissionless: `supply`, `borrow`, and `update_indexes` are all unprivileged, `lift_caps`-equivalent cap raising is reachable since caps are only governance-set bounds and the attacker simply uses a market with large caps. Medium severity is consistent with the capital requirement vs. permanent, multi-victim freeze.

### Recommendation
Add an explicit RAY-value ceiling check inside `accrue_step`: before computing `supplied.mul(new_index)` / `borrowed.mul(new_index)`, clamp the growth so the resulting value stays under `i128::MAX` (e.g., cap the effective `new_index` at `i128::MAX / supplied_shares * RAY`), matching how `update_supply_index` already clamps `MAX_SUPPLY_INDEX_RAY`. Alternatively, make the accrual loop in `global_sync` stop at the largest index whose value product fits, and emit the noted "ceiling alarm" event so listings can be wound down before the freeze.

### Proof of Concept
The repository ships a working exploit-as-test:

```rust
// tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321
let mut t = LendingTest::new()
    .with_market(big("BIG18", 18, xlm_curve()))
    .with_market(col())
    .with_max_utilization_disabled_all_markets()
    .build();
lift_caps(&t, "BIG18", 18);
let principal = BILLION * 10i128.pow(18);
t.supply_raw(BOB, "BIG18", principal);
let debt = principal / 100 * 98;
t.supply_raw(ALICE, "COL", BILLION * 10_000_000 * 3);
t.borrow_raw(ALICE, "BIG18", debt);
// advance time; try_update_indexes_for eventually errors MathOverflow
assert_contract_error(failed, errors::MATH_OVERFLOW);
assert!(last.borrow_index < MAX_BORROW_INDEX_RAY); // cap never engaged
assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);
```

Root-cause chain: unprivileged `supply`/`borrow` size `supplied`/`borrowed` shares → time accrual grows `borrow_index` → `accrue_chunk` calls `calculate_supplier_rewards`, whose `borrowed.mul(new_borrow_index)` (`common/src/rates/index.rs:80-81`) exceeds `i128::MAX` → `MathOverflow` → every entrypoint fails at `global_sync` (`contracts/pool/src/interest.rs:20`) permanently.