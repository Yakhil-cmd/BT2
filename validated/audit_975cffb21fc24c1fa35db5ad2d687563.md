### Title
Overflow in accrual (`borrowed * new_borrow_index` and `supplied * supply_index` past i128) permanently freezes a market before the borrow-index cap engages — (File: common/src/rates/simulate.rs)

### Summary
The CVE class is an integer overflow corrupting state. In XOXNO Lending the analog is the RAY-value ceiling: `accrue_step` computes `scaled_to_original(borrowed, borrow_index)` and `borrowed.mul(new_borrow_index)` on every accrual, and these panic with `MathOverflow` once `scaled_shares * index` leaves the i128/RAY domain. Because every pool mutation runs `interest::global_sync` first, once any market's `borrowed * borrow_index` product overflows — which happens while the borrow index is still below `MAX_BORROW_INDEX_RAY` — the market can never accrue again, permanently freezing all supply and debt in it. The protocol's own regression test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` demonstrates the freeze end-to-end (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321-356`).

### Finding Description
`accrue_step` at `common/src/rates/simulate.rs:60` calls `scaled_to_original(borrowed, borrow_index)`, which delegates to `Ray::mul` → `mul_div_half_up` in `common/src/math/fp_core.rs`. The I256 widened path keeps the intermediate exact but the result must still fit i128; when `borrowed_shares * borrow_index / RAY` exceeds `i128::MAX` it panics with `MathOverflow`. `calculate_supplier_rewards` (`common/src/rates/index.rs:80-83`) repeats the same product for `new_borrow_index`. `update_borrow_index` (`common/src/rates/index.rs:13-18`) caps the index at `MAX_BORROW_INDEX_RAY` (10^36), but the value ceiling `i128::MAX / RAY ≈ 1.7e11` whole tokens is hit first whenever scaled borrowed shares are large enough that `index × borrowed` overflows before `index` reaches the cap — the index cap therefore does not protect the accrual path.

Every market entrypoint calls `Cache::load` → `interest::global_sync` (`contracts/pool/src/interest.rs:20-33`), which loops `accrue_chunk` → `accrue_step`. There is no catch; a panic aborts the whole transaction. `repay`, `withdraw`, `liquidate`, `flash_loan`, `clean_bad_debt`/`seize_positions`, `recapitalize`, and the permissionless `update_indexes` all go through `global_sync`, so once the product overflows no path can advance `last_timestamp` or touch the market — including the bad-debt socialization and recapitalization escape hatches.

An unprivileged address reaches this by supplying a very large position (`controller::supply` → `pool::supply`) and keeping utilization high via `borrow` on a steep curve segment, then letting time accrue; the test fixture uses `BILLION * 10^18` principal at 98% utilization on the XLM curve and hits the cliff within 40 simulated years, before `MAX_BORROW_INDEX_RAY`.

### Impact Explanation
Permanent freezing of funds and protocol insolvency. All supplier deposits in the affected `(hub, token)` book become unwithdrawable forever — `withdraw` accrues first and reverts. Debtors cannot repay, liquidators cannot liquidate, and bad debt cannot be cleaned or recapitalized, so the market's cash and its unclaimed yield are locked permanently. The freeze is unconditional once the product crosses the bound: there is no admin path (`update_params`, `upgrade` excluded by scope) that avoids `global_sync`, and `recapitalize`/`claim_revenue` also accrue first and revert with `MathOverflow`.

### Likelihood Explanation
Medium-Low in isolation, but the path is entirely unprivileged: `supply` and `borrow` are open to any account, and `update_indexes` is a permissionless keeper. The barrier is capital and time — the market's debt must reach roughly `i128::MAX / index` in RAY terms, i.e., a whale-scale book on a high-decimals token held at sustained high utilization on a steep rate curve for years. Governance can raise caps (`lift_caps` in the test) but caps near the documented `i128::MAX / 10^(27-d)` admission maximum already permit the required principal. No oracle manipulation, privileged action, or leaked key is needed; the attacker only needs to be early and patient, or to contribute the marginal supply/debt that pushes an already-large market over the cliff. Once crossed, the freeze is irreversible and steals or locks 100% of that book's funds.

### Recommendation
Insert a guard in `accrue_step`/`global_sync` that prevents the panic from becoming permanent:

- Before computing `borrowed.mul(new_borrow_index)`, check whether the product fits i128 (e.g., `borrowed <= (i128::MAX - RAY/2) / new_borrow_index` as the certora rule at `certora/common/spec/rate_index_accounting_rules.rs:384` already encodes); if it would overflow, clamp `new_borrow_index` to the largest index for which `borrowed * index / RAY` fits — effectively an effective per-book index cap below `MAX_BORROW_INDEX_RAY` — rather than panicking.
- Alternatively, when the value product overflows, freeze only the growth of that market's index (accrue nothing, stamp `last_timestamp`) so `repay`, `withdraw`, `liquidate` and `clean_bad_debt` still execute against the last representable indexes instead of trapping forever.
- Add an explicit invariant test pinning that `update_indexes` never reverts for any committed state within admitted caps, not just before the cliff.

### Proof of Concept
`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321-356` is already a working PoC:

```rust
let principal = BILLION * 10i128.pow(18);
t.supply_raw(BOB, "BIG18", principal);
t.borrow_raw(ALICE, "BIG18", principal / 100 * 98);   // 98% utilization
// advance years; update_indexes eventually fails
assert_contract_error(failed, errors::MATH_OVERFLOW);
assert!(last.borrow_index < MAX_BORROW_INDEX_RAY);    // cap never engaged
// market permanently frozen:
assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);
```

Steps: (1) supply ~10^27 base units of an 18-decimal hub asset, (2) borrow ~98% of it against collateral in a second market, (3) let the steep-segment rate compound for a few years, (4) call the permissionless `update_indexes` → `global_sync` → `accrue_step` → `scaled_to_original` panics inside `borrowed * borrow_index` past i128; every subsequent `withdraw`, `repay`, `liquidate` and `recapitalize` reverts identically, permanently freezing the market.