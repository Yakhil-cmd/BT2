### Title
Accrual-time `Ray` overflow in `calculate_supplier_rewards` permanently freezes a high-utilization market before the borrow-index cap can engage - (File: common/src/rates/index.rs)

### Summary
Every pool verb first runs `global_sync` accrual (`contracts/pool/src/interest.rs:20-33`), which calls `accrue_step` → `calculate_supplier_rewards`. That function computes `borrowed.mul(env, new_borrow_index)` and `borrowed.mul(env, old_borrow_index)` using checked fixed-point multiplication. For a large market (`borrowed` scaled shares near the i128 domain limit), the index can grow to a point where `borrowed × index` overflows `i128` and panics with `GenericError::MathOverflow` — *before* `update_borrow_index`'s `MAX_BORROW_INDEX_RAY` clamp (`common/src/rates/index.rs:13-19`, `common/src/constants/pool.rs:19`) can cap the index. Since the panic occurs inside accrual, every subsequent call on that market — `supply`, `withdraw`, `repay`, `liquidate`, `clean_bad_debt`, `update_indexes`, `recapitalize` — hits the same overflow and aborts. The market is permanently frozen: suppliers cannot exit, borrowers cannot repay, liquidators cannot liquidate, and governance cannot recapitalize. This is the Soroban analog of the report's "panic inside the contract runtime" class: a reachable arithmetic panic bricks user funds, and no external catch can recover it because the panic re-executes on every entry.

### Finding Description
In `common/src/rates/index.rs:73-89`, `calculate_supplier_rewards` multiplies total scaled debt by the borrow index with checked `Ray::mul` (`common/src/rates/scaling.rs:14-16`). There is no bound on `borrowed`; `update_borrow_index` caps only the *index* at `MAX_BORROW_INDEX_RAY` (= 1e9 RAY), not the product `borrowed × index`. For an 18-decimal asset supplied in whale quantities (e.g., 1e9·1e18 units → scaled shares ≈ 1e45 ray), `borrowed × index` exceeds `i128::MAX` (≈1.7e38) once the index grows past roughly 1e-7 RAY — far below the 1e9·RAY cap, meaning the cap is unreachable protection in practice. The repository's own harness test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:316-361`) demonstrates exactly this: after enough years at ~98% utilization on the steep segment of the XLM-style rate curve, `try_update_indexes_for` fails with `MATH_OVERFLOW`, and both `withdraw` and `repay` fail identically because "every verb accrues first." The cap assertion in the test confirms `borrow_index < MAX_BORROW_INDEX_RAY` at freeze time.

### Impact Explanation
Permanent freezing of funds for every participant in the affected (hub, token) market book. Suppliers' deposits, borrowers' collateral access via repayment, and all liquidation capacity on that market are lost simultaneously — and because liquidation is dead, underwater positions on that market can never be closed, converting the freeze into protocol insolvency as the debt becomes unbacked. `recapitalize` cannot rescue the book because it also accrues first. The loss is total for that market's suppliers and permanent; there is no admin path that skips accrual.

### Likelihood Explanation
Reachable entirely by unprivileged addresses through `controller::supply` and `controller::borrow` with attacker-sized amounts on a steep-curve market, plus time (or `update_indexes` calls, which are permissionless). Requirements: a market listed with high decimals and a steep interest model, high sustained utilization, and caps lifted enough to admit whale positions — the test shows the cliff is reached at 98% utilization on the XLM curve shape. Any user can then trigger the fatal accrual via a dust `update_indexes`, dust `supply`, or `repay` of 1 unit. Attack cost is the capital parked in the position; alternatively, organic growth of a legitimately large market reaches the same cliff with no attacker at all. Medium likelihood: it needs a very large position or a long horizon, but once crossed it is irreversible.

### Recommendation
Bound the product, not just the index. In `update_borrow_index`/`accrue_step`, clamp `new_borrow_index` to `min(MAX_BORROW_INDEX_RAY, i128::MAX / borrowed.raw())` (or compute interest on saturating arithmetic), so accrual degrades gracefully — e.g., capping index growth — instead of panicking. Equivalently, enforce a maximum `borrowed`/`supplied` scaled-share ceiling at market operations (`calculate_scaled_supply`/`calculate_scaled_borrow` in `common/src/rates/scaling.rs:37-56`) such that `scaled × MAX_BORROW_INDEX_RAY` cannot overflow `i128`. A defensive fallback is to wrap the reward computation so that on overflow the index is clamped to the largest non-overflowing value and revenue accrual is truncated, preserving liveness.

### Proof of Concept
Reproduced by the existing harness test at `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:320-361`:

```rust
let principal = BILLION * 10i128.pow(18);      // whale 18-decimal supply
t.supply_raw(BOB, "BIG18", principal);
let debt = principal / 100 * 98;               // 98% utilization
t.supply_raw(ALICE, "COL", BILLION * 10_000_000 * 3);
t.borrow_raw(ALICE, "BIG18", debt);
// advance years; accrual eventually panics:
assert_contract_error(t.try_update_indexes_for(&["BIG18"]), errors::MATH_OVERFLOW);
// market is frozen — every verb accrues first and hits the same panic:
assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);
// the borrow index cap never engaged:
assert!(book(&t, "BIG18").borrow_index < MAX_BORROW_INDEX_RAY);
```

Root cause chain: `global_sync` → `accrue_chunk` → `accrue_step` → `calculate_supplier_rewards` → `borrowed.mul(env, index)` (`common/src/rates/index.rs:80-81`) → checked `Ray` multiply overflows `i128` → `panic_with_error!(MathOverflow)` → transaction aborts → identical panic on every future entry to the market.