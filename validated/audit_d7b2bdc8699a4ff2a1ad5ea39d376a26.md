### Title
Accrued-debt RAY multiplication overflows before the index cap and permanently freezes the market - ([File: common/src/rates/index.rs](common/src/rates/index.rs))

### Summary
The interest-accrual path computes total debt as `borrowed * borrow_index` without bounding the resulting RAY value to `i128::MAX`. The configured `MAX_BORROW_INDEX_RAY` is `1e9` times RAY, while a large market can hold enough scaled debt that an index near `~170x` already overflows `i128`. Once that state is reached, every pool mutation synchronizes interest before mutating and reverts in `calculate_supplier_rewards`. Because the accrual never commits `last_timestamp`, subsequent calls repeat the same arithmetic failure.

### Finding Description
`Cache::calculate_utilization` and accrual calculate debt value through `scaled_to_original`, which is implemented as `scaled.mul(env, index)` in `common/src/rates/scaling.rs:14-16`. `Ray::mul` panics with `MathOverflow` when the RAY-scaled product cannot fit into `i128`.

During accrual, `contracts/pool/src/interest.rs:20-32` runs `accrue_chunk` for each elapsed interval. `accrue_chunk` calls `accrue_step` at `contracts/pool/src/interest.rs:40-48`, which reaches `calculate_supplier_rewards`. That function unconditionally computes:

```rust
let old_total_debt = borrowed.mul(env, old_borrow_index);
let new_total_debt = borrowed.mul(env, new_borrow_index);
```

at `common/src/rates/index.rs:80-81`.

Although `update_borrow_index` attempts to cap the next index at `MAX_BORROW_INDEX_RAY` in `common/src/rates/index.rs:13-18`, the cap itself is `1e36` raw RAY units, i.e. an index multiplier of `1e9`, in `common/src/constants/pool.rs:18-23`. There is no corresponding bound that guarantees `borrowed * capped_index / RAY <= i128::MAX`. A sufficiently large debt therefore hits the value ceiling long before the nominal index cap.

Every normal pool operation loads an interest-synced market through `synced_market`, which calls `interest::global_sync`, at `contracts/pool/src/ops/mod.rs:30-33`. The permissionless controller `update_indexes` path calls the pool accrual through `contracts/controller/src/markets.rs:118-125` and `contracts/controller/src/external/pool.rs:109-116`. Repayment also reaches pool `repay` through `contracts/controller/src/positions/debt.rs:209-219`. Therefore, once the product overflows, repayment, withdrawal, liquidation processing, explicit index updates, and other debt-market mutations all revert before changing state.

### Impact Explanation
This is a permanent market-level freeze of user funds and protocol functions.

- Suppliers cannot withdraw the affected asset.
- Borrowers cannot repay or close the debt.
- Liquidators cannot reduce risk in the affected market.
- Protocol revenue and ordinary market operations that require accrual cannot proceed.
- `recapitalize` cannot repair the condition where recapitalization or governance parameter replacement first performs the same accrual.
- The failure is not self-healing: `last_timestamp` is only committed after accrual completes, so every later transaction starts from the same unsafe state.

The issue does not require malformed calldata parsing or an external dependency. It is a reachable arithmetic denial of service in the protocol's RAY accounting domain.

### Likelihood Explanation
Likelihood is constrained by the need for an unusually large market and sustained high-utilization accrual. An unprivileged user must create or use an existing market with enough scaled debt that `borrowed * borrow_index / RAY` exceeds `i128::MAX` before `borrow_index` reaches `MAX_BORROW_INDEX_RAY`.

A feasible route is:

1. Supply a very large amount of a high-decimal asset.
2. Supply sufficient collateral in another market.
3. Borrow a large fraction of the first market through `borrow`.
4. Leave the market at high utilization while interest accrues.

No privileged role is required for these actions or for later calling `update_indexes`. The capital requirement is substantial, but it is not a governance, oracle, leaked-key, upgrade, or third-party honesty assumption. The test harness explicitly demonstrates this failure mode: `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:315-356` states that a billion-token, 18-decimal market at 98% utilization reaches the RAY-value cliff before the index cap and then rejects both withdrawal and repayment.

### Recommendation
Enforce the actual `i128` value-domain invariant, not only the nominal index cap.

At minimum:

- Derive a per-market borrow-index ceiling as `floor(i128::MAX * RAY / borrowed)` before computing debt value.
- Apply the equivalent bound to the supply-side calculations that multiply `supplied` by `supply_index`.
- Enforce borrow and supply caps so newly minted scaled positions cannot exceed the maximum safe value under the configured index ceiling.
- If saturation is intended, make it explicit and economically reviewed; silently capping total debt would understate liabilities and can create insolvency.
- Add regression coverage asserting that repayment, withdrawal, liquidation, `update_indexes`, and parameter replacement remain executable at the largest permitted scaled balances and maximum configured rate.

A robust fix should bound or saturate the total-value calculation before `borrowed.mul(index)`, rather than only lowering the global `MAX_BORROW_INDEX_RAY` constant.

### Proof of Concept
The repository contains a direct regression-style demonstration in `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321-356`:

```rust
let principal = BILLION * 10i128.pow(18);
t.supply_raw(BOB, "BIG18", principal);
let debt = principal / 100 * 98;
t.supply_raw(ALICE, "COL", BILLION * 10_000_000 * 3);
t.borrow_raw(ALICE, "BIG18", debt);

loop {
    t.advance_time(YEAR_SECS);
    if let Err(e) = t.try_update_indexes_for(&["BIG18"]) {
        break e;
    }
}

assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);
```

Equivalent unprivileged transaction sequence:

1. Call `supply(caller = supplier, account_id = 0, spoke_id = S, assets = [(BIG18, principal)])`.
2. Call `supply(caller = borrower, account_id = 0, spoke_id = S, assets = [(COL, sufficient_collateral)])`.
3. Call `borrow(caller = borrower, account_id = borrower_id, borrows = [(BIG18, debt)], to = None)` where `debt ≈ 98%` of the supplied liquidity.
4. Advance ledger time until accrual pushes `borrowed * borrow_index / RAY` past `i128::MAX`.
5. Call `update_indexes(caller = anyone, assets = [BIG18])`; it reverts with `MathOverflow`.
6. Call `withdraw` or `repay` on the same market; both revert because their pool call accrues first.

The final state is permanently stuck because no successful call can commit the accrued timestamp or lower the index.