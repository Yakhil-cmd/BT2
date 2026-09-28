### Title
RAY debt-value overflow during interest accrual permanently freezes a market - (File: common/src/rates/simulate.rs)

### Summary
The pool computes each market’s borrowed value as `borrowed * borrow_index / RAY` before updating indexes. Once that quotient exceeds `i128::MAX`, accrual returns `MathOverflow`. Because every state-changing market operation accrues before acting, the same overflow prevents repayment, withdrawal, liquidation, bad-debt cleanup, and subsequent index updates.

### Finding Description
`accrue_step` in `common/src/rates/simulate.rs` unconditionally calls `scaled_to_original` for total borrowed shares and the borrow index before calculating utilization and the next index:

```rust
let borrowed_original = scaled_to_original(env, borrowed, borrow_index);
```

`scaled_to_original` delegates to `Ray::mul`, which calls `mul_div_half_up`. That helper preserves an oversized intermediate with `I256`, but still returns `None` when the final quotient exceeds `i128::MAX`; the wrapper then panics with `GenericError::MathOverflow`.

The pool invokes this step from `contracts/pool/src/interest.rs::global_sync`, which in turn is run before market mutations. Therefore, once the product of existing debt shares and the live borrow index crosses the representable RAY-value boundary, no later accrual can complete. The borrow-index ceiling does not prevent this condition because the ceiling limits the index, not `borrowed * index`; with sufficiently large scaled debt, overflow occurs well before the index approaches `MAX_BORROW_INDEX_RAY`.

An unprivileged path is:

1. Use `borrow(caller, account_id, [(debt_market, amount)], to)` to create a large debt position in a market whose configured caps and liquidity admit the amount.
2. Maintain high utilization through time so the borrow index grows.
3. Call `update_indexes(caller, [debt_market])` once the next accrual makes `borrowed_original` exceed `i128::MAX`.

After that call reverts, subsequent `repay`, `withdraw`, `liquidate`, `clean_bad_debt`, `flash_loan`, `flash_position`, strategy, `recapitalize`, or `update_indexes` calls touching the market hit the same accrual-first overflow.

### Impact Explanation
This permanently freezes all user funds and debt operations in the affected market. Suppliers cannot withdraw, borrowers cannot repay, liquidators cannot reduce unsafe debt, and cleanup or recapitalization cannot proceed because those paths load and synchronize the market before applying their own logic.

The impact is market-wide rather than limited to the account that created the oversized debt. Supplier principal and accrued yield remain inaccessible until privileged remediation such as an upgrade changes the accounting domain.

### Likelihood Explanation
The condition requires an exceptionally large debt market and sustained index growth, so it is not reachable in ordinary market sizes. However, it is reachable entirely through unprivileged `supply`, `borrow`, and `update_indexes` calls when configured caps, available liquidity, collateral value, and token supply permit the required position.

The repository’s harness demonstrates the condition with an 18-decimal market holding one billion whole tokens and approximately 98% utilization. In `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs`, repeated yearly index updates eventually produce `MATH_OVERFLOW`; the same test then verifies that both withdrawal and repayment revert. The failure occurs before the configured borrow-index ceiling is reached.

### Recommendation
Do not make accrual depend on converting total scaled debt into an unbounded RAY asset value. Options include:

- Calculate utilization from a reduced or capped representation that cannot overflow while preserving ordering.
- Bound `borrowed` based on the current index so `borrowed * borrow_index / RAY` always fits, and enforce that bound on borrow minting.
- Add an explicit debt-value ceiling below `i128::MAX`, reverting new borrows before the market reaches the cliff.
- If the ceiling is reached, clamp utilization or the derived borrow rate instead of panicking during mandatory synchronization.
- Emit an event or expose a view when the market approaches the representable-value bound so governance can reduce caps before the freeze.

Any fix must preserve the directed rounding rules for user positions while ensuring that routine accrual cannot permanently trap the market.

### Proof of Concept
The existing test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` reproduces the issue:

```rust
let principal = BILLION * 10i128.pow(18);
t.supply_raw(BOB, "BIG18", principal);
let debt = principal / 100 * 98;
t.borrow_raw(ALICE, "BIG18", debt);

loop {
    t.advance_time(YEAR_SECS);
    if let Err(e) = t.try_update_indexes_for(&["BIG18"]) {
        break e;
    }
}
```

The test then asserts:

```rust
assert_contract_error(failed, errors::MATH_OVERFLOW);
assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);
```

This demonstrates that once `scaled_to_original` overflows inside accrual, both exits and repayments remain blocked.