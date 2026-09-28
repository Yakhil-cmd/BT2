### Title
RAY value overflow permanently freezes an over-utilized market - (File: contracts/pool/src/cache/scale.rs)

### Summary
A sufficiently large high-decimal market can grow its accrued RAY-scaled debt value beyond the `i128` range before `MAX_BORROW_INDEX_RAY` engages. The overflow causes `scaled_to_original` to panic during accrual. Because pool operations accrue the market before applying their own logic, subsequent `withdraw`, `repay`, `liquidate`, and `update_indexes` calls fail repeatedly, permanently freezing the market.

### Finding Description
The attacker creates or uses an account, supplies a very large balance of a high-decimal asset and enough collateral, then borrows near full utilization. As interest accrues, the pool’s multiplication of scaled debt by the growing debt index reaches the `i128` ceiling before the configured borrow-index ceiling is reached. The regression scenario demonstrates that the last stored borrow index remains below `MAX_BORROW_INDEX_RAY`, so the intended index cap does not prevent the value conversion overflow. [1](#0-0) [2](#0-1) 

The triggering entrypoint is permissionless `Controller::update_indexes`, which forwards attacker-selected `HubAssetKey` values to the market accrual path. [3](#0-2)  Once the panic condition exists, `withdraw`, `repay`, and `liquidate` reach the same accrual before their settlement logic, so they cannot recover or close the affected market. [4](#0-3) [5](#0-4) 

### Impact Explanation
This is a permanent freezing-of-funds condition for the affected market. Suppliers cannot withdraw, borrowers cannot repay, and liquidators cannot liquidate because every recovery path first performs the overflowing accrual. The market remains operational in storage but can no longer process asset movement or debt settlement.

### Likelihood Explanation
The attack requires a market configuration whose supply and borrow caps admit extremely large balances, sufficient attacker liquidity, high-decimal assets, sustained high utilization, and enough ledger-time advancement for the index to cross the representable-value ceiling. No privileged call is needed once such a market exists: one address can supply both the borrowed asset and collateral, borrow the asset, and repeatedly call `update_indexes`.

### Recommendation
Apply the index ceiling before converting scaled balances to token values, and make the effective ceiling dynamic:

- Clamp accrual to `min(MAX_BORROW_INDEX_RAY, i128::MAX / total_scaled_debt)` before multiplication can overflow.
- Apply the same ceiling discipline to supply and debt indexes where their scaled totals are materialized.
- Keep conversion helpers checked, but ensure the checked multiplication only sees values that are already guaranteed representable.
- Add boundary tests proving that `withdraw`, `repay`, and `liquidate` still succeed at the maximum representable index.

### Proof of Concept
The existing boundary scenario exercises the exploit path:

1. Register a high-decimal borrowable market and a collateral market with sufficiently high configured caps.
2. As one unprivileged account, supply `1_000_000_000 * 10^18` base units of the borrowable asset.
3. Supply enough collateral to pass the health-factor and minimum-collateral checks.
4. Borrow approximately 98% of the supplied borrowable asset.
5. Advance ledger time and call `update_indexes(caller, [borrowable_hub_asset])` until accrual returns `MathOverflow`.
6. Call `withdraw`, `repay`, or `liquidate`; each fails with the same overflow because it accrues first.

The regression test demonstrates that the first failure occurs during `update_indexes`, after which both a one-unit withdrawal and a repayment fail with `MathOverflow`. [6](#0-5)

### Citations

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L315-320)
```rust
/// The cliff. A billion whole tokens is `1e36` raw ray; the value ceiling is
/// `i128::MAX`, 170 times that. At the XLM curve's steep segment the index
/// grows past 170x in a few years, and the next accrual panics inside
/// `scaled_to_original`. Every verb accrues first, so the market freezes:
/// no repay, no withdraw, no liquidation. The index cap never engages.
#[test]
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L321-356)
```rust
fn a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap() {
    let mut t = LendingTest::new()
        .with_market(big("BIG18", 18, xlm_curve()))
        .with_market(col())
        .with_max_utilization_disabled_all_markets()
        .build();
    lift_caps(&t, "BIG18", 18);
    lift_caps(&t, "COL", 7);
    let principal = BILLION * 10i128.pow(18);
    t.supply_raw(BOB, "BIG18", principal);
    let debt = principal / 100 * 98;
    t.supply_raw(ALICE, "COL", BILLION * 10_000_000 * 3);
    t.borrow_raw(ALICE, "BIG18", debt);

    let mut years = 0u32;
    let failure = loop {
        years += 1;
        assert!(
            years <= 40,
            "no cliff within 40 years; the bound in docs/reference/formulas.md is wrong"
        );
        t.advance_time(YEAR_SECS);
        if let Err(e) = t.try_update_indexes_for(&["BIG18"]) {
            break e;
        }
    };
    let failed: Result<(), soroban_sdk::Error> = Err(failure);
    assert_contract_error(failed, errors::MATH_OVERFLOW);
    let last = book(&t, "BIG18");
    assert!(
        last.borrow_index < MAX_BORROW_INDEX_RAY,
        "the index cap did not engage before the value overflow"
    );
    // The market is frozen: exits and repayments accrue first and hit the same panic.
    assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
    assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);
```

**File:** contracts/controller/src/lib.rs (L120-133)
```rust
    fn withdraw(
        env: Env,
        caller: Address,
        account_id: u64,
        withdrawals: Vec<(HubAssetKey, i128)>,
        to: Option<Address>,
    ) -> Vec<(HubAssetKey, i128)> {
        positions::process_withdraw(&env, &caller, account_id, &withdrawals, to)
    }

    /// Repays `account_id`'s debt using measured payments from the caller.
    /// Anyone may repay; excess payments are refunded to the caller.
    fn repay(env: Env, caller: Address, account_id: u64, payments: Vec<(HubAssetKey, i128)>) {
        positions::process_repay(&env, &caller, account_id, &payments);
```

**File:** contracts/controller/src/lib.rs (L144-158)
```rust
    fn liquidate(
        env: Env,
        liquidator: Address,
        account_id: u64,
        debt_payments: Vec<(HubAssetKey, i128)>,
        seize_mode: SeizeMode,
    ) -> u64 {
        positions::liquidation::process_liquidation(
            &env,
            &liquidator,
            account_id,
            &debt_payments,
            seize_mode,
        )
    }
```

**File:** contracts/controller/src/lib.rs (L367-372)
```rust
    /// Accrues pool borrow and supply indexes for `assets`. Permissionless;
    /// requires caller authorization.
    #[when_not_paused]
    fn update_indexes(env: Env, caller: Address, assets: Vec<HubAssetKey>) {
        markets::update_indexes(&env, caller, assets);
    }
```
