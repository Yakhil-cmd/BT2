### Title
`liquidate` has no minimum-seizure / expected-bonus slippage bound, so a competing liquidation can be front-run to degrade the bonus and seize less collateral than the repaid debt is worth - (File: contracts/controller/src/lib.rs)

### Summary
`Controller::liquidate` lets any unprivileged liquidator repay a victim's debt and seize collateral at a health-factor-based bonus computed at execution time. The entrypoint takes `debt_payments` and a `SeizeMode`, but exposes no parameter to bound the outcome — no minimum collateral seized, no maximum repayment actually applied, no expected bonus. Because the bonus is an HF-dependent curve (`set_spoke_liquidation_curve` configures `target_hf_wad`, `hf_for_max_bonus_wad`, `liquidation_bonus_factor_bps`), a front-runner can execute a small partial liquidation of the same account first, raising the victim's HF into a lower-bonus band and consuming pro-rata collateral, so the back-run liquidation settles on strictly worse terms with no revert. This is the same bug class as the reported `_updateSponsor` front-run: a caller commits funds expecting a computed outcome (`get_liquidation_estimate`), an unprivileged transaction changes the terms first, and the victim's payment still executes.

### Finding Description
`fn liquidate(env, liquidator, account_id, debt_payments, seize_mode) -> u64` is permissionless and delegates to `positions::liquidation::process_liquidation` [1](#0-0) . The liquidator's declared `debt_payments` are pulled and applied against the victim's debt, and seized collateral is computed from a pro-rata plan priced at execution time on the HF-based bonus curve (`positions/liquidation/math.rs`, `curve.rs`, `plan.rs`). There is no `min_seized`, `expected_bonus_bps`, or `max_debt_paid` argument — the only bound is whatever the plan computes on the current state.

The liquidation bonus is a function of the account's health factor, which is state a competitor can move: a small `debt_payments` liquidation by Bob raises the victim's HF, moving it along the bonus curve from `hf_for_max_bonus_wad` toward `target_hf_wad`, reducing Alice's bonus. Bob's partial liquidation also removes collateral pro-rata, so for a victim near insolvency Alice can repay debt while the remaining collateral seized at the degraded bonus is worth less than her measured payment — the plan's whole-unit sub-3-decimal leg rounding and per-leg caps make this gap real rather than theoretical. Separately, permissionless `update_indexes` (interest accrual) and `update_account_threshold` (restamping cached LTV/threshold snapshots) are additional unprivileged state-mutation levers that shift the same computed terms [2](#0-1) . `get_liquidation_estimate` advertises the pre-computation a liquidator would rely on, but nothing in `liquidate` enforces it [3](#0-2) .

### Impact Explanation
Alice loses funds: her debt payment is pulled and burned against the victim's debt, while the collateral she seizes (pool cash in `SeizeMode::Transfer`, or supply shares in `SeizeMode::Credit`) is valued at a worse bonus than she priced. On a low-collateral account the seized value can fall below the repaid value — direct theft of liquidator funds equivalent to the value gap. Bob profits by extracting the high-bonus tranche first and leaving the degraded remainder.

### Likelihood Explanation
Liquidation is permissionless and competitive, so front-running of the same target is the normal operating condition, not an edge case. Any unprivileged address can submit a partial `liquidate` (or `update_indexes`/`update_account_threshold`) ahead of a pending liquidation; Soroban's simulation shows liquidators the expected output via `get_liquidation_estimate`, but the executing transaction applies whatever the mutated state yields. Requires a victim account already liquidatable and a profitable bonus band — Medium likelihood, Medium impact.

### Recommendation
Add caller-specified bounds to `liquidate`, e.g. a `min_seized` per collateral leg (or an `expected_bonus_bps` / `min_hf_wad` guard) and a per-leg `max_debt_payment_applied`, reverting when the executed plan violates them — analogous to the `min_out` pattern the swap-aggregator already enforces (`SlippageExceeded`). The estimate view already returns expected seizure, fees, and bonus, so callers can populate the bound from the same simulation they use today.

### Proof of Concept
1. Victim V's account is liquidatable at HF = h where the curve assigns near-maximum bonus; collateral C backing debt D.
2. Alice simulates `get_liquidation_estimate(V, payments, SeizeMode::Transfer)` and submits `liquidate(V, payments, Transfer)` expecting collateral worth `(1 + bonus_max) * payment`.
3. Bob front-runs with `liquidate(V, small_payment, Transfer)`: V's debt shrinks, HF rises into a lower-bonus band, and C is reduced pro-rata.
4. Alice's transaction executes with no revert: her full payment is pulled, but the plan seizes collateral at the reduced bonus on the shrunken collateral base — seized value < paid value.
5. Alice holds collateral worth less than her outlay; Bob captured the profitable tranche.

### Citations

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

**File:** contracts/controller/src/lib.rs (L370-388)
```rust
    fn update_indexes(env: Env, caller: Address, assets: Vec<HubAssetKey>) {
        markets::update_indexes(&env, caller, assets);
    }

    /// Claims pool revenue and forwards measured receipts to the accumulator.
    /// Returns those amounts in asset units, in input order. Permissionless;
    /// requires caller authorization.
    #[when_not_paused]
    fn claim_revenue(env: Env, caller: Address, assets: Vec<HubAssetKey>) -> Vec<i128> {
        markets::claim_revenue(&env, caller, assets)
    }

    /// Refreshes supply LTV snapshots. With `has_risks`, also refreshes gated
    /// liquidation parameters and requires a final health factor of at least
    /// 1.05 WAD. Permissionless; requires caller authorization.
    #[when_not_paused]
    fn update_account_threshold(env: Env, caller: Address, has_risks: bool, account_ids: Vec<u64>) {
        risk::params::update_account_threshold(&env, caller, has_risks, account_ids);
    }
```

**File:** contracts/controller/src/lib.rs (L470-477)
```rust
    fn get_liquidation_estimate(
        env: Env,
        account_id: u64,
        debt_payments: Vec<(HubAssetKey, i128)>,
        seize_mode: SeizeMode,
    ) -> LiquidationEstimate {
        views::liquidation_estimations_detailed(&env, account_id, &debt_payments, seize_mode)
    }
```
