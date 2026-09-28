### Title
Indivisible debt-unit rounding can make an insolvent account unliquidatable and strand supplier funds - ([File: contracts/controller/src/positions/liquidation/math.rs])

### Summary
`liquidate` can permanently reject every repayment for an insolvent account whose only debt asset has a minimum token unit worth more than the collateral-backed liquidation quote but whose remaining collateral is still above the `$5` bad-debt threshold. A borrower can create this state by borrowing one indivisible unit of a high-priced, low-granularity asset and waiting for its collateral to fall into the affected range. The debt cannot be seized through liquidation, while permissionless `clean_bad_debt` remains unavailable, leaving debt-market suppliers without a permissionless recovery path until prices move below the dust threshold or governance force-socializes the account.

### Finding Description
An unprivileged borrower can call `supply` and then `borrow`, with the post-borrow gate requiring only sufficient LTV collateral, health factor `>= 1`, and the configured collateral floor at creation time. [1](#0-0) [2](#0-1) 

After a collateral-price decline makes `total_collateral < total_debt`, `estimate_liquidation_amount` caps the quote at approximately `total_collateral / (1 + base_bonus)` rather than allowing a liquidator to repay the full indivisible debt unit. [3](#0-2) 

`normalize_repayment_plan` then invokes `process_excess_payment` with `keep_within_quote = true` for the insolvency branch. [4](#0-3)  For a single debt leg whose one native unit exceeds the quote, `process_excess_payment` floors the kept repayment to zero tokens and removes the only repayment leg. [5](#0-4)  Execution subsequently rejects the empty payment set with `InvalidPayments`. [6](#0-5) 

The permissionless cleanup cannot close the gap while collateral exceeds `BAD_DEBT_USD_THRESHOLD`, because `is_socializable_bad_debt` additionally requires collateral at or below that threshold. [7](#0-6)  The uncapped cleanup path is explicitly owner-only, so the affected account depends on governance recovery while it remains above the dust cap. [8](#0-7) [9](#0-8) 

### Impact Explanation
Debt-market suppliers can suffer loss of funds or prolonged inability to withdraw because the borrowed tokens are already outside the pool while the insolvent borrower's collateral cannot be converted through liquidation. The protocol has a socialization mechanism, but it is unavailable permissionlessly in the affected `$5 < collateral < debt-unit repayment requirement` interval. Interest continues to accrue during this interval, increasing the eventual supplier write-down. If the collateral price remains above `$5` rather than reaching the permissionless cleanup boundary, recovery requires the owner-only `force_socialize_bad_debt` operation.

This maps to the external report's core failure: an economically liquidatable borrower becomes operationally impossible to liquidate, and other users bear the resulting deficit or frozen liquidity.

### Likelihood Explanation
The setup does not require privileged actions, malformed parameters, oracle manipulation, or a special account status. The borrower only needs a listed debt market whose one native unit has a USD value greater than the collateral-backed insolvency quote. The included regression test constructs exactly this numerical state with a three-decimal `EXP` market priced at `$10,000`, where `$9` of collateral backs less than one `$10` repayment unit and liquidation reverts with `InvalidPayments`. [10](#0-9) 

The borrower's opening state is valid: a high-value unit can be backed by substantially more collateral before a market movement. The triggering condition is a normal collateral-price decline into a broad interval bounded below by the `$5` cleanup threshold, so the attack does not depend on an exact transient price.

### Recommendation
Allow an insolvency liquidation to accept the smallest indivisible repayment unit even when its USD value exceeds `floor(total_collateral / (1 + bonus))`, while capping seizure at all remaining collateral and crediting only the measured repayment.

Specifically:

- In `contracts/controller/src/positions/liquidation/math.rs`, keep one native unit of a debt leg instead of flooring it to zero during `process_excess_payment` when the account is insolvent and the unit is the minimum possible repayment.
- Treat that kept unit as satisfying the collateral-backed quote even if rounding makes its nominal USD value slightly exceed the quote.
- Permit `seize_all` for that minimum-unit repayment so the liquidator receives all collateral, then invoke the existing dust-gated cleanup if any debt residue remains.
- Alternatively, lower or remove the collateral dust cap for accounts whose liquidation plan becomes empty solely because no positive debt-token unit fits the quote, so `clean_bad_debt` can socialize the account permissionlessly.

### Proof of Concept
A concrete harness scenario is:

1. List collateral `COL` and debt asset `EXP`, with `EXP` using three decimals and priced at `$10,000`, so one native unit represents `$10`. This configuration is already used by the regression fixture. [11](#0-10) 
2. Alice supplies enough `COL` to pass the LTV and health gates, then borrows exactly one native unit of `EXP` (`0.001 EXP`).
3. `COL` falls until Alice's collateral is `$9`; her `EXP` debt is approximately `$10`, so the account is insolvent and liquidatable by health factor.
4. The insolvency quote is approximately `$9 / 1.05 = $8.57`, below the `$10` minimum debt repayment unit.
5. Any liquidator calling `liquidate(liquidator, alice_id, [(EXP, 1)], SeizeMode::Transfer)` has the sole leg trimmed to zero, after which `liquidate` reverts on the empty repayment set.
6. Calling `clean_bad_debt` reverts because collateral is `$9`, above the `$5` threshold.
7. The result is an insolvent account that cannot be permissionlessly liquidated or cleaned while the collateral remains in that range.

The repository's existing test demonstrates steps 4–5 directly: the estimate returns zero repayments and no seized collateral, execution reverts with `InvalidPayments`, and the two `EXP` units remain as debt. [12](#0-11)

### Citations

**File:** contracts/controller/README.md (L73-78)
```markdown
| `supply` | `fn supply( env: Env, caller: Address, account_id: u64, spoke_id: u32, assets: Vec<(HubAssetKey, i128)>, ) -> u64` | blocked by global pause | Supplies `assets` as collateral to `account_id` in spoke `spoke_id`, creating a new account when `account_id` is 0, and returns the account id. |
| `borrow` | `fn borrow( env: Env, caller: Address, account_id: u64, borrows: Vec<(HubAssetKey, i128)>, to: Option<Address>, )` | blocked by global pause | Borrows `borrows` against `account_id`'s collateral, sending the funds to `to` if provided or to the caller otherwise; reverts if the resulting position breaches the account's solvency limits. |
| `withdraw` | `fn withdraw( env: Env, caller: Address, account_id: u64, withdrawals: Vec<(HubAssetKey, i128)>, to: Option<Address>, ) -> Vec<(HubAssetKey, i128)>` | — | Withdraws `withdrawals` from `account_id`'s supplied collateral, sending the funds to `to` if provided or to the caller otherwise, and returns the amounts actually withdrawn; a zero amount for an asset withdraws the entire position. |
| `repay` | `fn repay(env: Env, caller: Address, account_id: u64, payments: Vec<(HubAssetKey, i128)>)` | — | Repays `payments` against `account_id`'s debt positions, pulling the funds from the caller and refunding any excess. |
| `liquidate` | `fn liquidate( env: Env, liquidator: Address, account_id: u64, debt_payments: Vec<(HubAssetKey, i128)>, seize_mode: SeizeMode, ) -> u64` | — | Liquidates `account_id` by having `liquidator` repay `debt_payments` and seizing collateral at a bonus scaled by the account's health factor. Returns the `Credit` receiver's account id, or 0 for `Transfer`. |
| `clean_bad_debt` | `fn clean_bad_debt(env: Env, caller: Address, account_id: u64)` | — | Socializes `account_id`'s debt into the supply index and removes the account when it is insolvent and its remaining collateral value is at or below the dust threshold; reverts otherwise. |
```

**File:** contracts/controller/src/risk/validation.rs (L29-58)
```rust
pub(crate) fn require_post_pool_risk_gates(env: &Env, cache: &mut Context, account: &Account) {
    if account.debt_free() {
        return;
    }

    let totals = risk::calculate_account_risk_totals(
        env,
        cache,
        &account.supply_positions,
        &account.borrow_positions,
    );

    assert_with_error!(
        env,
        totals.ltv_collateral >= totals.total_debt,
        CollateralError::InsufficientCollateral
    );

    spec_hooks::solvency_gate_checked(account);

    assert_with_error!(
        env,
        totals.health_factor >= Wad::ONE,
        CollateralError::InsufficientCollateral
    );

    let floor = storage::get_min_borrow_collateral_usd_wad(env);
    if floor != 0 && totals.ltv_collateral.raw() < floor {
        panic_with_error!(env, CollateralError::MinBorrowCollateralNotMet);
    }
```

**File:** contracts/controller/src/positions/liquidation/curve.rs (L23-27)
```rust
/// Admits socialization when debt exceeds collateral and collateral is at or
/// below `BAD_DEBT_USD_THRESHOLD` (WAD USD).
pub(crate) fn is_socializable_bad_debt(total_debt: Wad, total_collateral: Wad) -> bool {
    total_debt > total_collateral && total_collateral <= Wad::from(BAD_DEBT_USD_THRESHOLD)
}
```

**File:** contracts/controller/src/positions/liquidation/curve.rs (L117-123)
```rust
    let bonus = match max_hf_preserving_bonus_bps(snap) {
        None => scaled_bonus,
        Some(_) if snap.total_collateral < snap.total_debt => {
            let one_plus_base = Wad::ONE.checked_add(env, bounds.base.to_wad(env));
            let backed = snap.total_collateral.div_floor(env, one_plus_base);
            return (backed.min(snap.total_debt), bounds.base);
        }
```

**File:** contracts/controller/src/positions/liquidation/math.rs (L186-204)
```rust
    let (curve_repayment_usd, bonus) = estimate_liquidation_amount(env, snap, bonus_bounds, curve);
    let insolvent = snap.total_collateral < snap.total_debt;
    let ideal_repayment_usd = if insolvent || curve_repayment_usd >= snap.total_debt {
        curve_repayment_usd
    } else {
        whole_unit_repayment(env, account, snap, curve_repayment_usd, bonus, cache)
    };
    let full_close = ideal_repayment_usd >= snap.total_debt;

    let mut final_repayment_tokens = repaid_tokens;
    if !full_close && total_debt_payment_usd > ideal_repayment_usd {
        let excess_usd = total_debt_payment_usd.checked_sub(env, ideal_repayment_usd);
        process_excess_payment(
            env,
            &mut final_repayment_tokens,
            &mut refunds,
            excess_usd,
            insolvent,
        );
```

**File:** contracts/controller/src/positions/liquidation/math.rs (L665-687)
```rust
        if usd > remaining_excess_usd {
            let decimals = entry.feed.asset_decimals;
            let price = Wad::from(entry.feed.price_wad);
            let new_amount = if keep_within_quote {
                usd.checked_sub(env, remaining_excess_usd)
                    .div_floor(env, price)
                    .to_token_floor(env, decimals)
                    .min(entry.amount)
            } else {
                let ratio = remaining_excess_usd.div_floor(env, usd);
                entry.amount
                    - Wad::from_token(env, entry.amount, decimals)
                        .mul_floor(env, ratio)
                        .to_token_floor(env, decimals)
            };
            let new_usd = Wad::from_token(env, new_amount, decimals).mul(env, price);
            refunds.push_back(PaymentTuple {
                asset: entry.hub_asset.asset.clone(),
                amount: entry.amount - new_amount,
            });
            if new_amount == 0 {
                repaid_tokens.remove(current_index);
            } else {
```

**File:** contracts/controller/src/positions/liquidation/mod.rs (L64-67)
```rust
    let result = liquidation_plan.into_result();

    require_non_empty_payments(env, &result.repaid);

```

**File:** contracts/controller/src/positions/liquidation/mod.rs (L202-208)
```rust
/// Admission condition for bad-debt socialization.
#[derive(Clone, Copy, PartialEq)]
enum BadDebtGate {
    /// Permissionless: insolvent *and* collateral at or below the dust threshold.
    DustCapped,
    /// Owner-only: insolvent alone, with no cap on the collateral left behind.
    InsolventOnly,
```

**File:** docs/reference/runbooks/force-socialize-bad-debt.md (L19-23)
```markdown
1. Confirm the network, target controller, governance contract, account id,
   NFT owner, positions and spoke. `force_socialize_bad_debt` is owner-only.
   Governance, the controller owner, schedules `ForceSocializeBadDebt` on the
   Sensitive delay tier; follow the
   [governance interface](../endpoints.md#governance) for proposal and execution.
```

**File:** tests/test-harness/tests/controller/liquidation_extreme.rs (L653-666)
```rust
fn insolvent_book_with_a_ten_dollar_unit(col_price_wad: i128) -> (LendingTest, u64) {
    let mut t = LendingTest::new()
        .with_market(asset("COL", 7, usd(1), 7500, 8000, 500, 1_000_000.0))
        .with_market(asset("CHEAP", 7, usd(1), 7500, 8000, 500, 1_000_000.0))
        .with_market(asset("EXP", 3, usd(10_000), 7500, 8000, 500, 100.0))
        .with_min_borrow_collateral_disabled()
        .build();
    t.supply(ALICE, "COL", 1_000.0);
    t.borrow(ALICE, "CHEAP", 90.0);
    t.borrow(ALICE, "EXP", 0.002);
    t.set_price("COL", col_price_wad);
    let account_id = t.resolve_account_id(ALICE);
    assert!(t.total_collateral_raw(ALICE) < t.total_debt_raw(ALICE));
    (t, account_id)
```

**File:** tests/test-harness/tests/controller/liquidation_extreme.rs (L719-744)
```rust
/// $9 of collateral backs $8.57, less than one $10 EXP unit: the estimate
/// keeps no repayment and refunds the whole offer, and execution reverts.
#[test]
fn test_insolvent_liquidation_reverts_when_no_debt_unit_fits_the_backed_quote() {
    let (mut t, account_id) = insolvent_book_with_a_ten_dollar_unit(usd(9) / 1_000);
    let exp = t.resolve_asset("EXP");
    let payments = vec![&t.env, (hub_asset(exp.clone()), 2)];
    let estimate =
        t.ctrl_client()
            .get_liquidation_estimate(&account_id, &payments, &SeizeMode::Transfer);
    assert_eq!(estimate.max_payment_wad, 0);
    assert!(estimate.seized_collaterals.is_empty());
    let refund = estimate.refunds.get(0).expect("EXP refund");
    assert_eq!((refund.asset, refund.amount), (exp, 2));

    let liquidator = t.get_or_create_user(LIQUIDATOR);
    t.resolve_market("EXP").token_admin.mint(&liquidator, &2);
    let result = map_try_ok_value(t.ctrl_client().try_liquidate(
        &liquidator,
        &account_id,
        &payments,
        &SeizeMode::Transfer,
    ));
    assert_contract_error(result, errors::INVALID_PAYMENTS);
    assert_eq!(t.token_balance_raw(LIQUIDATOR, "EXP"), 2);
    assert_eq!(t.borrow_balance_raw(ALICE, "EXP"), 2);
```
