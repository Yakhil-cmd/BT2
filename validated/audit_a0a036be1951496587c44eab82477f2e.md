### Title
`multiply` charges a mutable `flashloan_fee` on the borrow leg with no user-specified maximum, so a fee change between quoting and execution silently reduces proceeds while debt stays full - ([File: contracts/pool/src/ops/strategy.rs])

### Summary
`multiply` borrows via `pool_create_strategy_call` with `charge_fee = true`, so the pool mints debt for the full requested `amount` but only transfers `amount - fee`, where `fee` is derived from the admin/governance-mutable `flashloan_fee` market param at execution time. Neither `multiply` nor `create_strategy` accepts a `max_fee`/`min_received` bound on this leg, mirroring the Union Finance `UToken.borrow` finding where `originationFee` could change between quote and execution with no `maxDebt` cap.

### Finding Description
In `process_multiply`, the controller calls `borrow_into_controller(env, account, debt, debt_to_flash_loan, true, ...)` with `charge_fee` hard-coded to `true` [1](#0-0) . That reaches `pool.create_strategy`, whose accounting mints scaled debt for the full `action.amount` via `borrow::mint_debt`, then computes `fee = Bps(flashloan_fee).flash_loan_fee_on(amount)` and debits cash for only `amount - fee` [2](#0-1) . `flashloan_fee` lives in `MarketParams` and is replaced wholesale by `update_params` [3](#0-2) . No parameter in `MultiplyParams` lets the caller bound the fee or minimum proceeds [4](#0-3) .

For `Long`/`Short` modes the net proceeds flow through `swap_tokens`, where the route's min-out indirectly bounds the fee. But `PositionMode::Multiply` only requires `collateral != debt` as `HubAssetKey` — the same underlying asset in a different hub is allowed [5](#0-4) . In that case `swap_tokens_or_passthrough` passes the fee-reduced amount straight through with no min-out check, so the withheld fee directly becomes missing collateral while the recorded debt remains the full `amount`.

### Impact Explanation
A borrower who quoted a multiply at fee `f` can have the position executed at fee `f' > f` after a `update_params` change lands (including via governance execute of a ready operation). They owe the full `debt_to_flash_loan` while receiving `debt_to_flash_loan - f'`, and in the passthrough case the entire shortfall reduces deposited collateral, worsening their effective leverage/cost up to `MAX_FLASHLOAN_FEE_BPS` with no recourse — loss of expected user funds booked as protocol revenue [6](#0-5) .

### Likelihood Explanation
Requires the `flashloan_fee` to increase between the user's quote/simulation and execution. Fee updates are privileged, which lowers likelihood, but the class remains reachable by an unprivileged `multiply` caller with no on-chain bound, identical in shape to the referenced Medium finding.

### Recommendation
Add a `max_fee` or `min_amount_received` parameter to `multiply` (and propagate it into the `PoolAction`/strategy accounting), asserting `fee <= max_fee` (or `amount_received >= min_amount_received`) in `strategy::accounting` before committing.

### Proof of Concept
1. User quotes `multiply` on a Multiply-mode account with `collateral`/`debt` being the same asset in different hubs (passthrough swap), `debt_to_flash_loan = A`, current `flashloan_fee = f`.
2. `update_params` raises `flashloan_fee` to `f'`; the user's transaction executes afterward.
3. `create_strategy` mints debt for `A`, transfers `A - fee(f')` to the controller [7](#0-6) .
4. The passthrough supplies `A - fee(f')` as collateral; the account carries debt of `A`. The user pays `fee(f') - fee(f)` more than quoted with no way to have bounded it.

### Citations

**File:** contracts/controller/src/strategies/multiply.rs (L19-29)
```rust
pub(crate) struct MultiplyParams<'a> {
    pub account_id: u64,
    pub spoke_id: u32,
    pub collateral: &'a HubAssetKey,
    pub debt_to_flash_loan: i128,
    pub debt: &'a HubAssetKey,
    pub mode: PositionMode,
    pub swap: &'a StrategySwap,
    pub initial_payment: Option<(HubAssetKey, i128)>,
    pub convert_swap: Option<StrategySwap>,
}
```

**File:** contracts/controller/src/strategies/multiply.rs (L76-84)
```rust
    let amount_received = borrow_into_controller(
        env,
        &mut account,
        debt,
        debt_to_flash_loan,
        true,
        PositionAction::Multiply,
        &mut cache,
    );
```

**File:** contracts/controller/src/strategies/multiply.rs (L136-150)
```rust
    match mode {
        PositionMode::Multiply => {
            assert_with_error!(env, collateral != debt, GenericError::AssetsAreTheSame);
        }

        PositionMode::Long | PositionMode::Short => {
            assert_with_error!(
                env,
                collateral.asset != debt.asset,
                GenericError::AssetsAreTheSame
            );
        }
        _ => panic_with_error!(env, CollateralError::InvalidPositionMode),
    }
    require_positive_amount(env, debt_to_flash_loan);
```

**File:** contracts/pool/src/ops/strategy.rs (L58-79)
```rust
pub(crate) fn accounting(env: &Env, action: PoolAction, charge_fee: bool) -> StrategyOutcome {
    let PoolAction {
        position,
        amount,
        hub_asset,
    } = action;
    require_nonneg_amount(env, amount);

    let mut cache = ops::renewed_market(env, &hub_asset);
    let fee = compute_fee(env, &cache, amount, charge_fee);

    let mut position = Ray::from(position.scaled_amount);
    borrow::mint_debt(env, &mut cache, &mut position, amount);

    let protocol_fee = Ray::from_asset(env, fee, cache.params().asset_decimals);
    interest::add_protocol_revenue(&mut cache, protocol_fee);

    let amount_to_send = amount
        .checked_sub(fee)
        .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow));

    cache.debit_cash(amount_to_send);
```

**File:** contracts/pool/src/ops/strategy.rs (L94-101)
```rust
fn compute_fee(env: &Env, cache: &Cache, amount: i128, charge_fee: bool) -> i128 {
    if !charge_fee {
        return 0;
    }
    let fee = Bps::from(i128::from(cache.params().flashloan_fee)).flash_loan_fee_on(env, amount);
    assert_with_error!(env, fee <= amount, FlashLoanError::StrategyFeeExceeds);
    fee
}
```

**File:** contracts/controller/src/external/pool.rs (L159-166)
```rust
pub(crate) fn pool_update_params_call(
    env: &Env,
    pool_addr: &Address,
    hub_asset: &HubAssetKey,
    params: &InterestRateModel,
) {
    LiquidityPoolClient::new(env, pool_addr).update_params(hub_asset, params)
}
```
