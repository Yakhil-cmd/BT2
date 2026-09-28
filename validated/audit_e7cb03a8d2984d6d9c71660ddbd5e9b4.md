### Title
`flash_position` mints fee-free strategy debt, letting any user bypass the origination fee charged to `multiply`/`swap_debt` and permanently draining protocol revenue - (File: contracts/controller/src/strategies/flash_position.rs)

### Summary
The pool's `create_strategy` mints debt and, when `charge_fee = true`, withholds `flashloan_fee` bps as protocol revenue. The controller passes `charge_fee = true` for `multiply` and `swap_debt`, but `flash_position` calls the identical debt-minting path with `charge_fee = false`. Any unprivileged user can therefore open the same leveraged position through `flash_position` (via their own receiver contract) and pay zero origination fee — an inconsistent application of the same fee to economically identical operations, the direct analog of the Osmosis "taker fee non-determinism" bug class.

### Finding Description
`borrow_into_controller` forwards its `charge_fee` flag to `pool_create_strategy_call`. [1](#0-0)  In `multiply`/`swap_debt` the flag is `true`, so the pool books `fee = half_up(amount * flashloan_fee / 10_000)` (min 1) into `revenue`/`supplied` shares. [2](#0-1)  `flash_position::mint_and_forward` instead calls `borrow_into_controller(..., false, ...)` — fee-free debt for the same leverage primitive. [3](#0-2) 

Nothing gates this: `process_flash_position` only requires a caller-owned account, a WASM receiver that is not the controller or pool, and `is_flashloanable` on the debt market. [4](#0-3)  A trivial receiver contract that buys the collateral on a DEX and returns it reproduces `multiply` exactly. The harness test `flash_position_substitutes_multiply_without_origination_fee` proves parity of debt with `fp_revenue == 0` vs `mul_revenue == fee`. [5](#0-4) 

### Impact Explanation
Theft of unclaimed yield: every leveraged position opened via `flash_position` instead of `multiply`/`swap_debt` avoids paying `flashloan_fee` bps of principal to protocol revenue. At the configured 9–100 bps this is a direct, repeatable revenue loss borne by the `accumulator`/protocol. The user's own economics are unchanged-or-better, so rational flow migrates to the fee-free path.

### Likelihood Explanation
Fully permissionless — `flash_position` is a public controller entrypoint and the attacker controls `receiver`, `data`, `collaterals`, and `amount`. No timing, oracle, or privileged dependency; the bypass works on every leverage transaction where a DEX route exists.

### Recommendation
Apply the strategy fee symmetrically: pass `charge_fee = true` in `mint_and_forward`, or charge the fee on debt minted inside `flash_position` regardless of flag. If fee-free flash positions are intended, restrict `flash_position` to approved receivers or document the waiver as a deliberate, risk-accepted design decision.

### Proof of Concept
1. Attacker deploys a receiver contract that, on `execute_flash_position`, swaps the forwarded debt asset on Aquarius/Soroswap for the collateral asset and transfers it back to the controller.
2. Calls `controller.flash_position(account_id=0, spoke_id, mode=Multiply, debt=(hub, debtAsset), amount=X, receiver, data, collaterals=[(collateralKey, min)], refund_assets=[])`.
3. `borrow_into_controller` mints `X` of debt with `charge_fee=false`; the position holds the swapped collateral; `revenue` increases by `0`.
4. Compare with `multiply` on identical inputs: identical debt, but `revenue` increases by `half_up(X * flashloan_fee_bps / 10_000)` and the user's collateral is smaller by that fee — as pinned by `strategy_origination_fee_parity.rs`.

### Citations

**File:** contracts/controller/src/positions/debt.rs (L260-287)
```rust
pub(crate) fn borrow_into_controller(
    env: &Env,
    account: &mut Account,
    hub_debt: &HubAssetKey,
    amount: i128,
    charge_fee: bool,
    action: events::PositionAction,
    cache: &mut Context,
) -> i128 {
    require_positive_amount(env, amount);
    let aggregated = vec![env, (hub_debt.clone(), amount)];
    validate_position_entry_gates(
        env,
        account,
        &aggregated,
        cache,
        AccountPositionType::Borrow,
    );

    let position = account.get_or_create_debt_position(hub_debt);
    let pool_addr = cache.cached_pool_address();
    let pool_action = make_pool_action(&position, amount, hub_debt.clone());
    let controller = env.current_contract_address();
    let before = token::Client::new(env, &hub_debt.asset).balance(&controller);
    // Block token-hook reentry during funding, before the strategy swap guard.
    let result = storage::with_flash_guard(env, || {
        pool_create_strategy_call(env, &pool_addr, &controller, pool_action, charge_fee)
    });
```

**File:** certora/pool/spec/flash_loan_accounting_rules.rs (L146-170)
```rust
    let rounded_fee = fp_core::mul_div_half_up(&e, amount, i128::from(fee_bps), BPS);
    let configured_fee = if fee_bps > 0 && rounded_fee == 0 {
        1
    } else {
        rounded_fee
    };
    cvlr_assert!(terms.fee == configured_fee);
    cvlr_assert!(terms.total_repayment == amount + terms.fee);
    cvlr_assert!(terms.balance_after_payout == pre_balance - amount);
    cvlr_assert!(terms.balance_after_repayment == pre_balance + terms.fee);

    let expected_shares = expected_protocol_fee_shares(
        &e,
        Ray::from_asset(&e, terms.fee, ASSET_DECIMALS),
        Ray::from(supply_index),
        Ray::from(pre.supplied),
    );

    crate::ops::flash::book_fee(&mut cache, terms.fee);
    cache.commit();
    let post = read_state(&e, &asset);

    cvlr_assert!(post.cash - pre.cash == terms.fee);
    cvlr_assert!(post.revenue - pre.revenue == expected_shares.raw());
    cvlr_assert!(post.supplied - pre.supplied == expected_shares.raw());
```

**File:** contracts/controller/src/strategies/flash_position.rs (L40-91)
```rust
pub(crate) fn process_flash_position(
    env: &Env,
    caller: &Address,
    params: FlashPositionParams<'_>,
) -> u64 {
    require_authorized_caller(env, caller);

    let FlashPositionParams {
        account_id,
        spoke_id,
        mode,
        debt,
        amount,
        receiver,
        data,
        collaterals,
        refund_assets,
    } = params;

    require_positive_amount(env, amount);
    config::require_hub_active(env, debt.hub_id);
    assert_with_error!(
        env,
        matches!(
            mode,
            PositionMode::Multiply | PositionMode::Long | PositionMode::Short
        ),
        CollateralError::InvalidPositionMode
    );
    require_wasm_receiver(env, receiver);

    let controller = env.current_contract_address();
    assert_with_error!(
        env,
        *receiver != controller,
        FlashLoanError::InvalidFlashloanReceiver
    );

    let mut cache = Context::new(env);
    let pool_addr = cache.cached_pool_address();
    assert_with_error!(
        env,
        *receiver != pool_addr,
        FlashLoanError::InvalidFlashloanReceiver
    );
    // Caller-selected receivers require flash loans enabled; multiply uses
    // the configured router and does not require this flag.
    assert_with_error!(
        env,
        cache.cached_pool_sync_data(debt).params.is_flashloanable,
        FlashLoanError::FlashloanNotEnabled
    );
```

**File:** contracts/controller/src/strategies/flash_position.rs (L260-283)
```rust
fn mint_and_forward(
    env: &Env,
    account: &mut Account,
    debt: &HubAssetKey,
    amount: i128,
    receiver: &Address,
    cache: &mut Context,
) -> i128 {
    let controller = env.current_contract_address();
    let before = token::Client::new(env, &debt.asset).balance(&controller);

    let reported = borrow_into_controller(
        env,
        account,
        debt,
        amount,
        false,
        PositionAction::FlashPos,
        cache,
    );

    let measured = balance_delta_since(env, &debt.asset, &controller, before);
    assert_with_error!(env, measured == reported, GenericError::InternalError);
    assert_with_error!(env, measured > 0, GenericError::AmountMustBePositive);
```

**File:** tests/test-harness/tests/strategy_origination_fee_parity.rs (L97-129)
```rust
fn flash_position_substitutes_multiply_without_origination_fee() {
    let (mul_collateral, mul_debt, mul_revenue) = open_via_multiply();
    let (fp_collateral, fp_debt, fp_revenue) = open_via_flash_position();

    std::println!("multiply       : collateral={mul_collateral:.4} USDC  debt={mul_debt:.6} ETH  revenue={mul_revenue}");
    std::println!("flash_position : collateral={fp_collateral:.4} USDC  debt={fp_debt:.6} ETH  revenue={fp_revenue}");

    // Same debt taken on both routes.
    assert!(
        (mul_debt - fp_debt).abs() < 0.01,
        "routes should take comparable debt: multiply={mul_debt} flash_position={fp_debt}"
    );

    // `multiply` books exactly the fee on 1.0 ETH of strategy debt at
    // `DEFAULT_FLASHLOAN_FEE_BPS`; `flash_position` books nothing.
    let strategy_debt_raw = 10_000_000i128;
    let expected_fee = strategy_debt_raw - apply_flash_fee(strategy_debt_raw);
    assert_eq!(
        mul_revenue, expected_fee,
        "multiply must book exactly the origination fee on {strategy_debt_raw} \
         raw ETH of debt: expected {expected_fee}, got {mul_revenue}"
    );
    assert_eq!(
        fp_revenue, 0,
        "flash_position books no protocol revenue, got {fp_revenue}"
    );

    // The fee-free route ends with more collateral for the same debt.
    assert!(
        fp_collateral > mul_collateral,
        "flash_position should yield more collateral for the same debt: \
         multiply={mul_collateral} flash_position={fp_collateral}"
    );
```
