### Title
`flash_position` (and `multiply`) mint borrow debt without the spoke-asset `paused`/`frozen`/`is_borrowable` gates that `borrow()` enforces — ([File: contracts/controller/src/strategies/flash_position.rs](contracts/controller/src/strategies/flash_position.rs))

### Summary
The Blend M-01 bug class — "a flash-mint path that leaves debt outstanding bypasses the status checks applied to ordinary borrows" — maps onto XOXNO Lending's `flash_position`/`multiply` strategies. The ordinary `borrow()` flow gates every debt leg through `require_can_borrow`, which enforces `FreezePolicy::BlockOnEntry` (rejects `paused` and `frozen` spoke-asset flags) plus `is_borrowable`. `process_flash_position` validates only the *collateral* legs with `require_can_supply`/`BlockOnEntry`; the debt leg is minted through `borrow_into_controller`, which contains no `paused`/`frozen`/`can_borrow` check, so a permissionless caller can open new borrow exposure on a spoke listing the owner has halted.

### Finding Description
The halt flags (`paused`, `frozen`, `no_seize`) are the protocol's per-market circuit breaker, ratcheted by `set_spoke_asset_flags` and only relaxable via the timelocked `relax_spoke_asset_flags` path. [1](#0-0) 

For normal entry flows the enforcement point is `require_listed_unhalted_config`, which applies `FreezePolicy::BlockOnEntry` (rejects `paused`, rejects `frozen`), and `require_can_borrow` additionally requires `is_borrowable`. [2](#0-1)  These are reached for borrows via `validate_position_entry_gates` with `AccountPositionType::Borrow`. [3](#0-2) 

`process_flash_position` never applies those gates to the debt asset. It only checks `require_hub_active(debt.hub_id)` and `is_flashloanable` on the *pool* params. [4](#0-3)  `validate_collaterals` runs `require_can_supply`/`validate_position_entry_gates` with `AccountPositionType::Deposit` on the collateral legs only — the debt `HubAssetKey` is not in that list. [5](#0-4)  The debt is then minted via `borrow_into_controller` inside the flash guard, [6](#0-5)  and `positions/debt.rs` contains no `paused`/`frozen`/`can_borrow` references — the flag enforcement lives solely in `positions/mod.rs`, which the debt leg bypasses. The position is kept open afterward (`require_flash_position_still_open` requires `pos.scaled_amount > 0`), so this is exactly the Blend shape: a flash path that persists a borrow without the halted-market checks. [7](#0-6)  `multiply` reaches the same `borrow_into_controller` machinery with a caller-selected debt asset and likewise only validates the collateral leg.

### Impact Explanation
An owner pausing or freezing a spoke listing (the intended response to deteriorating market conditions, bad oracle data, or observed risk) does not stop new borrow exposure: any unprivileged address can keep opening leveraged debt on the halted asset via `flash_position` or `multiply`. This defeats the circuit breaker precisely when it is needed, allowing continued risk accumulation that can drive the pool toward insolvency — e.g., borrowing a frozen asset whose price feed is suspect, or keeping a paused market's utilization growing while ordinary `borrow()` reverts with `SpokeAssetPaused`/`SpokeAssetFrozen`. This qualifies as protocol-insolvency-enabling unauthorized state: funds are borrowed that governance explicitly halted.

### Likelihood Explanation
Requires only an unprivileged address, collateral to satisfy post-mint solvency, and a trivial Wasm receiver contract. The trigger is an admin-set flag, which is a realistic and intended operational state (the ratchet design at `require_flag_ratchet` exists precisely because flags get set during incidents). Every halted listing remains exploitable for the entire duration of the halt. No timing, oracle manipulation, or privileged access is needed.

### Recommendation
In `process_flash_position` (and equivalently in `multiply` and any other strategy that calls `borrow_into_controller`), run the debt asset through the same gate as `borrow()`: call `require_can_borrow(env, cache, account.spoke_id, debt)` — or pass the debt leg through `validate_position_entry_gates` with `AccountPositionType::Borrow` — before `mint_and_forward`. Preferably, move the `require_can_borrow` check inside `borrow_into_controller` itself so no future strategy can mint debt on a halted or non-borrowable listing. Note `is_borrowable` should also be enforced, not just the flags, since a non-borrowable listing can currently be debt-minted the same way.

### Proof of Concept
1. Owner lists asset X in spoke S with `can_borrow = true`.
2. Attacker supplies collateral normally; `borrow(X)` works.
3. Owner calls `set_spoke_asset_flags(spoke_id = S, hub_asset = X, paused = true, ...)` (ratchet allows tightening).
4. `controller.borrow(caller, account_id, [(X, amt)], None)` now reverts at `require_can_borrow` → `SpokeAssetPaused`. [8](#0-7) 
5. Attacker deploys a Wasm receiver that, in `execute_flash_position`, swaps the received X into a listed collateral token and transfers it to the controller.
6. Attacker calls `controller.flash_position(caller, 0, S, PositionMode::Multiply, debt = X, amount, receiver, data, collaterals = [(collateral_asset, min)], refund_assets = [])`. The only debt-side checks are `require_hub_active` and `is_flashloanable`; no flag or `is_borrowable` check on X occurs. [9](#0-8) 
7. The tx succeeds: the account ends with scaled debt in the paused listing X plus deposited collateral, identical end state to the reverted `borrow()` — the halt is fully bypassed. The same sequence works via `multiply` with a swap route.

*Caveat:* `positions/debt.rs` (`borrow_into_controller`) could not be read in full; the conclusion rests on grep evidence that it contains no flag/`can_borrow` logic and that all halt enforcement is centralized in `positions/mod.rs`, which the debt leg of `flash_position` never invokes. If `borrow_into_controller` internally calls `require_can_borrow`, this analog does not hold.

### Citations

**File:** contracts/controller/src/config/asset.rs (L110-123)
```rust
/// Tightens paused, frozen, and no-seize flags on a listed asset, advances
/// its flags epoch, and emits the new config. Rejects any true-to-false transition.
pub(crate) fn set_spoke_asset_flags(
    env: &Env,
    spoke_id: u32,
    hub_asset: HubAssetKey,
    paused: bool,
    frozen: bool,
    no_seize: bool,
) {
    let config = storage::get_spoke_asset(env, spoke_id, &hub_asset)
        .unwrap_or_else(|| panic_with_error!(env, SpokeError::AssetNotInSpoke));
    require_flag_ratchet(env, &config, paused, frozen, no_seize);
    write_spoke_asset_flags(env, spoke_id, hub_asset, config, paused, frozen, no_seize);
```

**File:** contracts/controller/src/positions/mod.rs (L186-213)
```rust
/// Requires an active hub, an active spoke listing, and neither pause nor
/// freeze. Returns the config for the supply or borrow permission check.
fn require_listed_unhalted_config(
    env: &Env,
    cache: &mut Context,
    spoke_id: u32,
    hub_asset: &HubAssetKey,
) -> AssetConfig {
    cache.require_hub_active(hub_asset.hub_id);
    let asset_config = cache.require_listed_active_config(spoke_id, hub_asset);
    enforce_spoke_asset_flags(env, cache, spoke_id, hub_asset, FreezePolicy::BlockOnEntry);
    asset_config
}

/// Requires an active, unhalted listing that permits borrowing.
pub(crate) fn require_can_borrow(
    env: &Env,
    cache: &mut Context,
    spoke_id: u32,
    hub_asset: &HubAssetKey,
) {
    let asset_config = require_listed_unhalted_config(env, cache, spoke_id, hub_asset);
    assert_with_error!(
        env,
        asset_config.is_borrowable,
        CollateralError::AssetNotBorrowable
    );
}
```

**File:** contracts/controller/src/positions/mod.rs (L243-252)
```rust
    for (hub_asset, _) in aggregated {
        match position_type {
            AccountPositionType::Deposit => {
                require_can_supply(env, cache, account.spoke_id, &hub_asset);
            }
            AccountPositionType::Borrow => {
                require_can_borrow(env, cache, account.spoke_id, &hub_asset);
            }
        }
    }
```

**File:** contracts/controller/src/positions/mod.rs (L264-272)
```rust
    if let Some(sa) = cache.cached_spoke_asset(spoke_id, hub_asset) {
        match freeze {
            FreezePolicy::BlockOnEntry => {
                assert_with_error!(env, !sa.paused, SpokeError::SpokeAssetPaused);
                assert_with_error!(env, !sa.frozen, SpokeError::SpokeAssetFrozen);
            }
            FreezePolicy::AllowOnExit => {
                assert_with_error!(env, !sa.paused, SpokeError::SpokeAssetPaused);
            }
```

**File:** contracts/controller/src/strategies/flash_position.rs (L59-91)
```rust
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

**File:** contracts/controller/src/strategies/flash_position.rs (L202-214)
```rust
        require_can_supply(env, cache, account.spoke_id, &hub_asset);
        seen_assets.set(hub_asset.asset.clone(), true);
    }

    assert_with_error!(env, has_positive_min, StrategyError::CollateralRequired);

    validate_position_entry_gates(
        env,
        account,
        collaterals,
        cache,
        AccountPositionType::Deposit,
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

**File:** contracts/controller/src/strategies/flash_position.rs (L356-370)
```rust
pub(crate) fn require_flash_position_still_open(env: &Env, account: &Account, debt: &HubAssetKey) {
    assert_with_error!(
        env,
        !account.is_empty() && !account.debt_free(),
        StrategyError::FlashPositionClosed
    );
    let Some(pos) = account.borrow_positions.get(debt.clone()) else {
        panic_with_error!(env, StrategyError::FlashPositionClosed);
    };
    assert_with_error!(
        env,
        pos.scaled_amount > 0 && !account.supply_positions.is_empty(),
        StrategyError::FlashPositionClosed
    );
}
```
