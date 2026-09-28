### Title
`flash_position` mints debt without spoke-level borrow gates, bypassing pause/freeze/`is_borrowable`/delisting restrictions on new borrowing — (File: contracts/controller/src/strategies/flash_position.rs)

### Summary
The controller enforces spoke-level restrictions on *new* borrowing — `paused`, `frozen`, missing/delisted listing, and `is_borrowable = false` — only through `require_can_borrow` / `FreezePolicy::BlockOnEntry`, which `validate_position_entry_gates` applies to the plain `borrow` flow. The `flash_position` strategy mints fee-free debt via `borrow_into_controller` without ever invoking these checks on the `debt` leg, so an unprivileged caller can open new debt in a market where governance has explicitly halted or disabled borrowing — the same bug class as a renewal path that verifies "a prior position exists" but skips the restriction that applies to the new exposure.

### Finding Description
- `process_borrow` enforces the full gate set: `validate_position_entry_gates` → `require_can_borrow` → `require_listed_unhalted_config` (hub active, listed active spoke config) plus `FreezePolicy::BlockOnEntry` (rejects `paused` and `frozen`) and `is_borrowable`. [1](#0-0) [2](#0-1) [3](#0-2) 
- `process_flash_position` checks only `require_hub_active(debt.hub_id)` and the pool flag `is_flashloanable` on the debt asset — never `require_can_borrow`, never `enforce_spoke_asset_flags(.., BlockOnEntry)` on `debt`, and no `is_borrowable` check. The only spoke-level gates applied are `require_can_supply`/`validate_position_entry_gates(.., Deposit)` on the *collateral* legs. [4](#0-3) [5](#0-4) 
- The debt mint goes through `mint_and_forward` → `borrow_into_controller`, which is defined in `debt.rs`; `require_can_borrow` has no call sites outside `positions/mod.rs` (grep over `contracts/controller/src`), so the strategy path cannot inherit the flag checks. Spoke *caps* are still enforced via the entry usage path (`LegDirection::Entry` → `apply_spoke_entry`; integration test `flash_position_borrow_cap_gap` expects `SpokeBorrowCapReached` #312), but caps and listing/pause/borrowable flags are enforced by different code. [6](#0-5) [7](#0-6) 
- Additionally, `enforce_spoke_asset_flags` and cap enforcement are no-ops when the spoke-asset row is absent (`if let Some(sa) = cached_spoke_asset(..)`), so a debt asset that was never listed or was delisted from the spoke likely skips even the cap check while `borrow` would have reverted at `require_listed_active_config`. [8](#0-7) 

Caveat: `borrow_into_controller`'s internals were not fully read; if it internally re-checks spoke-asset flags, the finding narrows to the delisted/missing-row case. No test or code path shows `paused`/`frozen`/`is_borrowable` being applied to the `flash_position` debt leg, and the integration suite exercises cap gaps (#312) but never a paused or non-borrowable debt leg for `flash_position`.

### Impact Explanation
Spoke `paused`/`frozen`/`is_borrowable` flags and delisting are the protocol's mechanism to stop *new* exposure in a risky or compromised market while still allowing exits and liquidation. A single unprivileged caller with a callback contract (or the configured router for `Multiply` mode) can keep minting debt — and drawing pool cash — in exactly the markets governance tried to close. If a market is paused because its price feed, liquidity, or collateral quality is suspect, the attacker accumulates debt that liquidation/risk settings assumed could not grow, producing protocol insolvency or bad debt borne by suppliers (theft of user funds via socialized write-down). Severity: High if the debt asset can be entirely unlisted (cap skipped → up to pool liquidity); otherwise Medium.

### Likelihood Explanation
Fully permissionless: `flash_position` requires only `require_authorized_caller` on the caller and a WASM receiver contract the caller controls (or `Multiply` mode using the configured router). Preconditions are a hub that is still active at hub level, the pool flag `is_flashloanable` still set, and any listed collateral to satisfy `require_can_supply` + post-action health gates — all common. It becomes exploitable the moment governance pauses/freezes an asset or clears `is_borrowable` to stop new borrowing, which is precisely the scenario those flags exist for.

### Recommendation
Apply `require_can_borrow(env, cache, spoke_id, debt)` (or equivalently `require_listed_active_config` + `FreezePolicy::BlockOnEntry` + `is_borrowable`) to the `debt` leg in `process_flash_position` before `mint_and_forward`, and audit every other debt-minting strategy path (`multiply`, `swap_debt`, `migrate_from_blend`) for the same omission. Make cap enforcement fail-closed for missing spoke-asset rows on entry.

### Proof of Concept
1. Admin sets spoke asset `(spoke, USDC)` `paused = true` (or `is_borrowable = false`, or removes the listing). `borrow` on USDC now reverts with `SpokeAssetPaused` / `AssetNotBorrowable` / listing error.
2. Attacker calls `flash_position` with `debt = (hub, USDC)`, `amount` up to pool liquidity, `mode = Multiply`, and `collaterals = [(XLM, min)]` — a listed, unpaused collateral asset. The call passes `require_hub_active`, `is_flashloanable`, and the collateral-side `require_can_supply` gates.
3. `mint_and_forward` mints USDC debt to the account and forwards the cash to the receiver; the receiver swaps it to XLM and returns it, which is deposited as collateral. Final solvency gates pass since the account is overcollateralized.
4. Result: a fresh USDC borrow exists despite the spoke-level halt — the "no new borrows" rule is bypassed through the strategy entrypoint, exactly as the reference renewal path bypassed the new-protection window.

Note: `borrow_into_controller` internals were not fully verified; if it applies spoke flags itself, the residual issue is the missing-listing case where `cached_spoke_asset` returns `None` and entry gates silently skip.

### Citations

**File:** contracts/controller/src/positions/debt.rs (L50-57)
```rust
    validate_position_entry_gates(
        env,
        &account,
        &aggregated,
        &mut cache,
        AccountPositionType::Borrow,
    );
    settle_borrow(env, &mut account, &recipient, &aggregated, &mut cache);
```

**File:** contracts/controller/src/positions/mod.rs (L99-127)
```rust
/// Applies the scaled position delta to spoke usage; entries enforce caps
/// using the leg's market index and asset decimals.
pub(crate) fn apply_leg_usage(
    env: &Env,
    cache: &mut Context,
    spoke_id: u32,
    side: UsageSide,
    hub_asset: &HubAssetKey,
    direction: LegDirection,
    old_scaled: Ray,
    outcome: &LegOutcome,
) {
    match direction {
        LegDirection::Entry { asset_decimals } => cache.apply_spoke_entry(
            spoke_id,
            side,
            hub_asset,
            outcome.new_scaled.checked_sub(env, old_scaled),
            &outcome.market_index,
            asset_decimals,
        ),
        LegDirection::Exit => cache.apply_spoke_exit(
            spoke_id,
            side,
            hub_asset,
            old_scaled.checked_sub(env, outcome.new_scaled),
        ),
    }
}
```

**File:** contracts/controller/src/positions/mod.rs (L188-213)
```rust
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

**File:** contracts/controller/src/positions/mod.rs (L257-278)
```rust
pub(crate) fn enforce_spoke_asset_flags(
    env: &Env,
    cache: &mut Context,
    spoke_id: u32,
    hub_asset: &HubAssetKey,
    freeze: FreezePolicy,
) {
    if let Some(sa) = cache.cached_spoke_asset(spoke_id, hub_asset) {
        match freeze {
            FreezePolicy::BlockOnEntry => {
                assert_with_error!(env, !sa.paused, SpokeError::SpokeAssetPaused);
                assert_with_error!(env, !sa.frozen, SpokeError::SpokeAssetFrozen);
            }
            FreezePolicy::AllowOnExit => {
                assert_with_error!(env, !sa.paused, SpokeError::SpokeAssetPaused);
            }
            FreezePolicy::SeizureLeg => {
                assert_with_error!(env, !sa.no_seize, SpokeError::SpokeAssetSeizureHalted);
            }
        }
    }
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

**File:** contracts/controller/src/strategies/flash_position.rs (L199-214)
```rust
        if min_amount > 0 {
            has_positive_min = true;
        }
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

**File:** contracts/controller/src/strategies/flash_position.rs (L260-295)
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

    let forwarded = transfer_amount_measured(
        env,
        &debt.asset,
        &controller,
        receiver,
        measured,
        GenericError::AmountMustBePositive,
    );
    assert_with_error!(env, forwarded > 0, GenericError::AmountMustBePositive);
    forwarded
}
```
