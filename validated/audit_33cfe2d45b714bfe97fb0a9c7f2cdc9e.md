### Title
Tokens transferred to the controller are permanently frozen — undeclared `flash_position` pushes and stray transfers have no recovery path - (contracts/controller/src/payments.rs)

### Summary
The Hubble analog maps to XOXNO Lending as follows: instead of an insurance fund whose unsold collateral can only move when a new auction starts, the controller contract can hold token balances that no code path can ever release. In Hubble the assets were stuck *until the next bad-debt event*; here they are stuck *permanently*, because the only refund mechanism explicitly preserves the pre-existing controller balance and no sweep/admin endpoint exists.

### Finding Description
`flash_position` is a permissionless entrypoint (`caller.require_auth()` only) that invokes a user-supplied Wasm receiver callback. During the callback, the receiver pushes tokens to the controller. After the callback, the controller:

1. deposits only the measured deltas of **declared** collateral assets via `collect_collateral_deposits` + `process_deposit` [1](#0-0) ;
2. refunds only the measured deltas of **declared** `refund_assets` via `refund_listed_assets` [2](#0-1) .

Any other token balance sitting on the controller is untouched. Crucially, `refund_controller_balance_delta` only refunds the delta above the *pre-callback* baseline [3](#0-2) , so tokens already stuck on the controller cannot be recovered even by a later `flash_position` that declares the asset as a refund — the baseline guard deliberately preserves them. There is no other endpoint that moves controller-held tokens: the docs state "Undeclared callback assets receive neither credit nor refunds. There is no controller sweep endpoint" [4](#0-3) . The integration tests even seed the controller with "donated" balances and assert they remain unchanged after a refund run, confirming this is enforced behavior rather than an accident [5](#0-4) .

Reachable by a single unprivileged address via:
- `flash_position(caller, account_id, spoke_id, mode, debt, amount, receiver, data, collaterals, refund_assets)` where `receiver` is the caller's own Wasm contract that transfers an undeclared (or mis-declared) token to the controller, or
- a plain `token.transfer(user, controller, amount)` — direct transfers to the controller are an accepted interaction path.

### Impact Explanation
Permanent freezing of funds. Tokens that end up on the controller outside a declared collateral/refund delta are unrecoverable by any caller, including their original owner and governance — the baseline guard in `refund_controller_balance_delta` actively shields the stuck balance from the only flow that ever transfers tokens out of the controller. Unlike the Hubble case, there is no future event (no auction restart, no sweep) that can release them.

### Likelihood Explanation
Low-to-moderate likelihood, permanent impact. Loss requires a token to reach the controller without a matching declaration: a receiver contract that pushes the wrong asset or forgets a `refund_assets` entry (the refund list is validated only for uniqueness, listing, and disjointness from collaterals — not for completeness [6](#0-5) ), or any stray/accidental direct transfer. The stuck amount is unbounded and grows with every such occurrence.

### Recommendation
Add a recovery path for orphaned controller balances, e.g. a governance-execute `sweep(asset, to)` operation on the Sensitive delay tier that transfers the controller's full token balance to a configured address, or allow `refund_assets` to declare-and-sweep pre-existing balances rather than only deltas. Alternatively, treat a nonzero undeclared delta on a listed asset as an automatic refund to `caller` instead of silently retaining it.

### Proof of Concept
1. Alice deploys a flash receiver whose `execute_flash_position` callback buys the declared collateral (XLM), transfers it to the controller, and also transfers 1,000 USDC to the controller.
2. Alice calls `flash_position` with `collaterals = [(hub, XLM), min]` and `refund_assets = []` (or omits USDC by mistake).
3. The call succeeds: XLM delta is deposited, and because USDC is undeclared, `refund_listed_assets` iterates an empty list and returns nothing for it.
4. The 1,000 USDC now sits on the controller. A second `flash_position` with `refund_assets = [USDC]` still refunds only the *delta since that call's baseline* — the stuck 1,000 USDC is below the new baseline and stays frozen. No other endpoint (supply/borrow/liquidate/claim_revenue/recapitalize or any admin operation) transfers tokens out of the controller's own balance.

### Citations

**File:** contracts/controller/src/strategies/flash_position.rs (L145-148)
```rust
    let deposits = collect_collateral_deposits(env, &controller, collaterals, &collateral_before);
    process_deposit(env, &controller, &mut account, &deposits, &mut cache);

    refund_listed_assets(env, caller, refund_assets, &refund_before);
```

**File:** contracts/controller/src/strategies/flash_position.rs (L217-256)
```rust
fn validate_refund_assets(
    env: &Env,
    cache: &mut Context,
    spoke_id: u32,
    hub_id: u32,
    collaterals: &Vec<(HubAssetKey, i128)>,
    refund_assets: &Vec<Address>,
) {
    let limits = storage::get_position_limits(env);
    assert_with_error!(
        env,
        refund_assets.len() <= limits.max_supply_positions,
        GenericError::InvalidPayments
    );

    let mut seen: Map<Address, bool> = Map::new(env);
    for asset in refund_assets.iter() {
        assert_with_error!(
            env,
            !seen.contains_key(asset.clone()),
            GenericError::InvalidPayments
        );
        seen.set(asset.clone(), true);
        // Refund transfers run after the guard; restrict tokens to listed assets.
        cache.require_listed_active_config(
            spoke_id,
            &HubAssetKey {
                hub_id,
                asset: asset.clone(),
            },
        );
        for (collateral, _) in collaterals.iter() {
            assert_with_error!(
                env,
                asset != collateral.asset,
                GenericError::InvalidPayments
            );
        }
    }
}
```

**File:** contracts/controller/src/strategies/flash_position.rs (L372-384)
```rust
fn refund_listed_assets(
    env: &Env,
    caller: &Address,
    refund_assets: &Vec<Address>,
    before: &Map<Address, i128>,
) {
    for asset in refund_assets.iter() {
        let baseline = before
            .get(asset.clone())
            .unwrap_or_else(|| panic_with_error!(env, GenericError::InternalError));
        refund_controller_balance_delta(env, &asset, baseline, caller);
    }
}
```

**File:** contracts/controller/src/payments.rs (L39-52)
```rust
/// Refunds only the controller balance increase since `balance_before`,
/// preserving the pre-existing balance; no-op for a nonpositive delta.
pub(crate) fn refund_controller_balance_delta(
    env: &Env,
    asset: &Address,
    balance_before: i128,
    refund_to: &Address,
) {
    let controller = env.current_contract_address();
    let excess = balance_delta_since(env, asset, &controller, balance_before);
    if excess > 0 {
        token::Client::new(env, asset).transfer(&controller, refund_to, &excess);
    }
}
```

**File:** docs/reference/endpoints.md (L84-86)
```markdown
Refund assets must be unique, listed in the debt hub and account spoke, disjoint from collateral declarations, and bounded by the maximum supply-position count. Refund eligibility requires an active spoke and an existing listing; it does not check collateralizable, borrowable, paused or frozen flags. Only positive balance changes above pre-callback balances return to the caller. The debt token can be a refund asset, but refunding it does not repay the minted debt.

Undeclared callback assets receive neither credit nor refunds. There is no controller sweep endpoint. Refunds produce token transfer events, without a dedicated controller refund event.
```

**File:** tests/integration/flows/flash_position.sh (L357-372)
```shellscript
    sac_transfer "$ALICE" "$USDC_SAC" "$ALICE_ADDR" "$CONTROLLER" 37 fp_protected_usdc_seed || return 1
    sac_transfer "$ALICE" "$XLM_SAC" "$ALICE_ADDR" "$CONTROLLER" 41 fp_protected_xlm_seed || return 1
    controller_usdc_pre=$(balance "$USDC_SAC" "$CONTROLLER") || return 1
    controller_xlm_pre=$(balance "$XLM_SAC" "$CONTROLLER") || return 1
    _uint_ge "$controller_usdc_pre" 37 && _uint_ge "$controller_xlm_pre" 41 \
        || { _assert_fail fp_protected_nonzero "controller baselines must contain donated funds"; return 1; }
    alice_usdc_pre=$(balance "$USDC_SAC" "$ALICE_ADDR") || return 1
    FP_COLS="$(fp_collaterals "$FP_EXTEND_COLLATERAL")"
    FP_REFUNDS="$(fp_refunds "$USDC_SAC")"
    fp_set_plan fp_plan_refund_extra "$FP_MODE_SUCCESS" "$FP_EXTEND_COLLATERAL" \
        "$USDC_SAC" "$extra_usdc" || return 1
    fp_run inv flash_position_refund_undeclared "" || return 1
    alice_usdc_post=$(balance "$USDC_SAC" "$ALICE_ADDR")
    assert_delta refund_exact "$alice_usdc_pre" "$alice_usdc_post" 10000000 || return 1
    assert_delta refund_protected "$controller_usdc_pre" "$(balance "$USDC_SAC" "$CONTROLLER")" 0 || return 1
    assert_delta fp_protected_collateral "$controller_xlm_pre" "$(balance "$XLM_SAC" "$CONTROLLER")" 0 || return 1
```
