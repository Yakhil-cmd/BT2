### Title
Tokens pushed to the controller during `flash_position` that are neither declared collateral nor refund-listed are permanently locked — no recovery mechanism (contracts/controller/src/strategies/flash_position.rs)

### Summary
The controller's `flash_position` entrypoint accepts arbitrary token transfers into the controller address from the caller's flash receiver during the callback. The post-callback settlement only handles two categories: assets declared in `collaterals` are measured and deposited, and assets listed in `refund_assets` have their positive balance delta returned to the caller. Any token transferred to the controller that appears in neither list is stranded: there is no sweep, rescue, or recovery entrypoint anywhere in the controller or pool ABI. This mirrors the Debita `incentivizePair` flaw — tokens enter contract custody on the caller's own action with no path back out once the transaction succeeds.

### Finding Description
In `flash_position`, after the receiver callback returns, settlement runs exactly two passes:

- `collect_collateral_deposits` + `process_deposit` — only iterates the declared `collaterals` list and deposits their measured deltas. [1](#0-0) 
- `refund_listed_assets` — only iterates the caller-supplied `refund_assets` vector and returns positive deltas to `caller`. [2](#0-1) 

The protocol's own invariant documents the hole: "Returned debt becomes collateral if declared, returns to the caller if refund-listed, or remains uncredited if in neither list." [3](#0-2)  The endpoint reference confirms "Undeclared callback assets receive neither credit nor refunds. There is no controller sweep endpoint." [4](#0-3)  The pool surface likewise contains no sweep or rescue entrypoint — every `in` leg is credited against `cash` bookkeeping and every `out` leg is a fixed protocol transfer. [5](#0-4) 

The same applies to direct token transfers to the controller or pool outside any entrypoint: donations "do not rewrite those books," and nothing transfers them back out. [6](#0-5) 

The reachable path for a single unprivileged address:

1. Deploy a receiver implementing `execute_flash_position`.
2. Call `controller.flash_position(caller, 0, spoke_id, Multiply, debt_hub_asset, amount, receiver, data, collaterals = [(XLM_market, min)], refund_assets = [])`.
3. In the callback, transfer the declared XLM collateral **plus** an extra transfer of an undeclared token (e.g. USDC, or any SAC/wrapped asset including tokens not listed in any hub) to the controller.
4. Transaction succeeds — the declared minimum is met, solvency passes — and the undeclared tokens remain on the controller balance with zero credit, zero refund, and no withdrawal path.

The harness test `test_flash_position_refunds_undeclared_push` proves the asymmetric behavior: the identical undeclared push is returned only because it was listed in `refund_assets`; absent the listing it stays locked. [7](#0-6) 

### Impact Explanation
Permanent freezing of funds. Any token amount delivered to the controller that is not declared in `collaterals` and not listed in `refund_assets` is locked forever — uncredited to any account, unrefundable, and unsweepable. Because the lock is on the controller (shared custody for all hubs and spokes), the stranded balance also sits permanently below measured deltas: later callbacks record baselines over it and can never touch it. [8](#0-7)  Severity is Medium: the loss requires the caller's own receiver to push the tokens (self-inflicted, like the Debita incentive creator), but the loss is total and unrecoverable, and a buggy or generically-written receiver contract — e.g. one that sweeps its full token balances to the `controller` callback argument — loses everything not explicitly declared.

### Likelihood Explanation
Moderate. The callback interface hands the receiver a `controller` address and expects it to push collateral via plain `token::transfer`; a receiver that pushes multi-asset swap output, dust from several venues, or simply mis-declares the `collaterals`/`refund_assets` lists (which must be disjoint and capped at `max_supply_positions`) strands the excess on every call. The 5-asset refund cap and the uniqueness/listing constraints make it easy to under-declare. [9](#0-8)  No external market condition is needed — the lock is deterministic once the transaction commits.

### Recommendation
Add a recovery path for stranded controller balances, analogous to the missing incentive withdrawal in DebitaIncentives:

- Sweep extra undeclared positive callback deltas into the caller as refunds by default (refund every asset whose delta grew, not only listed ones), or
- Add a permissionless `sweep(asset, to)`/`rescue` entrypoint restricted to balances exceeding tracked obligations, or at minimum an admin/accumulator-gated rescue for assets with no bookkeeping claim.
- If keeping the current design, revert when the callback leaves a positive delta in any undeclared, unlisted asset rather than silently locking it.

### Proof of Concept
```rust
// Receiver callback (simplified): pushes declared XLM collateral AND an
// undeclared USDC amount to the controller.
fn execute_flash_position(env, initiator, account_id, asset, amount, fee,
                          amount_received, controller, data) {
    let me = env.current_contract_address();
    // declared collateral — credited
    token::Client::new(&env, &XLM).transfer(&me, &controller, &xlm_out);
    // undeclared asset — stranded forever
    token::Client::new(&env, &USDC).transfer(&me, &controller, &1_000_000);
}
```
```rust
// Caller: refund_assets does NOT include USDC.
controller.flash_position(
    &caller, &0, &spoke_id, &PositionMode::Multiply,
    &debt_hub_asset, &borrow_amount, &receiver, &data,
    &vec![&env, (xlm_hub_asset, min_xlm)],   // collaterals
    &Vec::<Address>::new(&env),            // refund_assets: empty
);
// Transaction succeeds (min met, HF >= 1). USDC sits on the controller
// balance with no credit, no refund, and no endpoint that can move it —
// identical to test_flash_position_refunds_undeclared_push minus the
// refund listing.
```

### Citations

**File:** contracts/controller/src/strategies/flash_position.rs (L145-146)
```rust
    let deposits = collect_collateral_deposits(env, &controller, collaterals, &collateral_before);
    process_deposit(env, &controller, &mut account, &deposits, &mut cache);
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

**File:** docs/reference/invariants.md (L686-689)
```markdown
scaled debt and the account must retain supply. Returned debt becomes
collateral if declared, returns to the caller if refund-listed, or remains
uncredited if in neither list. Refunds cover only positive callback balance
changes.
```

**File:** docs/reference/endpoints.md (L75-86)
```markdown
`flash_position` requires a debt market with flash loans enabled and a deployed Wasm receiver other than the controller or pool. Its collateral declarations must meet all of these conditions:

- The list is nonempty and does not exceed the maximum supply-position count.
- Markets and underlying tokens are unique.
- All minimum amounts are nonnegative, with at least one positive minimum.
- Measured controller receipts from the callback meet every minimum.

Pool supply measures receipts again. Borrow and supply caps are checked when each pool result merges into the account. Supply and the declared debt position must remain open after finalization.

Refund assets must be unique, listed in the debt hub and account spoke, disjoint from collateral declarations, and bounded by the maximum supply-position count. Refund eligibility requires an active spoke and an existing listing; it does not check collateralizable, borrowable, paused or frozen flags. Only positive balance changes above pre-callback balances return to the caller. The debt token can be a refund asset, but refunding it does not repay the minted debt.

Undeclared callback assets receive neither credit nor refunds. There is no controller sweep endpoint. Refunds produce token transfer events, without a dedicated controller refund event.
```

**File:** contracts/pool/README.md (L67-82)
```markdown
| Entrypoint | Role | Tokens |
| --- | --- | --- |
| `create_market` | Verify params, write state, indexes at `RAY` | — |
| `update_params` | Accrue on the **old** curve, then replace the rate model | — |
| `update_indexes` | Accrue each market in the vec; commit only if time elapsed | — |
| `supply` | Mint supply shares, credit cash | in |
| `borrow` | Mint debt shares, debit cash, transfer | out |
| `withdraw` | Burn supply shares, withhold liquidation fee, transfer net | out |
| `repay` | Burn debt shares, credit net, refund overpayment | in/out |
| `net_settle` | Offset a user's own supply against their own debt | — |
| `seize_positions` | Bad-debt write-down, or deposit → revenue | — |
| `claim_revenue` | Burn revenue shares, transfer to owner | out |
| `recapitalize` | Credit cash up to the backing shortfall, refund excess | in/out |
| `flash_loan` | Payout → callback → collect principal + fee | out/in |
| `create_strategy` | Borrow for a strategy, net of fee | out |
| `upgrade` | Replace contract Wasm | — |
```

**File:** docs/explanation/threat-model.md (L129-132)
```markdown
One token listed in several hubs shares physical pool custody even though
market books are separate. Direct donations do not rewrite those books.
Cash flash loans impose exact balance transitions and allowance repayment;
receipt-tax compatibility elsewhere does not establish flash-loan compatibility.
```

**File:** tests/test-harness/tests/strategy/flash_position.rs (L236-267)
```rust
#[test]
fn test_flash_position_refunds_undeclared_push() {
    let mut t = setup();
    let receiver = t.deploy_flash_position_receiver();
    let extra = t.resolve_asset("ETH");
    let extra_amount = f64_to_i128(0.5, t.resolve_market("ETH").decimals);
    let req = FlashPositionRequest {
        mode: FlashPositionMode::Undeclared,
        collateral: t.resolve_asset("USDC"),
        collateral_amount: usdc_raw(&t, 4_000.0),
        extra_asset: extra.clone(),
        extra_amount,
        reenter_spoke_id: HARNESS_SPOKE,
        reenter_account_id: 0,
    };
    let mut refunds = Vec::new(&t.env);
    refunds.push_back(extra.clone());
    let caller = t.get_or_create_user(ALICE);
    let eth_before = soroban_sdk::token::Client::new(&t.env, &extra).balance(&caller);

    let account_id = t
        .try_alice_eth_flash(
            &receiver,
            &data(&t, req),
            &collaterals(&t, &[("USDC", 4_000.0)]),
            &refunds,
        )
        .expect("undeclared refund");
    assert!(account_id > 0);
    let eth_after = soroban_sdk::token::Client::new(&t.env, &extra).balance(&caller);
    assert_eq!(eth_after - eth_before, extra_amount);
    assert_eq!(t.supply_balance_for(ALICE, account_id, "ETH"), 0.0);
```

**File:** tests/integration/flows/flash_position.sh (L349-372)
```shellscript
    # Extra undeclared asset is not deposited; listed refund returns it to caller.
    local alice_usdc_pre alice_usdc_post extra_usdc=10000000
    local controller_usdc_pre controller_xlm_pre
    # Nonzero balances make accidental refund/credit of preexisting funds visible.
    # Both donations remain below the teardown's 1,000-stroop controller dust cap.
    inv fp_protected_usdc_funding "$ALICE" "$CONTROLLER" -- borrow \
        --caller "$ALICE_ADDR" --account_id "$ALICE_FP_ACCT" \
        --borrows "$(pay_vec "$PRIMARY_HUB_ID" "$USDC_SAC" 37)" --to null >/dev/null || return 1
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
