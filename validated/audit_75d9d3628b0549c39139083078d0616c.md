### Title
Flash-position collateral list is capped by declared leg count, not new slots, so over-limit accounts cannot top up existing collaterals - (File: contracts/controller/src/strategies/flash_position.rs)

### Summary
The analog of `lpDeposit()`'s over-broad `activeLpAddresses.length < lpLimit` check lives in `validate_collaterals`, which gates `flash_position` on the raw length of the caller-supplied `collaterals` vector instead of on the number of supply positions the call would actually open.

### Finding Description
`Controller::supply` and liquidation share-credit both route through `validate_bulk_position_limits`, which deduplicates legs and counts only hub-assets the account does not already hold — an early return when `new_positions_count == 0` lets top-ups proceed even after governance lowers `max_supply_positions` below the account's current count (fix for the same bug class, tracked as GH-16). [1](#0-0) 

`flash_position`'s `validate_collaterals`, however, applies a separate, stricter precondition before ever reaching that slot-aware check:

```rust
// contracts/controller/src/strategies/flash_position.rs:183-187
assert_with_error!(
    env,
    collaterals.len() <= limits.max_supply_positions,
    GenericError::InvalidPayments
);
``` [2](#0-1) 

The comparison is against `collaterals.len()` — the number of declared collateral legs — not against the number of *new* supply positions those legs would create. A leg naming a hub-asset the account already holds opens no slot (the downstream `process_deposit` would merge into the existing position), yet it still consumes one unit of the `max_supply_positions` budget in this assertion. The integration suite even documents the ordering: "List length is checked before unique-position count: 2 declared collaterals with max_supply_positions=1 is InvalidPayments (#16), not #109." [3](#0-2) 

### Impact Explanation
After governance lowers `max_supply_positions` below an account's existing supply-position count (a supported operation — the test-harness explicitly exercises `set_position_limits` below live counts), that account can no longer use `flash_position` to top up *existing* collateral legs if it needs to declare more than the new limit legs, even though every declared leg is already held and `validate_bulk_position_limits` would return immediately with `new_positions_count == 0`. For a leveraged Multiply/Long/Short account whose health factor is deteriorating, the flash path is the mechanism for adding collateral and debt atomically in one transaction via the receiver callback; being blocked from it is a temporary freezing of position-management functionality for the exact class of accounts (over-limit books) the GH-16 fix was meant to keep usable.

### Likelihood Explanation
Requires a governance `set_position_limits` that drops `max_supply_positions` under the account's held supply count, plus an account wanting to declare more than the new limit in a single `flash_position` call where all legs are already held. Both conditions are reachable by unprivileged users once the limit is lowered, and the same over-limit scenario is already exercised for `supply` in `position_limit_lowering_keeps_topups.rs`. [4](#0-3)  Medium-low likelihood; impact is bounded because plain `supply` top-ups remain open as a non-atomic workaround.

### Recommendation
Mirror the fix applied to `lpDeposit()`/`validate_bulk_position_limits`: in `validate_collaterals`, compare against the count of collaterals whose `hub_asset` is not already present in `account.supply_positions` (deduplicated as today), not against `collaterals.len()` — or drop the raw-length assertion entirely and let `validate_position_entry_gates` → `validate_bulk_position_limits` enforce the slot bound, keeping a separate constant (e.g., `MAX_FLASH_COLLATERALS`) if a list-size bound is needed for resource-limit reasons.

### Proof of Concept
1. Alice opens a Multiply position holding supply positions in USDC and ETH under `max_supply_positions = 5`.
2. Governance lowers `max_supply_positions` to 1 (`set_position_limits{max_supply_positions:1,...}`), below Alice's count of 2.
3. Alice calls `Controller::flash_position` declaring both held collaterals `(USDC, ETH)` to rebalance/top up via the receiver callback.
4. `validate_collaterals` reverts with `InvalidPayments` (#16) at `collaterals.len() (2) <= max_supply_positions (1)`, even though `validate_bulk_position_limits` would see `new_positions_count == 0` and pass — identical root cause to the `lpDeposit` report: a limit check applied where the action increases the position count by zero. The account retains its positions but is denied the atomic collateral-management path until the limit is raised again.

### Citations

**File:** contracts/controller/src/risk/validation.rs (L82-111)
```rust
    let mut seen: Map<HubAssetKey, bool> = Map::new(env);
    let mut new_positions_count: u32 = 0;
    for (hub_asset, _) in aggregated.iter() {
        if seen.contains_key(hub_asset.clone()) {
            continue;
        }
        seen.set(hub_asset.clone(), true);

        let already_present = match position_type {
            AccountPositionType::Deposit => account.supply_positions.contains_key(hub_asset),
            AccountPositionType::Borrow => account.borrow_positions.contains_key(hub_asset),
        };
        if !already_present {
            new_positions_count += 1;
        }
    }

    // Existing positions remain usable after governance lowers the position limit.
    if new_positions_count == 0 {
        return;
    }

    let total_positions = current_count
        .checked_add(new_positions_count)
        .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow));
    assert_with_error!(
        env,
        total_positions <= max_allowed,
        CollateralError::PositionLimitExceeded
    );
```

**File:** contracts/controller/src/strategies/flash_position.rs (L182-187)
```rust
    let limits = storage::get_position_limits(env);
    assert_with_error!(
        env,
        collaterals.len() <= limits.max_supply_positions,
        GenericError::InvalidPayments
    );
```

**File:** tests/integration/flows/flash_position.sh (L732-744)
```shellscript
    # Empty account + two new collaterals vs max_supply=1.
    inv fp_limits_one_supply_gaps "$ADMIN" "$CONTROLLER" -- set_position_limits \
        --limits '{"max_supply_positions":1,"max_borrow_positions":5}' >/dev/null
    FP_COLS="$(jq -nc --argjson h "$PRIMARY_HUB_ID" --arg x "$XLM_SAC" --arg u "$USDC_SAC" \
        '[[{hub_id:$h,asset:$x},"1"],[{hub_id:$h,asset:$u},"1"]]')"
    FP_ACCOUNT_ID=0
    # List length is checked before unique-position count: 2 declared
    # collaterals with max_supply_positions=1 is InvalidPayments (#16), not #109.
    fp_run xfail flash_position_two_collaterals_limit_new 'Error\(Contract, #16\)' || true
    # Existing already has XLM supply; declaring USDC as a second supply also #109.
    FP_ACCOUNT_ID="$ALICE_FP_ACCT"
    FP_COLS="$(pay_vec "$PRIMARY_HUB_ID" "$USDC_SAC" 1)"
    fp_run xfail flash_position_second_supply_limit_ex 'Error\(Contract, #109\)' || true
```

**File:** tests/test-harness/tests/controller/position_limit_lowering_keeps_topups.rs (L19-26)
```rust
#[test]
fn a_held_asset_can_still_be_topped_up_after_the_limit_drops_below_the_count() {
    let mut t = two_positions_then_limit_of_one();
    t.try_supply(ALICE, "USDC", 100.0)
        .expect("top-up opens no slot");
    t.try_supply_to_account(CAROL, ALICE, "USDC", 1.0)
        .expect("third-party top-up opens no slot");
}
```
