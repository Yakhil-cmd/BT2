### Title
Permissionless `supply` restamps a foreign account's collateral risk tuple, bypassing the `update_account_threshold` solvency gate - ([File: contracts/controller/src/positions/supply.rs])

### Summary
`controller::supply` is permissionless: a caller who is neither owner nor delegate may top up an existing supply position of any account. Ordinary supply deposits restamp the position's cached risk parameters (`loan_to_value`, `liquidation_threshold`, `liquidation_bonus`, `liquidation_fees`) to the currently listed values. The codebase deliberately gates the dedicated restamping path `update_account_threshold` behind a post-restamp health-factor floor (HF ≥ 1.05 when `has_risks` is set) precisely so a third party cannot push an account into liquidation. Third-party `supply` of a dust amount performs the same restamp with no such gate, so any unprivileged address can drag a foreign account's stale, more generous risk tuple to current values and then liquidate it — the analog of writing to a location outside the caller's authorized scope (the traversal primitive), reached with an attacker-controlled `account_id`.

### Finding Description
- `supply` resolves the account via `load_or_create_account` with `AccountGuard::Supply`, which only checks the spoke, not ownership — any caller may deposit into an existing account [1](#0-0) 
- `require_third_party_existing_supply` only restricts the *asset set* to markets the account already supplies; it imposes no risk gate [2](#0-1) 
- `process_deposit` merges the leg through `merge_supply_leg`, which refreshes supply risk params (`refresh_supply_risk_params` / `RiskRefreshScope` is imported for this purpose) [3](#0-2) [4](#0-3) 
- Tests confirm the semantics: "An ordinary supply restamps an existing position; a credit does not" [5](#0-4) 
- The intended-safe path explicitly forbids unsafe restamping: `update_account_threshold` "with has_risks set it reverts unless the account clears the update health-factor floor, so it cannot be used to push an account into liquidation" [6](#0-5) 

Because positions carry a cached risk tuple stamped at entry, lowering the listing via `edit_asset_in_spoke` does not affect existing positions until they are restamped. The protocol's own keeper path refuses to restamp an account that would land below HF 1.05; third-party `supply` enforces no such invariant.

### Impact Explanation
Theft of user funds via forced liquidation. After governance tightens a listing (lower LTV/threshold — a routine risk-off action), accounts holding that collateral remain healthy only because their stamps are stale. An attacker supplies 1 base unit of that asset to the victim's account, which restamps the tuple, drops the computed collateral value/health factor below 1, then immediately calls `liquidate` in the same or next transaction, extracting the liquidation bonus from the victim's collateral. This achieves by a dust donation what `update_account_threshold` is explicitly designed to prevent.

### Likelihood Explanation
High. Requirements: a listed asset's risk parameters are tightened while open positions exist (a normal lifecycle event — `edit_asset_in_spoke` exists for exactly this), and the victim's account was stamped under the old tuple. The attacker needs only one base unit of the asset and two permissionless calls (`supply`, `liquidate`). No privileged access, no price manipulation, no cooperation from the victim.

### Recommendation
Apply the same safety rule to third-party supply as `update_account_threshold`: when the caller is not the owner/delegate, either (a) skip restamping the merged position's risk tuple entirely (credit shares under the existing stamp, as `SeizeMode::Credit` already does for receiver positions), or (b) after `merge_supply_leg`, require the post-restamp account health factor to satisfy the same ≥ 1.05 floor used by the keeper path. Owner-initiated supply may restamp freely.

### Proof of Concept
1. Alice supplies USDC collateral under a listing with `ltv=7000`, `threshold=8000` and borrows near the limit; her position stores those stamps.
2. Governance lowers the listing to `ltv=4000`, `threshold=5000` (e.g., volatility response). Alice's account still reads HF > 1 from her cached tuple.
3. Keeper calls `update_account_threshold(caller, has_risks=true, [alice])` → reverts, because restamped HF < 1.05.
4. Attacker calls `supply(attacker, alice_id, [(hub_asset(USDC), 1)])` — allowed because USDC is already an existing supply slot on Alice's account. `merge_supply_leg` restamps the tuple to 4000/5000.
5. Alice's HF is now < 1 on-chain. Attacker calls `liquidate(attacker, alice_id, payments, SeizeMode::Transfer)` and seizes collateral at the bonus, profiting at Alice's expense — a state transition the protocol's own restamping gate was built to forbid.

### Citations

**File:** contracts/controller/src/account.rs (L95-111)
```rust
    if account_id == 0 {
        return create_account(env, caller, spoke_id, mode, cache);
    }
    let account = storage::get_account(env, account_id);
    match guard {
        AccountGuard::Supply => require_spoke_match(env, &account, spoke_id),
        AccountGuard::Migrate => {
            require_owner_or_delegate(env, account_id, caller, &account.owner);
            require_spoke_match(env, &account, spoke_id);
        }
        AccountGuard::Multiply => {
            require_owner_or_delegate(env, account_id, caller, &account.owner);
            require_spoke_match(env, &account, spoke_id);
            assert_with_error!(env, account.mode == mode, GenericError::AccountModeMismatch);
        }
    }
    (account_id, account)
```

**File:** contracts/controller/src/positions/supply.rs (L21-21)
```rust
use crate::risk::{refresh_supply_risk_params, validation, RiskRefreshScope};
```

**File:** contracts/controller/src/positions/supply.rs (L76-97)
```rust
/// Restricts third parties to existing supply positions. New accounts are
/// exempt because the caller becomes their owner.
fn require_third_party_existing_supply(
    env: &Env,
    account_id: u64,
    resolved_account_id: u64,
    caller: &Address,
    account: &Account,
    aggregated: &AggregatedPayments,
) {
    if account_id != 0
        && !account::is_owner_or_delegate(env, resolved_account_id, caller, &account.owner)
    {
        for (hub_asset, _) in aggregated.iter() {
            assert_with_error!(
                env,
                account.supply_positions.contains_key(hub_asset.clone()),
                GenericError::NotAuthorized
            );
        }
    }
}
```

**File:** contracts/controller/src/positions/supply.rs (L126-135)
```rust
        let position = account.get_or_create_supply_position(&hub_asset, &asset_config);
        entries.push_back(PoolSupplyEntry {
            action: make_pool_action(&position, received, hub_asset.clone()),
        });
    }

    let results = pool_supply_call(env, &pool_addr, &entries);
    for_each_leg(env, &entries, &results, |entry, result| {
        merge_supply_leg(env, account, &entry.action, &result, cache);
    });
```

**File:** tests/test-harness/tests/controller/liquidation_seize_modes.rs (L387-394)
```rust
fn a_receiver_with_a_position_keeps_its_own_tuple_and_just_grows() {
    let mut t = liquid_usdc();
    // Give the liquidator a USDC position stamped under today's listing.
    t.supply(LIQUIDATOR, "USDC", 1_000.0);
    let receiver = t.resolve_account_id(LIQUIDATOR);
    let before = position(&t, receiver, "USDC").expect("liquidator holds USDC");

    // Move the listing. An ordinary supply restamps an existing position; a credit does not.
```

**File:** scripts/permissionless_entrypoints.txt (L76-76)
```text
controller::update_account_threshold | caller-auth | INV-AUTH-03, INV-RISK-01 | Keeper maintenance: restamps cached risk parameters to their currently listed values. Without has_risks it restamps LTV only, which the health factor does not read; with has_risks set it reverts unless the account clears the update health-factor floor, so it cannot be used to push an account into liquidation.
```
