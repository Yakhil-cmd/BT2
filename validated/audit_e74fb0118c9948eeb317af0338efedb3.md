### Title
Attacker can permanently block permissionless bad-debt socialization by dust-donating collateral to an insolvent account - (File: contracts/controller/src/positions/supply.rs)

### Summary
The bug class from the report — an attacker donating a negligible token amount to defeat a "balance/dust" exit condition and keep a position alive — maps directly onto XOXNO Lending's bad-debt cleanup gate. `clean_bad_debt` is permissionless only while the account's total collateral is at or below `BAD_DEBT_USD_THRESHOLD` ($5 WAD). Because `process_supply` explicitly allows any third party to top up an **existing** supply position on someone else's account (`require_third_party_existing_supply`), an attacker can donate dust collateral into the victim's existing supply position to push `total_collateral` just above $5. After that, `is_socializable_bad_debt` fails, every `clean_bad_debt` call reverts with `CannotCleanBadDebt`, and the same check inside post-liquidation cleanup (`check_bad_debt_after_liquidation`) also skips socialization.

### Finding Description
- `is_socializable_bad_debt` admits cleanup only when `total_debt > total_collateral && total_collateral <= BAD_DEBT_USD_THRESHOLD` (curve.rs:25-27).
- `clean_bad_debt_standalone`/`socialize_bad_debt` with `BadDebtGate::DustCapped` reverts via `CannotCleanBadDebt` when the gate fails (mod.rs:229-235), and `check_bad_debt_after_liquidation` silently skips cleanup (apply.rs:313-315).
- `process_supply` resolves the target account from a caller-supplied `account_id` and only requires that third parties add to an *existing* supply position (supply.rs:61, 86-96). An insolvent account being cleaned necessarily has supply positions (its residual collateral), so the attacker always has a donation target.
- The attacker's deposit is credited to the victim's `supply_positions` via `merge_supply_leg` (supply.rs:285-299), raising `total_collateral` in `calculate_account_risk_totals` — exactly the value the gate reads.

The donation cost is only the delta to exceed $5 plus one wei. The attacker can repeat it: any time liquidation or price drift pushes collateral back below $5, another dust top-up re-closes the gate.

### Impact Explanation
Bad debt that should be permissionlessly socialized instead persists and continues accruing borrow interest, deepening the shortfall borne by suppliers of those markets. The only remaining remedy is the privileged owner-only `force_socialize_bad_debt` governance path (Sensitive delay tier), which is precisely the escalation the permissionless gate exists to avoid. This is temporary freezing of a required protocol operation / growing protocol insolvency reachable by a single unprivileged address, matching the "donate dust to defeat the exit trigger" class.

### Likelihood Explanation
The attack needs one ordinary `supply` call naming the victim's `account_id` and an existing `HubPayment` leg; no auth beyond the attacker's own signature is required and there is no minimum deposit. It is cheap, repeatable, and incentive-aligned for an attacker who profits from keeping an insolvent account open (e.g., delaying supplier write-downs, or griefing). Main limitation: it cannot create a *new* supply position asset for the victim, only top up an existing one — but a cleanup candidate always has one.

### Recommendation
Base the permissionless cleanup gate on the collateral attributable to the account's own positions at the time insolvency arose, or cap the gate at the *seizable* value rather than total collateral; alternatively, make `socialize_bad_debt` net/forgive third-party dust donations — e.g., during cleanup, treat collateral above the threshold only if it existed before the account became insolvent, or allow `clean_bad_debt` to first refund/forfeit dust supplied by non-owner addresses. A simpler fix consistent with the report's mitigation: let permissionless cleanup proceed when `total_collateral` exceeds the threshold solely due to positions topped up by non-owner/non-delegate callers, or record a per-account collateral snapshot used for the dust gate.

### Proof of Concept
```rust
// Alice is deeply insolvent: $4 of USDC collateral vs $100 of ETH debt.
// Gate admits cleanup: 4 <= BAD_DEBT_USD_THRESHOLD(5) && debt > collateral.
assert!(is_socializable_bad_debt(debt=100*WAD, coll=4*WAD));

// Attacker (any address, not owner/delegate) tops up Alice's *existing*
// USDC supply position by 2 USDC:
client.supply(
    &attacker,                      // caller: unprivileged third party
    &alice_account_id,              // target account (nonzero -> third-party path)
    &alice_spoke_id,
    &vec![&env, HubPayment { hub_asset: usdc_key, amount: 2 * ONE_USDC }],
);
// Passes: require_third_party_existing_supply only checks that the
// hub_asset key already exists in account.supply_positions.

// Now total_collateral = $6 > $5:
client.clean_bad_debt(&keeper, &alice_account_id);
// ^ reverts with CannotCleanBadDebt (#114).

// Same gate inside liquidate also skips cleanup:
// check_bad_debt_after_liquidation -> is_socializable_bad_debt fails.

// If a liquidation later pushes collateral back to <= $5,
// the attacker donates dust again. Permissionless cleanup is
// permanently denied; only owner-only force_socialize_bad_debt remains.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** contracts/controller/src/positions/liquidation/curve.rs (L25-27)
```rust
pub(crate) fn is_socializable_bad_debt(total_debt: Wad, total_collateral: Wad) -> bool {
    total_debt > total_collateral && total_collateral <= Wad::from(BAD_DEBT_USD_THRESHOLD)
}
```

**File:** contracts/controller/src/positions/supply.rs (L86-97)
```rust
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

**File:** contracts/controller/src/positions/liquidation/mod.rs (L229-237)
```rust
    let admits = match gate {
        BadDebtGate::DustCapped => {
            is_socializable_bad_debt(totals.total_debt, totals.total_collateral)
        }
        BadDebtGate::InsolventOnly => totals.total_debt > totals.total_collateral,
    };
    assert_with_error!(env, admits, CollateralError::CannotCleanBadDebt);

    bad_debt::execute_bad_debt_cleanup(env, &mut cache, account_id, &account, &totals);
```

**File:** contracts/controller/src/positions/liquidation/apply.rs (L300-316)
```rust
/// Removes empty accounts or socializes insolvent debt under the collateral dust cap.
pub(crate) fn check_bad_debt_after_liquidation(
    env: &Env,
    cache: &mut Context,
    account_id: u64,
    account: &Account,
    totals: &AccountRiskTotals,
) {
    if account.borrow_positions.is_empty() {
        account::cleanup_account_if_empty(env, account, account_id);
        return;
    }

    if is_socializable_bad_debt(totals.total_debt, totals.total_collateral) {
        bad_debt::execute_bad_debt_cleanup(env, cache, account_id, account, totals);
    }
}
```
