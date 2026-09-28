### Title
Permissionless `update_account_threshold` writes a victim's supply positions — any caller can restamp a foreign account's LTV/risk tuple without the owner's authorization - ([File: contracts/controller/src/risk/params.rs](contracts/controller/src/risk/params.rs))

### Summary
The Warp report describes untrusted remote output being materialized as a local state write (a file) without any confirmation from the affected principal. The analog in XOXNO Lending is `controller.update_account_threshold(caller, has_risks, account_ids)`: it is callable by *any* authenticated address and writes risk parameters into *other people's* supply positions. The `caller` only needs `require_auth` on its own identity (`require_authorized_caller`), and `account_ids` are arbitrary — no check binds the caller to the account owner or a delegate. An attacker can therefore push a forced parameter update onto a victim account at a moment that is unfavorable to the victim.

### Finding Description
`update_account_threshold` (`contracts/controller/src/lib.rs:386`) calls `risk::params::update_account_threshold`, which only calls `validation::require_authorized_caller(env, &caller)` [1](#0-0) . `sync_account_thresholds` then resolves the account owner solely to *build* the account — `try_account_owner` is used to fail closed on unresolvable NFT state, not to compare against `caller` [2](#0-1) . It then overwrites each listed supply position's `loan_to_value` with the current spoke config (`refresh_supply_risk_params` → `position.loan_to_value = effective_config.loan_to_value` [3](#0-2) ), and with `has_risks = true` also rewrites `liquidation_threshold`, `liquidation_bonus` and `liquidation_fees` subject only to a *hypothetical* HF ≥ 1.05 gate computed with the new tuple [4](#0-3) , plus a final HF ≥ 1.05 assertion [5](#0-4) .

Two observations make this a real bug rather than a benign keeper helper:

1. **The 1.05 gate only protects `has_risks = true`, and only protects the victim's *health*, not their terms.** With `has_risks = false` (`LtvOnly` scope), the LTV of every supplied asset is overwritten unconditionally [6](#0-5) . If governance has lowered a market's LTV, an attacker can immediately restamp every outstanding account, stripping grandfathered higher LTVs the protocol explicitly preserves ("Existing positions retain their risk tuple", ADR-0019 area [7](#0-6) ). Positions that were designed to keep their old borrow headroom lose it the moment any stranger sends one transaction.
2. **The HF gate permits the write whenever the victim stays above 1.05** — i.e. exactly when the victim is healthy enough to notice nothing. A threshold *reduction* is `favors_liquidator` [8](#0-7) , so it is applied only if post-write HF ≥ 1.05; but a threshold *increase* combined with a *bonus increase* also passes `favors_liquidator` (higher bonus counts as favoring the liquidator) — while a bonus *decrease* or fee *increase* that makes the victim *less* attractive to liquidate is applied unconditionally, and a threshold *increase* alone skips the gate entirely. The attacker chooses the timing: they call it when the stored tuple vs. new config combination best serves their liquidation plan (e.g., restamping a higher liquidation bonus onto the victim, or lowering the victim's LTV before a governance-announced de-rating the victim planned to borrow under).

Like the Warp bug, the fundamental flaw is that attacker-supplied input (`account_ids` over the wire, analogous to SSH output bytes) is materialized into persistent state belonging to a third party, with no confirmation from that party.

### Impact Explanation
- **Loss of grandfathered risk terms / temporary freezing of borrow capacity**: a forced `LtvOnly` restamp permanently downgrades a victim's `loan_to_value` to the current (lower) spoke config, blocking borrows and refinance strategies (`multiply`, `swap_debt`) that would have succeeded under the stored tuple. Since positions "retain their risk tuple" by design, this strips an intended protection.
- **Liquidation-term manipulation**: `FullTuple` restamp lets an attacker write a *higher* `liquidation_bonus` onto a victim (counted as `favors_liquidator`, gated only by HF ≥ 1.05 — trivially satisfied for healthy accounts), increasing the payout the attacker later collects when liquidating that account, i.e. direct theft-adjacent value extraction from user collateral.
- Impact category: theft/partial freezing of user funds (Medium severity — bounded by the HF gate for the tuple leg and by config actually having changed, but fully permissionless and permanent).

### Likelihood Explanation
- Requires only any funded Stellar address — `require_authorized_caller` accepts any signer; tests confirm "any signed caller may update_indexes" style permissionless semantics for these keeper endpoints [9](#0-8) .
- Trigger condition: any governance change to a spoke asset's `loan_to_value`, `liquidation_threshold`, `liquidation_bonus`, or `liquidation_fees` — a routine event. Between the config change landing and the victim acting, the attacker frontruns the restamp on every exposed `account_id` (enumerable via position-NFT counter, which the keeper itself scans [10](#0-9) ).
- No capital required; cost is one transaction per batch of accounts.

### Recommendation
Bind the refresh to the affected principal or make writes direction-safe:
1. Require `caller` to be the account owner or an active delegate for every `account_id`, matching `account::require_owner_or_delegate` used by the other account-mutating entrypoints (e.g. `repay_debt_with_collateral` [11](#0-10) ).
2. Alternatively, keep permissionless calling but only apply *non-adverse* deltas: skip the write when `effective_config.loan_to_value < position.loan_to_value`, when `liquidation_bonus` rises, or when `liquidation_threshold` falls — i.e. only restamp changes that strictly help or neutralize the account (a monotonicity guard symmetric to `favors_liquidator`).
3. At minimum, document and gate the adverse-direction restamp behind owner/delegate auth while leaving the favorable direction permissionless for keepers.

### Proof of Concept
1. Governance lowers spoke-1 USDC `loan_to_value` from 8000 to 7000 bps (or raises `liquidation_bonus` 300 → 500 bps).
2. Alice holds account 7 supplying USDC with the stored tuple (LTV 8000, bonus 300). She has HF well above 1.05.
3. Attacker calls `controller.update_account_threshold(caller = attacker, has_risks = false, account_ids = [7])`. `sync_account_thresholds` resolves Alice's owner via NFT but never compares it to `attacker`; `restamp` writes `loan_to_value = 7000` into Alice's supply position and commits via `set_supply_positions` [12](#0-11) .
4. Alice's planned `multiply`/`borrow` sized against her original 8000 bps LTV now fails `InsufficientCollateral`; her grandfathered terms are gone with no action or consent from her.
5. With `has_risks = true` after a bonus-increase config change, the same call writes `liquidation_bonus = 500` onto her position (HF ≥ 1.05 passes trivially for a healthy account); when the attacker later liquidates her, the seized-collateral bonus is computed from the attacker-restamped tuple.

### Citations

**File:** contracts/controller/src/risk/params.rs (L34-38)
```rust
    let before = *position;
    position.loan_to_value = effective_config.loan_to_value;
    if scope == RiskRefreshScope::FullTuple {
        apply_gated_liquidation_params(env, cache, account, hub_asset, position, effective_config);
    }
```

**File:** contracts/controller/src/risk/params.rs (L44-63)
```rust
pub(crate) fn restamp_listed_supply_ltv(cache: &mut Context, account: &mut Account) -> bool {
    let mut changed = false;
    let keys = account.supply_positions.keys();
    for hub_asset in keys.iter() {
        let Some(listed) = cache.cached_spoke_asset(account.spoke_id, &hub_asset) else {
            continue;
        };
        let config: AssetConfig = (&listed).into();
        let Some(raw) = account.supply_positions.get(hub_asset.clone()) else {
            continue;
        };
        let mut position = AccountPosition::from(&raw);
        if position.loan_to_value.raw() == config.loan_to_value.raw() {
            continue;
        }
        position.loan_to_value = config.loan_to_value;
        update_or_remove_supply_position(account, &hub_asset, &position);
        changed = true;
    }
    changed
```

**File:** contracts/controller/src/risk/params.rs (L76-92)
```rust
    if favors_liquidator(position, effective_config)
        && !account.debt_free()
        && !clears_min_hf(
            env,
            cache,
            account,
            hub_asset,
            position,
            effective_config.liquidation_threshold,
        )
    {
        return;
    }

    position.liquidation_threshold = effective_config.liquidation_threshold;
    position.liquidation_bonus = effective_config.liquidation_bonus;
    position.liquidation_fees = effective_config.liquidation_fees;
```

**File:** contracts/controller/src/risk/params.rs (L96-100)
```rust
fn favors_liquidator(position: &AccountPosition, effective_config: &AssetConfig) -> bool {
    effective_config.liquidation_threshold.raw() < position.liquidation_threshold.raw()
        || effective_config.liquidation_bonus.raw() > position.liquidation_bonus.raw()
        || effective_config.liquidation_fees.raw() < position.liquidation_fees.raw()
}
```

**File:** contracts/controller/src/risk/params.rs (L124-144)
```rust
pub(crate) fn update_account_threshold(
    env: &Env,
    caller: Address,
    has_risks: bool,
    account_ids: Vec<u64>,
) {
    validation::require_authorized_caller(env, &caller);

    let scope = if has_risks {
        RiskRefreshScope::FullTuple
    } else {
        RiskRefreshScope::LtvOnly
    };

    let mut cache = Context::new(env);

    for account_id in account_ids {
        cache.reset_spoke_context();
        sync_account_thresholds(env, account_id, scope, &mut cache);
    }
}
```

**File:** contracts/controller/src/risk/params.rs (L155-167)
```rust
    let Some(meta) = storage::try_get_account_meta(env, account_id) else {
        return;
    };

    let supply_positions = storage::get_supply_positions(env, account_id);
    if supply_positions.is_empty() {
        return;
    }

    // Fail closed: never update an account whose NFT owner cannot be resolved.
    let Some(owner) = storage::try_account_owner(env, account_id) else {
        return;
    };
```

**File:** contracts/controller/src/risk/params.rs (L191-219)
```rust
        let changed = refresh_supply_risk_params(
            env,
            cache,
            &account,
            &hub_asset,
            &mut updated,
            &asset_config,
            scope,
        );
        if !changed {
            continue;
        }

        any_changed = true;
        update_or_remove_supply_position(&mut account, &hub_asset, &updated);

        let market_index = cache.cached_market_index(&hub_asset);
        cache.record_supply_position_update(
            events::PositionAction::ParamUpd,
            &hub_asset,
            market_index.supply_index.raw(),
            0,
            &updated,
        );
    }

    if any_changed {
        storage::set_supply_positions(env, account_id, &account.supply_positions);
    }
```

**File:** contracts/controller/src/risk/params.rs (L221-234)
```rust
    if full_tuple {
        let hf = calculate_account_risk_totals(
            env,
            cache,
            &account.supply_positions,
            &account.borrow_positions,
        )
        .health_factor;
        assert_with_error!(
            env,
            hf >= Wad::from(THRESHOLD_UPDATE_MIN_HF_RAW),
            CollateralError::HealthFactorTooLow
        );
    }
```

**File:** docs/explanation/decisions.md (L238-240)
```markdown

Receiver position limits still apply, and a newly credited asset needs a
listing. Existing positions retain their risk tuple; new positions use the
```

**File:** tests/test-harness/tests/controller/keeper.rs (L395-410)
```rust
#[test]
fn test_permissionless_keeper_endpoints() {
    let mut t = LendingTest::new()
        .with_market(usdc_preset())
        .with_dust_disabled_all_markets()
        .build();

    let bob_addr = t.get_or_create_user(BOB);

    let ctrl = t.ctrl_client();
    let assets = soroban_sdk::vec![&t.env, hub_asset(t.resolve_market("USDC").asset.clone())];

    t.env.mock_all_auths();
    let result = ctrl.try_update_indexes(&bob_addr, &assets);
    assert!(result.is_ok(), "any signed caller may update_indexes");
}
```

**File:** services/keeper/README.md (L141-143)
```markdown
| Controller `Hub(id)` / `Spoke(id)` | persistent | `LastHubId` / `LastSpokeId` | yes |
| Account state (`AccountMeta` / `SupplyPositions` / `BorrowPositions` / `Delegates`) | persistent | position-NFT counter scan | yes |
| Account ownership (`Owner(token_id)` on the position NFT) | persistent | position-NFT counter scan | yes, in the `per_user` metrics group. OpenZeppelin extends it to 30 days and the controller extends account keys to 120 days, so it archives first if unrenewed |
```

**File:** contracts/controller/src/strategies/repay_debt_with_collateral.rs (L50-51)
```rust
    let mut account = storage::get_account(env, account_id);
    account::require_owner_or_delegate(env, account_id, caller, &account.owner);
```
