### Title
Credit-mode liquidation never books seized supply against the receiver's spoke usage, corrupting per-spoke accounting and freezing the receiver's collateral — (File: contracts/controller/src/positions/liquidation/apply.rs)

### Summary
The analog of CVE-2022-42928 (allocations missing required annotations that corrupt shared state under a specific runtime condition) is a missing usage annotation: `SeizeMode::Credit` liquidation writes new supply shares to the receiver account but never calls `Context::apply_spoke_entry` for the receiver's `spoke_id`. The only usage movement on the seizure leg is the exit booked against the *liquidated* account's spoke. Whenever the credited receiver lives on a different spoke than the liquidated account — a state the code explicitly supports by resolving the receiver's own `spoke_id` — the receiver's spoke `SpokeUsage` row permanently under-counts real supply. On a later exit, `apply_spoke_exit` underflows, freezing the receiver's collateral and leaving stranded usage that silently widens the spoke's cap headroom.

### Finding Description
`process_liquidation` resolves a receiver for `SeizeMode::Credit(receiver_id)` and calls `apply::apply_liquidation_share_credit`, which routes through `credit_supply_shares`. That function deliberately reads the receiver's own spoke listing (`cache.require_spoke_asset(receiver.spoke_id, hub_asset)` in `contracts/controller/src/positions/liquidation/apply.rs:230`), i.e. the receiver may be on a different spoke than the liquidated account — the docs confirm same-spoke is required only for `PositionMode::Normal` receivers. [1](#0-0) 

The seizure leg's usage bookkeeping is done only on the liquidated account's side: `apply_liquidation_seizures`/`apply_withdraw_batch` → `merge_withdraw_leg` → `apply_leg_usage(env, cache, account.spoke_id, UsageSide::Supply, ..., Exit, ...)`, which decrements `SpokeUsage(liquidated.spoke_id, hub_asset)` by the seized scaled amount. `credit_supply_shares` then increments `receiver` shares with **no** `apply_spoke_entry(receiver.spoke_id, ...)` — compare `merge_supply_leg`, which always pairs a share credit with `apply_leg_usage(... Entry ...)`. [2](#0-1) [3](#0-2) 

The comment in the certora spec states the design assumption explicitly: credit mode "moves collateral between two accounts on one spoke in one call, so only the sum over both tracks usage" — the identity holds only because the spec seeds both principals on the same spoke. For a cross-spoke receiver the sum-over-pair identity is meaningless: spoke A's row drops by `S` while spoke B's row gains nothing even though `S` of shares now live under spoke B. [4](#0-3) 

Because `SpokeUsage` is the sole per-spoke cap record ("a verb that moves a position but skips `apply_leg_usage` breaks cap enforcement ... and no other check sees it"), the missing annotation is invisible to every other check. [5](#0-4) 

### Impact Explanation
Two concrete harms, both reachable by unprivileged users:

1. **Permanent freezing of funds (receiver).** When the receiver (or a later owner of that account) withdraws or is itself liquidated, the exit calls `apply_spoke_exit(receiver.spoke_id, Supply, hub_asset, delta_scaled)`, which does a checked subtraction on a row that never counted the credited shares. Once the cumulative credited `scaled_amount` exceeds the supply usage other accounts contributed on that spoke, every exit path underflows and reverts — the credited collateral is permanently frozen, since `update_or_remove_supply_position` still requires the position to be drained through the guarded exit paths. [6](#0-5) 
2. **Cap desync / protocol risk.** While the under-counted row persists, spoke B's supply cap check (`usage + delta <= cap`) runs against a usage figure missing `S`, silently enlarging effective cap headroom and letting new suppliers enter a market governance intended to be closed — exactly the "under-count lets a spoke exceed its cap" failure mode the spec warns cannot be observed elsewhere.

### Likelihood Explanation
Reaching the corrupt state requires only a `liquidate` call with `SeizeMode::Credit(receiver_id)` where the receiver account sits on a different spoke than the liquidated account — both liquidate and account creation are permissionless, and the code fetches the receiver's spoke config rather than asserting `receiver.spoke_id == account.spoke_id`. A liquidator can create their own receiver account on an empty spoke (making its usage row zero), guaranteeing underflow on their very first withdrawal of credited shares. The missing-annotation pattern mirrors the CVE: the corruption only materializes in a specific state (cross-spoke receiver), is silent at write time, and detonates later at read/exit time. Note: I could not fully enumerate `resolve_seize_receiver`'s cross-spoke checks within this investigation, so the likelihood is conditioned on the credit path admitting a different-spoke receiver — which the receiver-spoke config lookup and the "same-spoke in Normal mode" qualification strongly indicate.

### Recommendation
In `apply_liquidation_share_credit`/`credit_supply_shares`, mirror the share credit with a usage entry on the receiver's spoke: call `cache.apply_spoke_entry(receiver.spoke_id, UsageSide::Supply, &hub_asset, credited_scaled)` (or extend `record_share_credit_updates`' finalize flow) whenever `receiver.spoke_id` differs from the liquidated account's spoke — or enforce `receiver.spoke_id == account.spoke_id` for all seize modes so the single-spoke usage identity assumed by the spec holds by construction. Add a certora rule seeding the credit-mode principals on distinct spokes, and a harness test asserting `get_spoke_usage` matches `scaled` sums per spoke after a cross-spoke credit liquidation.

### Proof of Concept
1. Governance lists the same `hub_asset` on spoke A and spoke B.
2. Victim account `V` on spoke A supplies collateral `C` and borrows; price moves so `V` is liquidatable.
3. Attacker opens receiver account `R` on spoke B (`supply(caller, 0, spoke_B, ...)`), authorized per `resolve_seize_receiver` (own account / Normal-mode authorization rules for spoke B).
4. Attacker calls `liquidate(liquidator, V, debt_payments, SeizeMode::Credit(R))`:
   - `merge_withdraw_leg` decrements `SpokeUsage(A, C)` by seized `S` (`apply_leg_usage ... Exit`), plus the transfer of the fee.
   - `credit_supply_shares` writes `S - fee` shares into `R.supply_positions[C]` using `require_spoke_asset(R.spoke_id = B, C)` — no `apply_spoke_entry(B, ...)`.
   - `SpokeUsage(B, C).supplied_scaled_ray` remains 0 while `R` holds `S - fee` scaled shares.
5. Attacker calls `withdraw(R, [(C, 0)])`: `merge_withdraw_leg` → `apply_leg_usage(... Exit ...)` → `apply_spoke_exit(B, Supply, C, S - fee)` → checked subtraction `0 - (S - fee)` underflows → revert. Every subsequent exit (withdraw, liquidation seizure, `swap_collateral` withdraw leg, `repay_debt_with_collateral` close) reverts the same way: the collateral on `R` is permanently frozen, and `SpokeUsage(B, C)` stays under-counted for the lifetime of the position.

### Citations

**File:** contracts/controller/src/positions/liquidation/apply.rs (L217-236)
```rust
fn credit_supply_shares(
    env: &Env,
    receiver: &mut Account,
    hub_asset: &HubAssetKey,
    scaled: Ray,
    cache: &mut Context,
) {
    if scaled == Ray::ZERO {
        return;
    }
    let mut position = match receiver.supply_positions.get(hub_asset.clone()) {
        Some(raw) => AccountPosition::from(&raw),
        None => {
            let config = cache.require_spoke_asset(receiver.spoke_id, hub_asset);
            receiver.get_or_create_supply_position(hub_asset, &config)
        }
    };
    position.scaled_amount = position.scaled_amount.checked_add(env, scaled);
    update_or_remove_supply_position(receiver, hub_asset, &position);
}
```

**File:** contracts/controller/src/positions/supply.rs (L301-312)
```rust
    apply_leg_usage(
        env,
        cache,
        account.spoke_id,
        UsageSide::Supply,
        hub_asset,
        LegDirection::Entry {
            asset_decimals: result.asset_decimals,
        },
        old_scaled,
        &outcome,
    );
```

**File:** contracts/controller/src/positions/supply.rs (L345-354)
```rust
    apply_leg_usage(
        env,
        cache,
        account.spoke_id,
        UsageSide::Supply,
        hub_asset,
        LegDirection::Exit,
        old_scaled,
        outcome,
    );
```

**File:** certora/controller/spec/spoke_rules.rs (L776-780)
```rust
// `SpokeUsage(spoke_id, hub_asset)` is the only per-spoke record of cap
// consumption; the pool keeps no per-spoke book. `spoke_usage.rs` maintains it
// apart from the position maps it shadows. A verb that moves a position but
// skips `apply_leg_usage` breaks cap enforcement (an under-count lets a spoke
// exceed its cap, an over-count blocks valid supply), and no other check sees it.
```

**File:** certora/controller/spec/spoke_rules.rs (L2284-2291)
```rust
/// Credit-mode liquidation moves collateral between two accounts on one
/// spoke, and supply usage falls by exactly the shares that left the pair:
/// the protocol fee, not the whole seizure.
///
/// Stated over the slice `[liquidated, receiver]`, because per account
/// neither delta reconciles with usage: the liquidated account loses `S`
/// while usage moves by `fee`, and the receiver gains `S - fee` while usage
/// does not move for it at all. The sum is what the accumulator tracks.
```

**File:** contracts/controller/src/context.rs (L275-285)
```rust
    /// Buffers a scaled usage decrease; missing usage is a no-op, underflow fails.
    pub(crate) fn apply_spoke_exit(
        &mut self,
        spoke_id: u32,
        side: UsageSide,
        hub_asset: &HubAssetKey,
        delta_scaled: Ray,
    ) {
        self.require_spoke_usage_context(spoke_id)
            .apply_exit(side, hub_asset, delta_scaled);
    }
```
