### Title
Scaled-debt `i128` overflow permanently freezes all market operations - (File: `common/src/rates/simulate.rs`)

### Summary
Interest accrual multiplies the market’s stored scaled debt by the borrow index before applying the index ceiling. For a sufficiently large market, that intermediate value can exceed `i128::MAX` even though the updated borrow index remains below `MAX_BORROW_INDEX_RAY`. Because every pool mutation synchronizes interest before changing state, the first failed accrual permanently prevents repayment, withdrawal, liquidation, and further index updates for that market. [1](#0-0) 

### Finding Description
The vulnerable calculation is in `accrue_step`, which computes `borrowed_original = scaled_to_original(borrowed, borrow_index)` before deriving utilization and the next index. [2](#0-1)  `scaled_to_original` is `scaled.mul(index)`, and unrepresentable RAY results panic with `MathOverflow` rather than saturating. [3](#0-2) 

Although `update_borrow_index` clamps the index to `MAX_BORROW_INDEX_RAY`, that check is reached only after the current scaled debt is multiplied by the current index. [4](#0-3)  Consequently, the market-level bound is really `borrowed_scaled * borrow_index / RAY <= i128::MAX`; a large enough `borrowed_scaled` fails before either index cap can protect it.

`global_sync` invokes this step for every accrued time chunk. [5](#0-4)  Pool operations obtain a synchronized cache through `synced_market`, which always calls `interest::global_sync` before the requested mutation. [6](#0-5)  The permissionless controller `update_indexes(caller, assets)` reaches the same accrual path directly. [7](#0-6) [8](#0-7) 

### Impact Explanation
Once the market crosses the representable RAY-value boundary, every entrypoint that touches it fails before it can reduce debt, withdraw supply, repay, settle, recapitalize, or update parameters. [6](#0-5)  The panic aborts the transaction before `mark_accrued` commits a newer timestamp, so retrying later repeats the same overflowing calculation rather than skipping the bad interval. [9](#0-8) 

This is permanent freezing of supplier and borrower funds in that market. It also prevents liquidation and repayment needed to restore solvency, so a distressed market cannot be remediated through ordinary protocol operations.

### Likelihood Explanation
An unprivileged account can create the precondition through ordinary `supply` and `borrow` calls if governance configuration and token liquidity permit a sufficiently large position, then simply let interest accrue. No privileged call, oracle manipulation, malformed token, or external service failure is required.

Likelihood is constrained by the required market size, collateral, and sustained utilization. The precondition is nevertheless protocol-reachable: admitted token amounts and index ceilings independently allow the intermediate scaled value to exceed the `i128` domain, and there is no market-level value cap checked before accrual. [10](#0-9) 

### Recommendation
Enforce a representable market-value bound before accrual, rather than relying only on index ceilings. In particular:

- Check `borrowed_scaled * borrow_index / RAY` and `supplied_scaled * supply_index / RAY` against `i128::MAX` before minting or scaling additional shares.
- Reject `supply` and `borrow` operations that could leave the market without enough arithmetic headroom for future index growth.
- Add an emergency path that can reduce debt or supply without requiring full historical accrual first, or make accrual saturate at a safe value boundary before performing downstream multiplications.
- Prefer explicit checked widening for accrual calculations and return a controlled bounded result only if doing so preserves accounting invariants.

### Proof of Concept
Conceptual transaction sequence:

1. A user calls controller `supply` for a high-decimal market, depositing an amount near the admitted scaled-share domain.
2. From a sufficiently collateralized account, the user calls controller `borrow` for a large fraction of that market.
3. Time advances while utilization remains high, increasing `borrow_index`.
4. Any caller invokes:

```text
update_indexes(caller, [HubAssetKey { hub_id, asset }])
```

5. `update_indexes` reaches `ops::market::accrue`, `global_sync`, and `accrue_step`. [8](#0-7) [5](#0-4) 
6. `scaled_to_original(borrowed_scaled, borrow_index)` overflows `i128` and reverts before the borrow-index cap is relevant. [2](#0-1) [4](#0-3) 
7. Subsequent `repay`, `withdraw`, liquidation settlement, `recapitalize`, and `update_indexes` calls all load a synced market first and fail on the same calculation, leaving the market’s funds frozen. [11](#0-10)

### Citations

**File:** common/src/rates/simulate.rs (L60-69)
```rust
    let borrowed_original = scaled_to_original(env, borrowed, borrow_index);
    let supplied_original = scaled_to_original(env, supplied, supply_index);
    let util = utilization(env, borrowed_original, supplied_original);
    let borrow_rate = calculate_borrow_rate(env, util, params);
    let interest_factor = compound_interest(env, borrow_rate, delta_ms);

    let new_borrow_index = update_borrow_index(env, borrow_index, interest_factor);

    let (supplier_rewards, protocol_fee) =
        calculate_supplier_rewards(env, params, borrowed, new_borrow_index, borrow_index);
```

**File:** common/src/rates/scaling.rs (L12-16)
```rust
/// Converts a scaled `Ray` amount to its original (unscaled) value by
/// multiplying by `index`, rounding half up.
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
}
```

**File:** common/src/rates/index.rs (L13-18)
```rust
pub fn update_borrow_index(env: &Env, old_index: Ray, interest_factor: Ray) -> Ray {
    let new_index = old_index.mul(env, interest_factor);
    if new_index.raw() > MAX_BORROW_INDEX_RAY {
        return Ray::from(MAX_BORROW_INDEX_RAY);
    }
    new_index
```

**File:** contracts/pool/src/interest.rs (L20-32)
```rust
pub(crate) fn global_sync(env: &Env, cache: &mut Cache) {
    if !cache.needs_accrual() {
        return;
    }

    let mut remaining = cache.elapsed_ms();
    while let Some(nonzero) = NonZeroU64::new(remaining) {
        let chunk = nonzero.get().min(MAX_COMPOUND_DELTA_MS);
        accrue_chunk(env, cache, chunk);
        remaining = remaining.saturating_sub(chunk);
    }

    cache.mark_accrued();
```

**File:** contracts/pool/src/ops/mod.rs (L29-47)
```rust
/// Loads a market cache and accrues interest through the current ledger time.
pub(crate) fn synced_market(env: &Env, hub_asset: &HubAssetKey) -> Cache {
    let mut cache = Cache::load(env, hub_asset);
    interest::global_sync(env, &mut cache);
    cache
}

/// Renews instance TTL, then loads and accrues the market.
pub(crate) fn renewed_market(env: &Env, hub_asset: &HubAssetKey) -> Cache {
    renew_instance(env);
    synced_market(env, hub_asset)
}

/// Validates `action.amount ≥ 0`, syncs the market, and returns (cache, scaled position).
pub(crate) fn load_leg(env: &Env, action: &PoolAction) -> (Cache, Ray) {
    require_nonneg_amount(env, action.amount);
    let cache = synced_market(env, &action.hub_asset);
    (cache, Ray::from(action.position.scaled_amount))
}
```

**File:** contracts/controller/src/lib.rs (L367-372)
```rust
    /// Accrues pool borrow and supply indexes for `assets`. Permissionless;
    /// requires caller authorization.
    #[when_not_paused]
    fn update_indexes(env: Env, caller: Address, assets: Vec<HubAssetKey>) {
        markets::update_indexes(&env, caller, assets);
    }
```

**File:** contracts/pool/src/ops/market.rs (L65-72)
```rust
pub(crate) fn accrue(env: &Env, hub_assets: Vec<HubAssetKey>) {
    renew_instance(env);

    for hub_asset in hub_assets.iter() {
        let mut cache = Cache::load(env, &hub_asset);
        interest::global_sync(env, &mut cache);
        events::emit_market_state(env, cache.commit());
    }
```

**File:** common/src/constants/pool.rs (L18-23)
```rust
/// Ceiling the borrow index is clamped to after growth, in raw ray units.
pub const MAX_BORROW_INDEX_RAY: i128 = 1_000_000_000_000_000_000_000_000_000_000_000_000;

/// Ceiling the supply index is clamped to after growth, in raw ray units.
/// Equal to [`MAX_BORROW_INDEX_RAY`].
pub const MAX_SUPPLY_INDEX_RAY: i128 = MAX_BORROW_INDEX_RAY;
```
