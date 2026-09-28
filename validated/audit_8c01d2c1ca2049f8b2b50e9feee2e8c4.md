### Title
`claim_revenue` always reverts until `set_accumulator()` is called — (File: contracts/controller/src/markets.rs)

### Summary
The `claim_revenue` entrypoint is callable by any address, but `claim_revenue_for_asset` unconditionally loads the accumulator address and panics with `OracleError::NoAccumulator` when it has never been configured [1](#0-0) . This is the same bug class as TRST-H-6: a core permissionless path hard-reverts purely because a storage variable was never initialized, and stays broken until an owner calls a setter (`set_accumulator`).

### Finding Description
`claim_revenue(env, caller, assets)` requires only caller authorization — it is permissionless [2](#0-1) . For every requested `HubAssetKey` it calls `claim_revenue_for_asset`, which does:

```rust
let accumulator = storage::try_get_accumulator(env)
    .unwrap_or_else(|| panic_with_error!(env, OracleError::NoAccumulator));
``` [1](#0-0) 

The accumulator lookup happens *before* the pool claim, so `pool_claim_revenue_call` is never reached [3](#0-2) . `set_accumulator` is an owner-only administration entrypoint [4](#0-3) , and unlike `min_borrow_collateral_usd`, which falls back to `DEFAULT_MIN_BORROW_COLLATERAL_USD_WAD` when unset [5](#0-4) , the accumulator has no default — zero-state reverts unconditionally.

### Impact Explanation
Until the owner configures an accumulator, every `claim_revenue` call reverts, so accrued protocol revenue cannot be claimed or forwarded by anyone — a temporary freezing of unclaimed yield gated entirely on an administrative action. Unlike the mitigated TRST-H-6 shape (requirement skipped when the config value is zero), there is no fallback path here: the panic fires before any revenue is moved.

### Likelihood Explanation
Any deployment where `set_accumulator` has not yet been called — a normal, valid protocol state since nothing forces accumulator configuration at init or at `create_liquidity_pool` — exhibits the failure on the very first `claim_revenue` call. It requires no attacker action; a single unprivileged caller with any non-empty `assets` vector triggers it.

### Recommendation
Either default-forward revenue (e.g., retain it at the controller or send to a governance-set default sink) when `try_get_accumulator` returns `None`, mirroring the TRST-H-6 fix pattern of making the unset state benign, or require/emit a warning-free accumulator at initialization so the permissionless claim path is never unreachable.

### Proof of Concept
1. Deploy controller, deploy pool, create a hub and a liquidity pool market; do **not** call `set_accumulator`.
2. Have any address supply and borrow to accrue revenue shares.
3. Call `claim_revenue(caller, [hub_asset])` from any address — it reverts with `NoAccumulator` at `markets.rs:175` before the pool's `claim_revenue` executes, regardless of how much revenue has accrued.

### Citations

**File:** contracts/controller/src/markets.rs (L129-134)
```rust
pub(crate) fn claim_revenue(env: &Env, caller: Address, assets: Vec<HubAssetKey>) -> Vec<i128> {
    validation::require_authorized_caller(env, &caller);
    let mut results = Vec::new(env);
    let mut cache = Context::new(env);
    for hub_asset in assets {
        let amount = claim_revenue_for_asset(env, &caller, &hub_asset, &mut cache);
```

**File:** contracts/controller/src/markets.rs (L174-175)
```rust
    let accumulator = storage::try_get_accumulator(env)
        .unwrap_or_else(|| panic_with_error!(env, OracleError::NoAccumulator));
```

**File:** contracts/controller/src/markets.rs (L177-186)
```rust
    let pool_addr = cache.cached_pool_address();

    // Measure custody receipts before forwarding inexact-delivery tokens (INV-ACCT-03).
    let controller = env.current_contract_address();
    let asset = &hub_asset.asset;
    let before = token::Client::new(env, asset).balance(&controller);

    let _ = pool_claim_revenue_call(env, &pool_addr, hub_asset);

    let received = balance_delta_since(env, asset, &controller, before);
```

**File:** contracts/controller/README.md (L141-143)
```markdown
| `set_swap_aggregator` | `fn set_swap_aggregator(env: Env, addr: Address)` | owner-only | Sets the swap aggregator contract address used by strategy swaps. |
| `set_price_aggregator` | `fn set_price_aggregator(env: Env, addr: Address)` | owner-only | Sets the price aggregator contract address used for oracle lookups. |
| `set_accumulator` | `fn set_accumulator(env: Env, addr: Address)` | owner-only | Sets the accumulator address that receives claimed protocol revenue. |
```

**File:** contracts/controller/tests/governance/config.rs (L231-240)
```rust
#[test]
fn min_borrow_floor_reads_the_default_when_unset() {
    let env = Env::default();
    let contract = new_controller(&env);
    env.as_contract(&contract, || {
        assert_eq!(
            storage::get_min_borrow_collateral_usd_wad(&env),
            crate::constants::DEFAULT_MIN_BORROW_COLLATERAL_USD_WAD
        );
    });
```
