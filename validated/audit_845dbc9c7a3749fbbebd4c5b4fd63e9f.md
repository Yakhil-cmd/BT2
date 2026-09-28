The analog exists: the pool's unconditional post-burn guards can revert a revenue claim based on market state outside the caller's control — same shape as `SetWithdrawAddress` failing when `WithdrawAddrEnabled = false`. Let me confirm the guard code.### Title
Unconditional post-burn solvency guards can permanently block `claim_revenue`, freezing accrued protocol yield - (File: contracts/pool/src/ops/revenue.rs)

### Summary
The permissionless `controller.claim_revenue(caller, assets)` path always invokes the pool's `claim_revenue`, which burns revenue shares first and then unconditionally runs `require_utilization_below_max` and `require_supply_for_debt`. Because burning revenue decreases `supplied`, the claim itself pushes utilization up, and there is no way for the caller to request a smaller (passing) amount — the claim size is fixed at `min(cash, floor(revenue_value))`. When market utilization is at or above `max_utilization` (a state entirely outside the caller's control), every claim reverts and accrued revenue is frozen. This mirrors the reported class: a required intermediate step (`MsgSetWithdrawAddress` / the post-burn guard) fails under external configuration/market state, taking the whole claim down with it.

### Finding Description
`ops::revenue::accounting` performs the burn before the guard checks:

```rust
// contracts/pool/src/ops/revenue.rs:39-48
let net_transfer = cache.burn_claimable_revenue();
guards::require_utilization_below_max(env, &cache);
guards::require_supply_for_debt(env, &cache);
cache.debit_cash(net_transfer);
``` [1](#0-0) 

`burn_claimable_revenue` computes `amount = min(cash, treasury_actual)` and burns `revenue` pro-rata, decreasing `supplied` by the same scaled amount. There is no caller-supplied amount to reduce the burn. [2](#0-1) 

`require_utilization_below_max` reverts with `UtilizationAboveMax` when `ceil(borrowed·borrow_index) / floor(supplied·supply_index) > max_utilization` — and the just-executed burn lowers `supplied`, raising utilization. [3](#0-2) 

`require_supply_for_debt` reverts with `PoolInsolvent` whenever the burn drives `supplied` to zero while debt remains — i.e., a market whose entire supply has been converted to revenue shares can never claim. [4](#0-3) 

The entrypoint is permissionless: `Controller::claim_revenue` only requires the caller's own auth (`markets::claim_revenue` → `require_authorized_caller`), then calls `pool_claim_revenue_call` per asset, so any revert in the pool propagates and fails the whole transaction. [5](#0-4) [6](#0-5) 

A test already encodes the failure: `test_claim_revenue_rejects_utilization_above_max_after_revenue_burn` shows a 100/90-supplied market with `max_utilization = 0.95` reverting on claim even though the burn itself is only 10 shares of revenue. [7](#0-6) 

### Impact Explanation
Accrued protocol revenue cannot be withdrawn while utilization is above (or driven above) the market ceiling by the claim. Since new borrows are blocked at `max_utilization` but interest keeps accruing on outstanding debt, a market can sit above the cap indefinitely — especially in high-rate or distressed markets where borrowers do not repay. The yield stays locked in the pool as revenue shares (`burn_claimable_revenue` leaves the unclaimed remainder earning, but unreachable). This is freezing of unclaimed yield, reachable by any unprivileged caller via `claim_revenue`. In the extreme `supplied → 0` case (`require_supply_for_debt`), a partial claim could pass while the forced full claim always reverts.

### Likelihood Explanation
Utilization at/above `max_utilization` is a normal, expected market state — it is precisely the state the borrow-side guard is designed to create. No privileged or adversarial precondition is needed beyond ordinary interest accrual on existing debt. Once in that state, every `claim_revenue` call for that market reverts until borrowers repay or fresh supply arrives, and no caller-side workaround exists because the claim amount is not configurable (batching other markets does not help; one failing market reverts the batch, but the failing market itself can never be claimed). Severity: Medium — temporary freezing of unclaimed yield with no in-protocol recovery path for the affected market.

### Recommendation
Two complementary fixes, analogous to the report's `ReplyOn.Error` suggestion of not letting an optional step sink the whole call:

1. In `ops::revenue::accounting`, cap `net_transfer` so the post-claim state still satisfies `require_utilization_below_max` (i.e., limit the share burn to the largest amount that keeps `ceil(borrowed·borrow_index) / floor((supplied − burned)·supply_index) ≤ max_utilization`), instead of reverting on the full claim.
2. If capping is undesirable, run the utilization/solvency guards against the *pre-claim* cache and only block claims that would newly breach a guard, or skip `require_supply_for_debt` for revenue burns since revenue is a subset of protocol-owned supply, not user claims.

### Proof of Concept
```text
1. Market: supplied = 100 RAY, borrowed = 90 RAY, revenue = 10 RAY,
   cash = 10 tokens, max_utilization = 0.95, indexes = RAY.
   (Exactly the state in test_claim_revenue_rejects_utilization_above_max_after_revenue_burn,
   contracts/pool/tests/flows.rs:1739.)
2. Any unprivileged user calls
   controller.claim_revenue(caller, [hub_asset])  // caller.require_auth only
3. Pool burns 10 RAY of revenue shares -> supplied becomes 90 RAY.
   utilization = ceil(90) / floor(90) = 1.0 > 0.95
   -> require_utilization_below_max panics (UtilizationAboveMax).
4. Every subsequent call reverts while utilization stays > 0.95;
   revenue shares and their yield remain locked in the pool.
```

### Citations

**File:** contracts/pool/src/ops/revenue.rs (L39-55)
```rust
pub(crate) fn accounting(env: &Env, hub_asset: HubAssetKey) -> RevenueOutcome {
    let mut cache = ops::renewed_market(env, &hub_asset);

    let net_transfer = cache.burn_claimable_revenue();

    guards::require_utilization_below_max(env, &cache);
    guards::require_supply_for_debt(env, &cache);
    cache.debit_cash(net_transfer);

    cache.commit();
    RevenueOutcome {
        cache,
        mutation: PoolAmountMutation {
            actual_amount: net_transfer,
        },
    }
}
```

**File:** contracts/pool/src/cache/shares.rs (L54-75)
```rust
    pub(crate) fn burn_claimable_revenue(&mut self) -> i128 {
        let treasury_actual = self.unscale_supply_floor(self.revenue);
        let amount = self.cash.min(treasury_actual);
        if amount <= 0 {
            return 0;
        }
        let scaled_to_burn = if amount >= treasury_actual {
            self.revenue
        } else {
            self.revenue
                .mul_ratio_ceil(&self.env, amount, treasury_actual)
        };

        assert_with_error!(
            self.env,
            scaled_to_burn != Ray::ZERO,
            GenericError::InternalError
        );
        self.revenue = self.revenue.checked_sub(&self.env, scaled_to_burn);
        self.supplied = self.supplied.checked_sub(&self.env, scaled_to_burn);
        amount
    }
```

**File:** contracts/pool/src/guards.rs (L19-34)
```rust
pub(crate) fn require_utilization_below_max(env: &Env, cache: &Cache) {
    if cache.supplied() == Ray::ZERO || cache.params().max_utilization >= Ray::ONE {
        return;
    }

    let borrowed = cache.borrowed().mul_ceil(env, cache.borrow_index());
    if borrowed == Ray::ZERO {
        return;
    }
    let supplied = cache.supplied().mul_floor(env, cache.supply_index());
    assert_with_error!(
        env,
        supplied > Ray::ZERO && borrowed.div_ceil(env, supplied) <= cache.params().max_utilization,
        CollateralError::UtilizationAboveMax
    );
}
```

**File:** contracts/pool/src/guards.rs (L69-73)
```rust
pub(crate) fn require_supply_for_debt(env: &Env, cache: &Cache) {
    if cache.supplied() == Ray::ZERO && cache.borrowed() != Ray::ZERO {
        panic_with_error!(env, CollateralError::PoolInsolvent);
    }
}
```

**File:** contracts/controller/src/markets.rs (L129-137)
```rust
pub(crate) fn claim_revenue(env: &Env, caller: Address, assets: Vec<HubAssetKey>) -> Vec<i128> {
    validation::require_authorized_caller(env, &caller);
    let mut results = Vec::new(env);
    let mut cache = Context::new(env);
    for hub_asset in assets {
        let amount = claim_revenue_for_asset(env, &caller, &hub_asset, &mut cache);
        results.push_back(amount);
    }
    results
```

**File:** contracts/controller/src/markets.rs (L168-209)
```rust
fn claim_revenue_for_asset(
    env: &Env,
    caller: &Address,
    hub_asset: &HubAssetKey,
    cache: &mut Context,
) -> i128 {
    let accumulator = storage::try_get_accumulator(env)
        .unwrap_or_else(|| panic_with_error!(env, OracleError::NoAccumulator));

    let pool_addr = cache.cached_pool_address();

    // Measure custody receipts before forwarding inexact-delivery tokens (INV-ACCT-03).
    let controller = env.current_contract_address();
    let asset = &hub_asset.asset;
    let before = token::Client::new(env, asset).balance(&controller);

    let _ = pool_claim_revenue_call(env, &pool_addr, hub_asset);

    let received = balance_delta_since(env, asset, &controller, before);

    if received > 0 {
        payments::transfer_amount_measured(
            env,
            asset,
            &controller,
            &accumulator,
            received,
            GenericError::AmountMustBePositive,
        );

        events::ClaimRevenueEvent {
            hub_id: hub_asset.hub_id,
            asset: asset.clone(),
            caller: caller.clone(),
            accumulator,
            amount: received,
        }
        .publish(env);
    }

    received
}
```

**File:** contracts/pool/tests/flows.rs (L1739-1759)
```rust
#[test]
fn test_claim_revenue_rejects_utilization_above_max_after_revenue_burn() {
    let t = TestSetup::new();
    let client = t.client();

    t.env.as_contract(&t.pool, || {
        let key = PoolKey::Params(hub(&t.asset));
        let mut params: MarketParamsRaw = t.env.storage().persistent().get(&key).unwrap();
        params.max_utilization = RAY * 95 / 100;
        t.env.storage().persistent().set(&key, &params);
    });
    t.edit_state(|state| {
        state.supplied = 100 * RAY;
        state.borrowed = 90 * RAY;
        state.revenue = 10 * RAY;
        state.cash = 10_0000000i128;
    });

    let result = flatten_contract_result(client.try_claim_revenue(&hub(&t.asset)));
    assert_contract_error(result, CollateralError::UtilizationAboveMax as u32);
}
```
