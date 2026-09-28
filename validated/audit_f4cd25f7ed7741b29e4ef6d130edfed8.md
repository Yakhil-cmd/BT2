### Title
Aquarius LP collateral venue and gauge rewards are permanently unclaimable — no pool entrypoint exists to claim or forward them - (File: contracts/pool/src/lib.rs)

### Summary
The pool contract physically holds Aquarius LP tokens supplied as collateral. Aquarius venue rewards and gauge rewards accrue to the LP holder — the pool address — but the pool ABI exposes no entrypoint to claim, sweep, or forward any reward token. The only outbound token paths (`withdraw`, `borrow`, `repay` refunds, `claim_revenue`, `flash_loan`, `create_strategy`) move the market's own `asset`, never arbitrary reward tokens. Gauge rewards additionally require the holder's authorization, which the pool can never produce off-contract, so they are locked permanently.

### Finding Description
The threat model itself states the shape: "Aquarius LP collateral earns venue rewards for its holder, which is the pool. The pool has no entrypoint to claim or forward them... Gauge rewards need the pool's authorization and therefore cannot be claimed at all" [1](#0-0) . The full pool surface confirms no generic sweep or claim exists: `claim_revenue` only burns revenue shares and transfers the market asset to the owner [2](#0-1) , and all other mutators are enumerated in the pool ABI with no reward-claim or token-rescue function [3](#0-2) . This is the exact analog of the reported class: rewards accrue to the contract holding the underlying funds, with no mechanism to call the venue's claim functions.

### Impact Explanation
Unclaimed yield is permanently frozen. Any user supplying Aquarius LP tokens as collateral generates venue rewards attributable to the pool balance; gauge-type rewards requiring holder authorization can never be claimed by anyone, so they are lost forever rather than merely delayed. Free rewards that any caller can push to the pool become unbooked donations — they sit in the pool's token balance outside the `cash` ledger and are never credited to suppliers or revenue. This matches "theft or freezing of unclaimed yield": a quantifiable, growing loss proportional to LP-collateral TVL and reward emission rates.

### Likelihood Explanation
Certain wherever Aquarius LP tokens are listed as collateral and the underlying venues emit rewards — no attacker action is needed; the loss accrues automatically through ordinary `supply` usage. The magnitude depends on how much LP collateral the protocol attracts and the emission rate of the venues, so the practical severity is Medium: real and permanent, but bounded to forgone yield rather than principal.

### Recommendation
Add an owner-gated pool (or controller-routed) entrypoint that either (a) calls the venue's `claim`/`claim_rewards` with the pool as claimant and forwards the measured receipt to the accumulator or suppliers, or (b) sweeps arbitrary non-market reward tokens held by the pool to the accumulator, guarded so listed market assets cannot be swept below their booked `cash`/backing requirements.

### Proof of Concept
1. Governance lists an Aquarius LP share token as collateral; `Alice` calls `controller.supply` with that LP token — the pool now holds the LP position.
2. Time passes; the Aquarius pool/gauge accrues rewards to the pool address.
3. Any caller invoking `pool.claim_revenue(hub_asset)` only receives the market asset's revenue shares (`burn_claimable_revenue` → `transfer_out` of the market asset), never reward tokens [4](#0-3) .
4. Gauge rewards remain permanently locked since claiming requires the pool's own authorization, which no entrypoint produces; pushable rewards become unbooked donations increasing `token.balance(pool)` without any crediting path [1](#0-0) .

### Citations

**File:** docs/explanation/threat-model.md (L134-140)
```markdown
Aquarius LP collateral earns venue rewards for its holder, which is the pool.
The pool has no entrypoint to claim or forward them. The venue's reward claim
did not require the holder's authorization when reviewed (mainnet simulation,
2026-09), so any caller can push accrued rewards into the pool address as an
unbooked donation. Gauge rewards need the pool's authorization and therefore
cannot be claimed at all. Suppliers of LP collateral should expect no venue
rewards; this is forgone yield, not a loss of principal.
```

**File:** contracts/pool/src/ops/revenue.rs (L22-34)
```rust
pub(crate) fn apply(env: &Env, hub_asset: HubAssetKey) -> PoolAmountMutation {
    let outcome = accounting(env, hub_asset);

    if outcome.mutation.actual_amount != 0 {
        let owner = ownable::get_owner(env)
            .unwrap_or_else(|| panic_with_error!(env, GenericError::OwnerNotSet));
        outcome
            .cache
            .transfer_out(&owner, outcome.mutation.actual_amount);
    }

    events::emit_market_state(env, outcome.cache.snapshot());
    outcome.mutation
```

**File:** contracts/pool/src/ops/revenue.rs (L39-48)
```rust
pub(crate) fn accounting(env: &Env, hub_asset: HubAssetKey) -> RevenueOutcome {
    let mut cache = ops::renewed_market(env, &hub_asset);

    let net_transfer = cache.burn_claimable_revenue();

    guards::require_utilization_below_max(env, &cache);
    guards::require_supply_for_debt(env, &cache);
    cache.debit_cash(net_transfer);

    cache.commit();
```

**File:** contracts/pool/README.md (L66-82)
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
