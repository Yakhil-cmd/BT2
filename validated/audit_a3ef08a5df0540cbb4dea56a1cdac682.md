### Title
Aquarius LP collateral venue rewards accrue to the pool but can never be claimed or distributed - (File: contracts/pool/src/lib.rs)

### Summary
The pool contract holds Aquarius LP tokens as collateral backing, and those LP positions continuously accrue venue rewards (AQUA emissions / gauge rewards) to the pool's address. The pool has no entrypoint to claim or forward those rewards, and rewards requiring the holder's authorization (gauge claims) cannot be harvested at all, so the yield is permanently locked. Rewards that any caller can permissionlessly push into the pool arrive as unbooked donations that no supply, revenue, or liquidation accounting path attributes to suppliers, so they are also permanently frozen.

### Finding Description
XOXNO Lending accepts Aquarius LP tokens as collateral in hub markets. The physical LP position is held by the pool contract, which is therefore the venue's reward recipient. The pool's public surface exposes only lending flows — `deposit`, `withdraw`, `borrow`, `repay`, `seize_positions`, `claim_revenue`, `recapitalize`, flash entrypoints — with no `claim_rewards`/`harvest`/`forward` entrypoint and no arbitrary-call capability. The protocol's own threat model confirms this: "Aquarius LP collateral earns venue rewards for its holder, which is the pool. The pool has no entrypoint to claim or forward them... Gauge rewards need the pool's authorization and therefore cannot be claimed at all" [1](#0-0) .

Rewards that the venue pushes to the pool without holder auth land as a plain token balance. Direct donations "do not rewrite those books" — market books are tracked separately from physical pool custody [2](#0-1) . The backing check compares floored supplied claims against tracked cash plus debt [3](#0-2) , and revenue payout "cannot exceed tracked cash or the floored revenue claim" [4](#0-3) , so donated reward tokens in a non-listed asset have no claim path at all, and even the LP token itself only pays out against supply/revenue shares, not stray balance. `claim_revenue` routes only the book-tracked revenue claim to the accumulator via the controller [5](#0-4) .

This is the same bug class as the audit finding: a contract that accumulates reward tokens it cannot liquidate or redistribute, with no escape function. Unlike the Tokemak recommendation (add an extra-rewards function), there is no analogous mechanism here.

### Impact Explanation
Permanent freezing of unclaimed yield: every epoch of venue emissions on pooled LP collateral is locked in the pool address forever. Gauge rewards requiring pool authorization are unclaimable from day one; permissionlessly pushable rewards become unbooked donations indistinguishable from stray balance, unclaimable by suppliers, revenue, or liquidators. For markets dominated by LP collateral, the forgone yield grows monotonically with TVL and time.

### Likelihood Explanation
Certain by construction — the rewards accrue automatically to the pool address whenever LP collateral is supplied, which is a normal permissionless `supply` flow any unprivileged user triggers. No privileged action, misconfiguration, or oracle failure is needed; the missing entrypoint guarantees the outcome.

### Recommendation
Add a governed recovery/distribution path on the pool (or routed through the controller), e.g. a `claim_external_rewards(hub_asset, reward_token, receiver)` operation callable via governance `execute`, that either (a) invokes the venue's claim with the pool's authorization and forwards the measured receipt to the accumulator alongside `claim_revenue`, or (b) sweeps non-listed reward token balances. Alternatively, accrue pushed rewards into the market's revenue claim so `claim_revenue` distributes them.

### Proof of Concept
1. Governance lists an Aquarius LP token as a collateral asset in a hub (`CreateLiquidityPool` + `ConfigureAssetOracle`).
2. Alice calls `controller.supply(spoke_id, payments=[(lp_token, amount)])`; the LP tokens move to the pool address.
3. Time passes; the Aquarius venue accrues AQUA/gauge rewards to the pool address as LP holder.
4. Any caller pushes the permissionless reward claim — tokens land in the pool as an unbooked donation (books unchanged, no supply/revenue shares minted). Gauge rewards remain unclaimed because no pool entrypoint authorizes the venue claim.
5. Enumerate the pool's public functions: no claim/harvest/sweep exists; `claim_revenue` only burns book revenue shares bounded by tracked cash; `withdraw` only pays against positions. The reward balance is permanently frozen — matching the documented statement that suppliers "should expect no venue rewards".

### Citations

**File:** docs/explanation/threat-model.md (L129-130)
```markdown
One token listed in several hubs shares physical pool custody even though
market books are separate. Direct donations do not rewrite those books.
```

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

**File:** docs/reference/invariants.md (L128-133)
```markdown
### INV-ACCT-04 — Backing shortfall blocks new supply

New token-funded supply rejects a positive backing shortfall. The check compares
floored supplied claims against tracked cash plus ceiled debt value in native
token units, using saturating arithmetic.

```

**File:** docs/reference/invariants.md (L154-158)
```markdown
### INV-ACCT-06 — Revenue claims respect accounting bounds

Revenue payout cannot exceed tracked cash or the floored revenue claim. Full
payout burns all revenue shares; cash-limited payout burns a proportional
ceiling of shares. Positive payout cannot burn zero shares.
```

**File:** contracts/controller/src/markets.rs (L166-196)
```rust
/// Claims one market's revenue and forwards the measured controller receipt.
/// Requires an accumulator; emits a revenue event only for positive receipts.
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
```
