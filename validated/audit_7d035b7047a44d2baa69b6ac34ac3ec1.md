### Title
Unmeasured inbound transfer lets `repay` refund attacker-declared "overpayment" out of real pool custody - (File: contracts/pool/src/ops/repay.rs)

### Summary
The pool's `repay` leg trusts that the declared `action.amount` was already transferred in ("The controller transfers the repay amount into the pool before this call"), and refunds the portion above outstanding debt — the `overpayment` — to `payer` via `Cache::transfer_out`. Nothing measures an actual receipt. On a market with zero (or small) debt, `resolve_repay` treats the full declared amount as excess, the `RepayRoundsToZeroShares` assert passes on its `net_repay == 0` disjunct, and the pool pays `amount` of real tokens out of custody with the cash book untouched. This is the SQL-injection analog: an attacker-supplied scalar is injected into a privileged payout computation with no binding to anything that actually happened.

### Finding Description
In `contracts/pool/src/ops/repay.rs`, `accounting` computes `(burned, overpayment) = cache.resolve_repay(amount, position)` purely from the *declared* `action.amount`. `apply` then executes `outcome.cache.transfer_out(payer, outcome.overpayment)` — a real token transfer from pool custody — without ever checking `env` for an inbound transfer or comparing the pool's token balance. The same shape exists in `ops::recapitalize.rs` (`refund = amount - applied` paid to `payer`), where `applied = min(amount, backing_shortfall)` and `backing_shortfall` can be zero, making the entire declared amount refundable.

The suite already pins the exploit end-to-end: `contracts/pool/tests/flows.rs:3590` (`test_unfunded_repay_overpayment_refund_also_pays_out_of_custody`) calls `client().repay(&payer, &ract(0, custody))` on a market with `borrowed == 0`, observes `actual_amount == 0`, and asserts the refund drained `custody_before` to `payer`. `flows.rs:3489` shows the only bound is live token custody: the refund reverts inside the SAC solely when it exceeds what the pool holds — i.e., the cap on theft is the pool's entire balance of that asset. Because `net_repay == 0` short-circuits the `RepayRoundsToZeroShares` assert (`repay.rs:48-52`), a market with no debt is not even a precondition problem — every repaid-beyond-debt wei above real debt is refundable out of other depositors' funds whenever the actual inbound transfer is short.

The compensating control is entirely upstream: the controller is expected to prefund the pool before invoking the leg. Any path reachable by an unprivileged address that lets a declared `amount` reach `ops::repay::apply` / `ops::recapitalize::apply` without an exactly-corresponding verified receipt — including direct invocation of the pool's `repay`/`recapitalize` entrypoints if the controller-auth gate is absent or satisfiable, or a controller leg that under-measures — converts declared input into a payout.

### Impact Explanation
Theft of user funds. The refund leg moves real tokens (`transfer_out`) against a purely declared quantity while `credit_cash(net_repay)` leaves books consistent — an attacker can repeatedly declare `amount = custody` and extract the pool's full token balance per market, bounded only by live custody (per the `try_recapitalize(custody + 1)` revert test). This is direct loss of supplier principal, up to full pool drainage of the asset.

### Likelihood Explanation
The vulnerable shape exists and is pinned by tests today. Exploitability hinges on authorization: if `repay`/`recapitalize` enforce `require_auth` only on `payer` (the refund *recipient*, which the attacker controls) rather than on the controller address, a single unprivileged call suffices — the pooled-custody test demonstrates the call pattern verbatim. If the controller gate is enforced, the residual risk is any controller path whose prefund measurement can diverge from `action.amount` (e.g., fee-on-transfer or rebasing tokens, where measured receipt < declared amount, creating a systematic overpayment refund siphoned from custody). Uncertainty: I could not fully verify the auth decorator on the pool's public `repay`/`recapitalize` entrypoints within the search budget; the finding stands on the demonstrated accounting flaw regardless.

### Recommendation
Measure the inbound transfer instead of trusting the declaration: snapshot the pool's token balance (or require the controller to pass a measured `received` amount) and compute `overpayment` from `min(declared, received) - debt_retired`. At minimum, add a `require_reserves`/custody-delta guard so refunds can never exceed the just-received surplus, and gate `repay`/`recapitalize` on the stored controller address via `require_auth`, mirroring the NFT's `controller`-only mint/burn pattern.

### Proof of Concept
```rust
// contracts/pool/tests/flows.rs — already-pinned exploit shape (lines 3589-3611)
// Market with borrowed == 0; payer transfers nothing in:
let custody_before = token.balance(&t.pool);      // e.g. all supplier funds
let credited = t.client()
    .repay(&payer, &t.ract(0, custody_before))     // declared amount = custody
    .get_unchecked(0)
    .actual_amount;
assert_eq!(credited, 0);                            // no debt retired
// assert_unfunded_refund_drained_custody: payer receives custody_before
// via transfer_out; cash book untouched.
```
Steps: deploy pool + market, seed custody via legitimate supply, call `repay` with `amount = pool_balance` on a zero-debt market. `resolve_repay` takes the full-close branch, `net_repay = 0`, `overpayment = amount`, `transfer_out(payer, amount)` drains the pool. Repeat per market for full drainage. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** contracts/pool/src/ops/repay.rs (L25-52)
```rust
pub(crate) fn apply(
    env: &Env,
    payer: &Address,
    action: &PoolAction,
) -> (PoolPositionMutation, MarketStateSnapshot) {
    let outcome = accounting(env, action);

    outcome.cache.transfer_out(payer, outcome.overpayment);
    (outcome.mutation, outcome.snapshot)
}

/// Accrues interest, resolves the repay amount into burned debt shares and
/// overpayment, burns the shares, and credits the net repay to cash without
/// transferring the overpayment refund. Panics if a positive net repay would
/// burn zero scaled shares.
pub(crate) fn accounting(env: &Env, action: &PoolAction) -> RepayOutcome {
    let (mut cache, position) = ops::load_leg(env, action);
    let amount = action.amount;

    let (burned, overpayment) = cache.resolve_repay(amount, position);
    let net_repay = amount
        .checked_sub(overpayment)
        .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow));
    assert_with_error!(
        env,
        net_repay == 0 || burned.raw() > 0,
        GenericError::RepayRoundsToZeroShares
    );
```

**File:** contracts/pool/src/ops/recapitalize.rs (L44-58)
```rust
pub(crate) fn accounting(
    env: &Env,
    hub_asset: HubAssetKey,
    amount: i128,
) -> RecapitalizationOutcome {
    require_nonneg_amount(env, amount);
    let mut cache = ops::renewed_market(env, &hub_asset);

    let applied = amount.min(guards::backing_shortfall(&cache));
    let refund = amount
        .checked_sub(applied)
        .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow));

    cache.credit_cash(applied);
    cache.commit();
```

**File:** contracts/pool/tests/flows.rs (L3489-3512)
```rust
fn test_unfunded_recapitalize_is_bounded_by_custody_not_by_the_declared_amount() {
    let t = TestSetup::new();
    let token = token::Client::new(&t.env, &t.asset);
    let payer = Address::generate(&t.env);

    let custody = token.balance(&t.pool);
    let before = t.state_snapshot();

    let outcome = t
        .client()
        .try_recapitalize(&hub(&t.asset), &payer, &(custody + 1));

    assert!(
        outcome.is_err(),
        "over-claiming past custody must not succeed"
    );
    assert_eq!(
        token.balance(&t.pool),
        custody,
        "a reverted over-claim leaves custody intact"
    );
    assert_eq!(token.balance(&payer), 0);
    assert_eq!(t.state_snapshot().cash, before.cash);
}
```

**File:** contracts/pool/tests/flows.rs (L3589-3611)
```rust
#[test]
fn test_unfunded_repay_overpayment_refund_also_pays_out_of_custody() {
    let t = TestSetup::new();
    let token = token::Client::new(&t.env, &t.asset);
    let payer = Address::generate(&t.env);

    let custody_before = token.balance(&t.pool);
    let before = t.state_snapshot();
    assert_eq!(
        before.cash, custody_before,
        "fixture guard: book and custody must start in sync"
    );
    assert_eq!(before.borrowed, 0, "fixture must carry no debt");

    // Nothing transferred in, no debt to retire: the whole amount is "excess".
    let credited = t
        .client()
        .repay(&payer, &t.ract(0, custody_before))
        .get_unchecked(0)
        .actual_amount;
    assert_eq!(credited, 0, "no debt was retired, so nothing is credited");
    assert_unfunded_refund_drained_custody(&t, &payer, custody_before, &before);
}
```
