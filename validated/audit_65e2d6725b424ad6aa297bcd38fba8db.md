### Title
Tokens held by the controller are permanently locked — no sweep or rescue mechanism exists - (File: contracts/controller/src/markets.rs)

### Summary
Analogous to H-01 (a contract receiving funds it has no code to move), the XOXNO Lending `controller` contract can hold token balances it can never release. The controller is a legitimate token recipient — pool `claim_revenue` pays the owner (the controller), strategy callbacks (`flash_position`, `multiply`, `swap_debt`, `swap_collateral`, `repay_debt_with_collateral`, `migrate_from_blend`) deliver tokens to it, and any user can transfer tokens directly to it — yet no controller entrypoint can transfer tokens out except tightly-scoped, measured forwards inside an operation. Any residual balance is permanently stranded.

### Finding Description
The controller's outbound token movements are all inside measured flows:

- `claim_revenue_for_asset` measures only the balance delta produced by `pool_claim_revenue_call` (`balance_delta_since`) and forwards exactly `received` to the accumulator — a pre-existing controller balance is deliberately untouched [1](#0-0) . The pinned test asserts `controller dust must be untouched` [2](#0-1) .
- Strategy finalization refunds only positive callback deltas of refund-listed tokens; "Undeclared callback assets receive neither credit nor refunds. There is no controller sweep endpoint." [3](#0-2) .
- `repay`/`recapitalize` refunds come from the *pool*, not the controller; `supply`/`repay` push tokens into the pool; no path pulls tokens out of the controller's own balance [4](#0-3) .

Because the controller never invokes a bare `token.transfer` from its own balance outside those bounded flows, and governance cannot call an arbitrary controller function that transfers tokens, any of the following become frozen forever:

- Tokens any address transfers directly to the controller contract address.
- Undeclared assets a `flash_position`/strategy callback or router leg deposits at the controller (receiver contracts are arbitrary deployed Wasm).
- Dust residuals left when a measured flow under-delivers or a taxed forward transfer leaves change at the controller.

### Impact Explanation
Permanent freezing of funds. Tokens at the controller have no reachable withdrawal path for any caller (unprivileged or privileged); only a contract `upgrade` could add a rescue function — the same "locked until upgraded" impact class as the reference finding. Residuals are also non-accidental: the protocol's own tests leave a `100_000_000_000` stranded dust balance at the controller and prove it is never recoverable [5](#0-4) .

### Likelihood Explanation
High for accumulation: every permissionless user can send tokens to the controller, and every strategy/flash callback can leave undeclared tokens there through normal use; taxed or partially-delivering tokens can leave remainder balances on each hop. Severity Medium: each strand is user- or callback-driven rather than a drain of booked user deposits, but the funds are unrecoverable by design of the deployed code.

### Recommendation
Add a governance-gated rescue/sweep entrypoint on the controller that transfers a specified `asset`/`amount`/`to`, restricted so it cannot touch balances owed to flows in progress (the flash guard already prevents mid-flow re-entry). Alternatively, refund assets by measuring the controller's absolute balance rather than only the positive callback delta so undeclared leftovers can be swept through an existing refund path.

### Proof of Concept
1. Any address calls `token.transfer(user, controller_addr, amount)` on a listed or arbitrary token (explicitly allowed scope: "direct token transfers to the pool or controller").
2. Inspect the controller: `token.balance(controller)` increases by `amount`.
3. Enumerate the controller ABI (`docs/reference/endpoints.md`, `scripts/permissionless_entrypoints.txt`): `supply`, `repay`, `recapitalize`, `claim_revenue`, flash and strategy entrypoints all either push tokens to the *pool* or forward only measured per-call deltas. No entrypoint moves a pre-existing controller token balance.
4. `claim_revenue` provably leaves the balance: `claim_revenue_for_asset` snapshots `before`, forwards only `received`, and the harness test `claim_revenue_forwards_the_measured_amount_and_leaves_controller_dust_intact` asserts a `100_000_000_000` pre-seeded controller balance is unchanged afterward.
5. Result: the tokens sit at the controller permanently; recovery requires a Wasm `upgrade`, exactly the lock-up the reference report describes.

### Citations

**File:** contracts/controller/src/markets.rs (L141-164)
```rust
/// shortfall, and refunds unused funds. Returns credited cash; rejects flash loans.
pub(crate) fn recapitalize(
    env: &Env,
    payer: Address,
    hub_asset: HubAssetKey,
    amount: i128,
) -> i128 {
    validation::require_authorized_caller(env, &payer);
    require_positive_amount(env, amount);

    let mut cache = Context::new(env);
    let pool_addr = cache.cached_pool_address();
    // Prefund the pool and credit only its measured receipt.
    let received = payments::transfer_amount_measured(
        env,
        &hub_asset.asset,
        &payer,
        &pool_addr,
        amount,
        GenericError::AmountMustBePositive,
    );

    pool_recapitalize_call(env, &pool_addr, &hub_asset, &payer, received).actual_amount
}
```

**File:** contracts/controller/src/markets.rs (L179-196)
```rust
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

**File:** tests/test-harness/tests/controller/outbound_transfer_measurement.rs (L126-151)
```rust
    let dust = 100_000_000_000i128;
    weird.mint(&controller, &dust);
    let controller_before = tok.balance(&controller);

    let claimed = t.claim_revenue("USDC");
    // Captured before the balance reads below: `events().all()` is scoped to
    // the last contract invocation, and every `tok.balance` call is one.
    let claim_events = t.env.events().all();
    assert!(
        claimed > 0,
        "a positive claim is what makes this observable"
    );

    let accumulator_got = tok.balance(&accumulator);
    let controller_after = tok.balance(&controller);

    assert_eq!(
        accumulator_got,
        claimed - claimed / 100,
        "accumulator receives one forward-hop haircut less than the measured claim"
    );

    assert_eq!(
        controller_after, controller_before,
        "controller dust must be untouched, before={controller_before} after={controller_after}"
    );
```

**File:** docs/reference/endpoints.md (L84-86)
```markdown
Refund assets must be unique, listed in the debt hub and account spoke, disjoint from collateral declarations, and bounded by the maximum supply-position count. Refund eligibility requires an active spoke and an existing listing; it does not check collateralizable, borrowable, paused or frozen flags. Only positive balance changes above pre-callback balances return to the caller. The debt token can be a refund asset, but refunding it does not repay the minted debt.

Undeclared callback assets receive neither credit nor refunds. There is no controller sweep endpoint. Refunds produce token transfer events, without a dedicated controller refund event.
```
