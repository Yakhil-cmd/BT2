### Title
Tokens transferred directly to the controller are permanently locked — the contract only ever spends same-call balance deltas (File: contracts/controller/src/payments.rs)

### Summary
The original report's bug class — funds sent to a contract on a path that does not use them being locked forever — maps directly onto the XOXNO controller. The controller is a token-holding contract (it receives revenue, flash collateral pushes, and repay legs), but every outbound token path in it is *delta-scoped*: it only ever moves the balance increase measured inside the current call. There is no sweep, skim, or rescue entrypoint. Any token transferred directly to the controller address by an unprivileged user — a plain SAC `transfer` — becomes part of the "pre-existing balance" that every refund and forwarding helper explicitly preserves, and can never leave.

### Finding Description
The controller's only generic refund primitive is `refund_controller_balance_delta` in `contracts/controller/src/payments.rs:41-52`, which computes `balance_delta_since(env, asset, &controller, balance_before)` and transfers *only* the excess over the pre-call balance back to the caller. The docstring is explicit: "Refunds only the controller balance increase since `balance_before`, **preserving the pre-existing balance**". [1](#0-0) 

Revenue forwarding in `claim_revenue_for_asset` works the same way: it snapshots `before`, calls `pool_claim_revenue_call`, and forwards to the accumulator only `received = balance_delta_since(...)`, leaving any pre-existing controller balance untouched. [2](#0-1) 

A grep of `contracts/controller/` for `sweep|skim|stray|donat` finds no recovery function; the swap-aggregator has `sweep_balance` (`contracts/swap-aggregator/src/lib.rs:188-203`), but the controller does not. The protocol's own integration test proves the lock: in `tests/integration/flows/flash_position.sh:354-372`, the harness donates USDC and XLM directly to the controller, runs a full `flash_position` flow, and asserts the donated balances are *unchanged* afterward ("`refund_protected`", "`fp_protected_xlm_seed`" — controller balance delta asserted to be exactly 0). The protection is deliberate for in-flight deltas, but it means externally donated tokens have no exit path: every helper is designed to not touch them.

### Impact Explanation
Permanent freezing of funds. A user (or integrated contract) that transfers any SAC asset directly to the controller address — e.g., repaying debt "the OpenQ way" by pushing tokens, or pre-funding what they believe is a settlement address — loses those tokens forever. They are not credited to any account, not added to pool `cash` (the pool credits `cash` only on the controller's word via `supply`/`repay`/`recapitalize`, never reconciling `token.balance()` except inside `flash_loan`), and no entrypoint can move them: `claim_revenue` forwards only same-call deltas, refund helpers preserve the baseline, and there is no admin sweep. Severity Medium: it requires a user mistake (direct transfer instead of calling `repay`/`supply`), but the loss is total and unrecoverable, matching the original finding's Medium rating.

### Likelihood Explanation
Likelihood is moderate rather than hypothetical: the controller is the public-facing contract of the protocol (pool entrypoints are `#[only_owner]` and unreachable), so it is the address integrators and users interact with and see in explorers and events. The test suite itself demonstrates the pattern — `sac_transfer ... $CONTROLLER` is a supported operation any wallet can perform, and receiver contracts that push collateral to the controller during `flash_position` could over-push beyond declared refunds. Unlike the swap-aggregator, which added `sweep_balance` precisely because stray balances accumulate on a token-holding router, the controller has no equivalent.

### Recommendation
Add an owner/accumulator-gated sweep or, better, route stray balances into existing accounting: e.g., let `claim_revenue` or a dedicated `skim` entrypoint forward `token.balance(controller) - reserved` for each market asset to the accumulator or to the pool via `recapitalize`. Alternatively, document and emit events so off-chain tooling warns users never to transfer directly, and consider a `sweep_balance`-style function mirroring `swap-aggregator/src/lib.rs:188-203`.

### Proof of Concept
1. Deploy controller/pool with a USDC market; Alice supplies via the normal `supply` path.
2. Bob (unprivileged) calls `token.transfer(bob, controller, 1_000_000)` on the USDC SAC — a plain direct transfer, explicitly an in-scope action.
3. Invoke every reachable exit path: `controller.claim_revenue(caller, [hub_asset])` forwards only the delta produced by `pool_claim_revenue_call` (markets.rs:186-196); `flash_position` refunds only declared assets and only the in-call delta (payments.rs:41-51, asserted by `refund_protected` at flash_position.sh:371-372).
4. `token.balance(controller)` still shows the 1_000_000; no entrypoint — including all sixteen unprivileged-reachable controller functions and governance `execute` — can move it. The donation is permanently locked, exactly the reported bug class.

### Citations

**File:** contracts/controller/src/payments.rs (L39-51)
```rust
/// Refunds only the controller balance increase since `balance_before`,
/// preserving the pre-existing balance; no-op for a nonpositive delta.
pub(crate) fn refund_controller_balance_delta(
    env: &Env,
    asset: &Address,
    balance_before: i128,
    refund_to: &Address,
) {
    let controller = env.current_contract_address();
    let excess = balance_delta_since(env, asset, &controller, balance_before);
    if excess > 0 {
        token::Client::new(env, asset).transfer(&controller, refund_to, &excess);
    }
```

**File:** contracts/controller/src/markets.rs (L180-196)
```rust
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
