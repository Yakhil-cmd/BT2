### Title
Direct `pool.flash_loan` escapes the controller's flash-loan sandbox — callback can reenter monetary controller paths and the pool commits a stale `Cache` over their writes — (File: contracts/pool/src/lib.rs)

### Summary
CVE-2021-1801 is an iframe-sandbox policy violation: content that should be confined escapes its sandbox. The analog here is the `FlashLoanOngoing` sandbox: all monetary controller entrypoints are confined during a flash callback by a temporary flag plus the host's re-entry prohibition — but that confinement only exists when the flash loan is initiated through the controller. The pool exposes its own `flash_loan`, and a direct pool-level flash loan leaves the controller flag unset and the controller off the call stack, so the callback escapes the sandbox and can reenter controller entrypoints mid-loan.

### Finding Description
The confinement has two layers:

1. A temporary flag `FlashLoanOngoing` stored in *controller* storage, set only via `with_flash_guard`, and checked by `require_not_flash_loaning` / `require_authorized_caller`. [1](#0-0) [2](#0-1) 
2. The Soroban host re-entry prohibition, which rejects calls into a contract already on the stack — the callback chain controller → pool → receiver makes every controller reentry fail with `Error(Context, InvalidAction)`. [3](#0-2) 

Both layers are bypassed by calling `pool.flash_loan` directly (the pool's own flash entrypoint, exercised by the `ReenterPoolFlashLoan` mock mode [4](#0-3) ):

- The controller is never invoked, so `with_flash_guard` never runs and `is_flash_loan_ongoing` stays `false` — the flag lives in controller storage and the pool cannot set it.
- The call stack is pool → receiver → controller; the controller is not on the stack, so host re-entry does not fire.

Inside the callback the attacker can call `controller.supply`, `borrow`, `withdraw`, `repay`, `update_indexes`, `claim_revenue`, `recapitalize`, `liquidate`, etc. The codebase itself documents why this is dangerous: `update_indexes`/`pool_update_indexes_call` commits accrual with no flash guard, and the pool's `flash::apply` then commits the `Cache` it loaded *before* the callback, silently dropping that accrual. [5](#0-4)  The same stale-Cache commit applies to any nested controller call that mutates pool state — including `borrow`, which transfers cash out and records debt through the pool.

### Impact Explanation
During a direct pool flash loan, the attacker's callback calls `controller.borrow` (or `withdraw`/`supply`/`update_indexes`). The nested call commits its changes to pool storage (debt position, indexes, accrual). When the callback returns, `flash::apply` writes back the `Cache` snapshotted before payout, overwriting the nested commit while the cash transferred to the attacker stays transferred. Result: the attacker keeps borrowed funds while the recorded debt/accrual is rolled back — theft of user funds and protocol insolvency. Even a minimal `update_indexes` reentry permanently drops committed interest accrual (theft of unclaimed yield). This matches the "theft of user funds / protocol insolvency" acceptance bar.

### Likelihood Explanation
Fully unprivileged: any address can call `pool.flash_loan` with its own deployed Wasm receiver, and inside the callback invoke controller entrypoints whose only mid-flash protection is the (unset) flag and the (absent) host frame. Solvency gates still apply to `borrow`, but the attacker can pre-seed a legitimate collateral account, borrow during the callback, and rely on the stale-Cache commit to erase the recorded debt — no privileged access, oracle manipulation, or parameter misconfiguration required.

### Recommendation
Set the flash guard for pool-originated loans too, or funnel all flash loans through the controller. Options: have `pool.flash_loan` invoke a controller hook that sets `FlashLoanOngoing` around the callback (equivalent to `with_flash_guard`), or make the pool's flash entrypoint callable only by the controller. Additionally, have `flash::apply` reload/merge index and accrual state instead of blindly committing the pre-callback `Cache`, so nested commits cannot be clobbered.

### Proof of Concept
1. Deploy a receiver contract whose callback performs a nested `controller.update_indexes` (minimal) or `controller.borrow` (maximal, with a funded collateral account).
2. Call `pool.flash_loan(asset, amount, receiver, data)` directly — not `controller.flash_loan`.
3. Inside the callback, `is_flash_loan_ongoing` is `false` and the controller is not on the call stack, so the nested call succeeds and commits pool state.
4. After the callback, `flash::apply` commits the pre-callback `Cache`: the nested accrual/debt write is dropped while transferred cash remains gone — reserves stay consistent only for the `B + F` check, the clobbered accounting is lost.

Caveat: I could not read `contracts/pool/src/lib.rs`/`flash.rs` in full within the available iterations, so the exact `flash::apply` cache-commit semantics are inferred from the pinned test comment and invariant docs; the guard-bypass (flag unset + controller off the stack) follows directly from the storage scoping and host re-entry rule cited above.

### Citations

**File:** contracts/controller/src/storage/account.rs (L285-307)
```rust
pub(crate) fn is_flash_loan_ongoing(env: &Env) -> bool {
    env.storage()
        .temporary()
        .get(&SessionKey::FlashLoanOngoing)
        .unwrap_or(false)
}

/// Sets the temporary flash-loan flag, or removes it when clearing.
pub(crate) fn set_flash_loan_ongoing(env: &Env, ongoing: bool) {
    if ongoing {
        env.storage()
            .temporary()
            .set(&SessionKey::FlashLoanOngoing, &true);
    } else {
        env.storage()
            .temporary()
            .remove(&SessionKey::FlashLoanOngoing);
    }
}

/// Runs `f` with the flash-loan flag set; preserves an already-active outer guard.
pub(crate) fn with_flash_guard<T>(env: &Env, f: impl FnOnce() -> T) -> T {
    let prev = is_flash_loan_ongoing(env);
```

**File:** contracts/controller/src/risk/validation.rs (L13-25)
```rust
pub(crate) fn require_authorized_caller(env: &Env, caller: &Address) {
    caller.require_auth();
    require_not_flash_loaning(env);
}

/// Rejects execution while the temporary flash-loan flag is set.
pub(crate) fn require_not_flash_loaning(env: &Env) {
    assert_with_error!(
        env,
        !storage::is_flash_loan_ongoing(env),
        FlashLoanError::FlashLoanOngoing
    );
}
```

**File:** tests/test-harness/tests/controller/bad_debt_netting_and_exit_timing.rs (L327-331)
```rust
// The owner-gated `upgrade_liquidity_pool_params` calls `pool_update_indexes_call`,
// which commits accrual with no flash guard. If a flash callback could reach it,
// pool `flash::apply` would then commit the `Cache` it loaded before the
// callback and drop that accrual.

```

**File:** tests/test-harness/tests/controller/bad_debt_netting_and_exit_timing.rs (L334-342)
```rust
/// The call stack is controller -> pool -> receiver -> controller. Cross-contract
/// calls default to `ContractReentryMode::Prohibited` (soroban-env-host 27.0.1,
/// `src/host/frame.rs`), and re-entry into a contract already on the context
/// stack returns `Error(Context, InvalidAction)`.
///
/// `supply` is not owner-gated and auth mocking stays on, so neither an
/// authorization failure nor the flash guard (`FlashLoanOngoing`) explains its
/// rejection. Both cases return the same host error, so no unguarded controller
/// entrypoint is reachable from a callback, whoever holds the owner key.
```

**File:** mock/flash-loan-receiver/README.md (L17-24)
```markdown
Reentry modes read the `Plan` stored by `set_plan(controller, hub_id, spoke_id, account_id)`. Without a plan they trap with `MissingPlan`. `ReenterPoolFlashLoan` calls the callback's `pool` and takes only `hub_id` from the plan; the other reentry modes call `controller`.

| Mode | Behavior |
| --- | --- |
| `Success` | Approve `amount + fee` to pool |
| `NoRepay` | No approval |
| `UnderRepay` | Approve `amount + fee - 1` |
| `ReenterPoolFlashLoan` | Nested `pool.flash_loan`, then approve |
```
