### Title
`require_running` in `exit_to_near_precompile_callback` Blocks Refund Path, Permanently Freezing ERC-20 Tokens When Engine Is Paused During a Failed `ft_transfer` - (File: `engine/src/contract_methods/connector.rs`)

---

### Summary

The `exit_to_near_precompile_callback` function enforces a `require_running` guard before it can execute the ERC-20 refund path. Because the ERC-20 burn is committed in an earlier NEAR receipt (during the original `ExitToNear` precompile execution), if the engine is paused between that receipt and the callback receipt, and the `ft_transfer` promise fails, the refund is permanently blocked. The user's ERC-20 tokens are burned with no corresponding NEP-141 transfer, resulting in permanent fund loss.

---

### Finding Description

The `ExitToNear` precompile flow spans multiple asynchronous NEAR receipts:

1. **Receipt 1** – User submits an EVM transaction that calls the `ExitToNear` precompile. The EVM executor burns the user's ERC-20 tokens and commits those state changes via `engine.apply(...)`. A NEAR promise to call `ft_transfer` on the NEP-141 contract is scheduled, along with a callback to `exit_to_near_precompile_callback`.

2. **Receipt 2** – The NEP-141 `ft_transfer` executes. It can fail for legitimate reasons (e.g., the recipient account is not registered with the NEP-141 contract).

3. **Receipt 3** – `exit_to_near_precompile_callback` executes. If Receipt 2 failed and `args.refund` is `Some`, this callback is supposed to call `engine::refund_on_error` to re-mint the burned ERC-20 tokens back to the user.

The problem is that `exit_to_near_precompile_callback` calls `require_running` **before** inspecting the promise result or executing the refund:

```rust
// engine/src/contract_methods/connector.rs
pub fn exit_to_near_precompile_callback<...>(...) -> Result<...> {
    with_hashchain(io, env, function_name!(), |io| {
        let state = state::get_state(&io)?;
        require_running(&state)?;          // ← blocks entire callback if paused
        env.assert_private_call()?;
        ...
        } else if let Some(args) = args.refund {
            // Exit call failed; need to refund tokens
            let refund_result = engine::refund_on_error(io, env, state, &args, handler)?;
```

If the engine owner calls `pause_contract` at any point between Receipt 1 and Receipt 3, `require_running` returns `Err(ERR_PAUSED)`, the callback panics, and NEAR rolls back only the callback's own state changes. The ERC-20 burn from Receipt 1 is already finalized and **cannot be rolled back**. The user's tokens are permanently destroyed.

Note that `refund_on_error` itself does **not** call `require_running`—it operates directly on the passed `state`. The guard is exclusively in the callback wrapper, making it an unnecessary and dangerous restriction on an internal recovery path.

---

### Impact Explanation

**Critical – Permanent freezing of funds.**

A user's ERC-20 tokens are irreversibly burned inside the Aurora EVM with no corresponding NEP-141 tokens received. The funds cannot be recovered because:
- The ERC-20 burn is committed in a finalized NEAR receipt.
- The refund path (`refund_on_error`) is gated behind `require_running` and cannot execute while the engine is paused.
- There is no alternative recovery mechanism.

---

### Likelihood Explanation

**Low.**

Two independent conditions must coincide:
1. The `ft_transfer` promise in Receipt 2 must fail (possible but not the common case—requires an unregistered recipient account or similar NEP-141 rejection).
2. The engine must be paused (a legitimate admin operation) in the window between Receipt 1 and Receipt 3.

Both conditions are individually plausible in production. The engine is pausable by the owner for maintenance or emergency response, and `ft_transfer` failures are a documented possibility. Their simultaneous occurrence is unlikely but not negligible.

---

### Recommendation

Remove `require_running` from `exit_to_near_precompile_callback`, or restructure the guard so it does not apply to the refund branch. The callback is an internal, private-only function (`env.assert_private_call()` already enforces this) and must always be able to execute its recovery logic regardless of the engine's pause state. The analogous fix applied in the referenced report was to allow the recovery path to proceed unconditionally when the state transition has already been committed.

```rust
pub fn exit_to_near_precompile_callback<...>(...) -> Result<...> {
    with_hashchain(io, env, function_name!(), |io| {
        let state = state::get_state(&io)?;
        // Do NOT call require_running here; the refund path must be
        // reachable even when the engine is paused.
        env.assert_private_call()?;
        ...
    })
}
```

---

### Proof of Concept

**Step 1.** User calls `ExitToNear` precompile via an EVM transaction targeting an unregistered NEP-141 recipient. ERC-20 tokens are burned; `ft_transfer` and `exit_to_near_precompile_callback` promises are scheduled.

**Step 2.** Engine owner calls `pause_contract` (a routine admin action). `state.is_paused` is set to `true`.

**Step 3.** `ft_transfer` executes and fails (unregistered account). Receipt 2 is marked failed.

**Step 4.** `exit_to_near_precompile_callback` executes. `require_running` reads `state.is_paused == true` and returns `Err(ERR_PAUSED)`. The callback panics. NEAR rolls back the callback's state changes only.

**Step 5.** The ERC-20 burn from Step 1 remains finalized. The user has lost their tokens permanently.

---

**Root cause location:** [1](#0-0) 

**`require_running` guard that blocks the refund path:** [2](#0-1) 

**Refund branch that is unreachable when engine is paused:** [3](#0-2) 

**`refund_on_error` itself (does not check `require_running`):** [4](#0-3) 

**`pause_contract` that sets `is_paused = true`:** [5](#0-4) 

**`require_running` definition:** [6](#0-5)

### Citations

**File:** engine/src/contract_methods/connector.rs (L196-210)
```rust
pub fn exit_to_near_precompile_callback<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I,
    env: &E,
    handler: &mut H,
) -> Result<Option<SubmitResult>, ContractError> {
    with_hashchain(io, env, function_name!(), |io| {
        let state = state::get_state(&io)?;
        require_running(&state)?;
        env.assert_private_call()?;

        // This function should only be called as the callback of
        // exactly one promise.
        if handler.promise_results_count() != 1 {
            return Err(errors::ERR_PROMISE_COUNT.into());
        }
```

**File:** engine/src/contract_methods/connector.rs (L231-239)
```rust
        } else if let Some(args) = args.refund {
            // Exit call failed; need to refund tokens
            let refund_result = engine::refund_on_error(io, env, state, &args, handler)?;

            if !refund_result.status.is_ok() {
                return Err(errors::ERR_REFUND_FAILURE.into());
            }

            Some(refund_result)
```

**File:** engine/src/engine.rs (L1176-1204)
```rust
pub fn refund_on_error<I: IO + Copy, E: Env, P: PromiseHandler>(
    io: I,
    env: &E,
    state: EngineState,
    args: &RefundCallArgs,
    handler: &mut P,
) -> EngineResult<SubmitResult> {
    let current_account_id = env.current_account_id();
    if let Some(erc20_address) = args.erc20_address {
        // ERC-20 exit; re-mint burned tokens
        let erc20_admin_address = current_address(&current_account_id);
        let mut engine: Engine<_, _> =
            Engine::new_with_state(state, erc20_admin_address, current_account_id, io, env);

        let refund_address = args.recipient_address;
        let amount = U256::from_big_endian(&args.amount);
        let input = setup_refund_on_error_input(amount, refund_address);

        engine.call(
            &erc20_admin_address,
            &erc20_address,
            Wei::zero(),
            input,
            u64::MAX,
            Vec::new(),
            Vec::new(),
            handler,
        )
    } else {
```

**File:** engine/src/contract_methods/admin.rs (L251-259)
```rust
pub fn pause_contract<I: IO + Copy, E: Env>(io: I, env: &E) -> Result<(), ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        let mut state = state::get_state(&io)?;
        require_owner_only(&state, &env.predecessor_account_id())?;
        require_running(&state)?;
        state.is_paused = true;
        state::set_state(&mut io, &state)?;
        Ok(())
    })
```

**File:** engine/src/contract_methods/mod.rs (L65-70)
```rust
pub fn require_running(state: &state::EngineState) -> Result<(), ContractError> {
    if state.is_paused {
        return Err(errors::ERR_PAUSED.into());
    }
    Ok(())
}
```
