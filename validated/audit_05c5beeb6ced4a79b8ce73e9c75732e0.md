### Title
Scheduled XCC Promises Execute Without Re-Validating Engine Pause State — (`etc/xcc-router/src/lib.rs`)

---

### Summary

The XCC router's `execute_scheduled` function performs no state validation before executing stored promises. When the Aurora Engine is paused for emergency reasons, previously-scheduled cross-contract calls can still be triggered by any caller, bypassing the engine's pause mechanism entirely.

---

### Finding Description

The XCC router contract (`etc/xcc-router/src/lib.rs`) supports two execution modes for cross-contract calls: immediate (`execute`) and delayed (`schedule` + `execute_scheduled`). The `schedule` function is gated by `assert_preconditions()`, which verifies the caller is the parent Aurora Engine and that no prior promises have failed: [1](#0-0) 

However, `execute_scheduled` is intentionally open to any caller and performs **zero state validation**: [2](#0-1) 

The Aurora Engine's pause mechanism sets `is_paused = true` in engine state and is enforced via `require_running` at the start of every mutative engine method: [3](#0-2) 

This check is applied to all engine entry points including `submit`, `call`, `deploy_code`, and the XCC precompile path. The XCC precompile itself is also subject to the engine-level pause: [4](#0-3) 

However, the router sub-account is a **separate NEAR contract** with its own state. It has no mechanism to read the engine's `is_paused` flag. When `execute_scheduled` is called directly on the router (not through the engine), none of the engine's guards apply.

The attack path is:

1. A user calls the XCC precompile with `CrossContractCallArgs::Delayed(...)`, which causes the engine to call `schedule` on the user's router sub-account, storing the promise.
2. The engine is subsequently paused via `pause_contract` (e.g., due to a discovered vulnerability).
3. Any account — including the original user or a third party — calls `execute_scheduled` directly on the router sub-account with the stored nonce.
4. The router executes the stored promise unconditionally, making the cross-contract call proceed despite the engine being in a paused/emergency state.

The `CrossContractCallArgs::Delayed` variant is explicitly designed for this deferred execution pattern: [5](#0-4) 

The comment in `execute_scheduled` itself acknowledges the open-caller design but does not account for the engine pause state: [6](#0-5) 

---

### Impact Explanation

**High — Temporary freezing bypass.**

The `pause_contract` mechanism is the primary emergency stop for the Aurora Engine. When triggered, it is intended to halt all state-changing operations. However, any promises already stored in router sub-accounts remain executable by anyone, regardless of the engine's pause state. This means the pause does not achieve a complete halt of operations: cross-contract calls that were scheduled before the pause can still be dispatched to arbitrary NEAR contracts, potentially moving tokens or triggering state changes in external protocols during an incident window.

---

### Likelihood Explanation

**Medium.**

The `Delayed` XCC mode is a documented, production feature used to expand gas availability for expensive calls. Any user who has used `CrossContractCallArgs::Delayed` and has a pending scheduled promise at the time of a pause is a potential trigger. The `execute_scheduled` function requires no special permissions, so the user themselves or any third party can call it. The scenario requires a pause event to occur after scheduling, which is an emergency condition but not an implausible one given the engine has a `pause_contract` function designed for exactly such situations.

---

### Recommendation

The `execute_scheduled` function should verify the parent engine is not paused before dispatching the stored promise. Since the router cannot directly read the engine's storage, this can be achieved by:

1. Making a synchronous view call to the parent engine's `get_paused` or equivalent view method before executing, and reverting if paused.
2. Alternatively, having the engine's `pause_contract` propagate a pause signal to all known router sub-accounts (more complex).
3. At minimum, documenting that `pause_contract` does not cover scheduled router promises and providing a separate mechanism (e.g., a `cancel_scheduled` method callable by the parent) to drain pending promises during an emergency.

---

### Proof of Concept

1. User calls the XCC precompile with `CrossContractCallArgs::Delayed(ft_transfer_promise)`. The engine calls `schedule` on `{user_address}.aurora`, storing the promise at nonce 0. [7](#0-6) 

2. Admin calls `pause_contract` on the Aurora Engine. `is_paused` is set to `true`. [8](#0-7) 

3. Any account calls `execute_scheduled({"nonce": "0"})` directly on `{user_address}.aurora`. The router removes the promise from storage and dispatches it unconditionally: [9](#0-8) 

4. The cross-contract call executes on the target NEAR contract. The engine's `require_running` guard is never consulted because the call originates from the router, not the engine.

### Citations

**File:** etc/xcc-router/src/lib.rs (L136-144)
```rust
    pub fn schedule(&mut self, #[serializer(borsh)] promise: PromiseArgs) {
        self.assert_preconditions();

        let nonce = self.nonce.get().unwrap_or_default();
        self.scheduled_promises.insert(nonce, promise);
        self.nonce.set(&(nonce + 1));

        near_sdk::log!("Promise scheduled at nonce {}", nonce);
    }
```

**File:** etc/xcc-router/src/lib.rs (L146-156)
```rust
    /// It is intentional that this function can be called by anyone (not just the parent).
    /// There is no security risk to allowing this function to be open because it can only
    /// act on promises that were created via `schedule`.
    #[payable]
    pub fn execute_scheduled(&mut self, nonce: U64) {
        let Some(promise) = self.scheduled_promises.remove(&nonce.0) else {
            env::panic_str("ERR_PROMISE_NOT_FOUND")
        };
        let promise_id = Self::promise_create(promise);
        env::promise_return(promise_id);
    }
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

**File:** engine-precompiles/src/lib.rs (L140-144)
```rust
        if self.is_paused(&address) {
            return Some(Err(PrecompileFailure::Fatal {
                exit_status: ExitFatal::Other(prelude::Cow::Borrowed("ERR_PAUSED")),
            }));
        }
```

**File:** engine-types/src/parameters/promise.rs (L279-285)
```rust
    /// The promise is to be stored in the router contract, and can be executed in a future transaction.
    /// The purpose of this is to expand how much NEAR gas can be made available to a cross contract call.
    /// For example, if an expensive EVM call ends with a NEAR cross contract call, then there may not be
    /// much gas left to perform it. In this case, the promise could be `Delayed` (stored in the router)
    /// and executed in a separate transaction with a fresh 300 Tgas available for it.
    Delayed(PromiseArgs),
}
```

**File:** engine-precompiles/src/xcc.rs (L159-172)
```rust
            CrossContractCallArgs::Delayed(call) => {
                let attached_near = call.total_near();
                let promise = PromiseCreateArgs {
                    target_account_id,
                    method: consts::ROUTER_SCHEDULE_NAME.into(),
                    args: borsh::to_vec(&call)
                        .map_err(|_| ExitError::Other(Cow::from(consts::ERR_SERIALIZE)))?,
                    attached_balance: ZERO_YOCTO,
                    // We don't need to add any gas to the amount need for the schedule call
                    // since the promise is not executed right away.
                    attached_gas: costs::ROUTER_SCHEDULE,
                };
                (promise, attached_near)
            }
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
