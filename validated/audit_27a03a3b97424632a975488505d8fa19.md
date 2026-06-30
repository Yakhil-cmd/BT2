### Title
Unrestricted `execute_scheduled` Allows Anyone to Force Premature Execution of a User's Scheduled XCC Promise, Temporarily Freezing Attached NEAR Funds - (File: `etc/xcc-router/src/lib.rs`)

### Summary

The XCC router contract's `execute_scheduled` function has no caller restriction. Any NEAR account can call it with any nonce, immediately consuming and executing a user's scheduled cross-contract promise. When the forced execution occurs at an unfavorable time and the promise fails, the NEAR tokens that were pre-funded into the router for that promise are temporarily frozen in the router contract, inaccessible to the user until they re-schedule a new XCC transaction.

### Finding Description

The `execute_scheduled` function in the XCC router contract is explicitly designed to be callable by anyone: [1](#0-0) 

The developer comment states: *"There is no security risk to allowing this function to be open because it can only act on promises that were created via `schedule`."* This reasoning is flawed in the same way as the original report's credential front-running: it considers only **what** the promise does, not **when** it executes or what happens when forced execution fails.

The `schedule` function, by contrast, is correctly restricted to the parent (Aurora engine): [2](#0-1) 

When a user uses the XCC precompile with `CrossContractCallArgs::Delayed`, the engine:
1. Burns the user's wNEAR EVM balance and transfers real NEAR to the router sub-account via `withdraw_wnear_to_router`
2. Calls `router.schedule(promise)` to store the promise [3](#0-2) 

The NEAR is now held in the router contract. The scheduled promise (which may carry `attached_balance > 0`) is stored in `scheduled_promises`. At this point, **any external NEAR account** can call `execute_scheduled(nonce)` and force the promise to execute immediately.

The critical detail is that `scheduled_promises.remove` is a storage mutation committed in the **current transaction**, while the promise itself executes asynchronously in a future receipt. If the promise fails (e.g., the target contract is paused, has a time-lock, or rejects the call due to timing), the storage removal is **not rolled back** — the promise slot is permanently gone, but the NEAR refunded to the router is now stranded there with no direct user-accessible withdrawal path. [4](#0-3) 

The router has no user-facing `withdraw` function. The only egress paths are `execute_scheduled` (requires a new scheduled promise) and `send_refund` (restricted to the parent/engine): [5](#0-4) 

### Impact Explanation

**High — Temporary freezing of funds.**

When a user schedules a delayed XCC call with NEAR attached (e.g., to interact with a NEAR DeFi protocol that requires NEAR payment), the NEAR is pre-funded into the router. An attacker who front-runs `execute_scheduled` at a moment when the target contract rejects the call causes:

1. The promise slot to be permanently deleted from `scheduled_promises`
2. The attached NEAR to be refunded to the router contract's balance
3. The user's NEAR to be stranded in the router — inaccessible without scheduling a new XCC transaction and paying additional gas

The user's funds are not permanently lost (they can recover by scheduling a new promise), but they are temporarily frozen and the user is forced to pay additional gas costs to recover them. The attacker bears only the cost of one NEAR function call.

### Likelihood Explanation

**Medium.** NEAR blockchain state is fully public. An attacker can monitor all router sub-accounts (named `{evm_address}.aurora`) for `schedule` calls via the NEAR indexer or RPC. Once a scheduled promise with `attached_balance > 0` is detected, the attacker can identify windows where the target contract would reject the call (e.g., known pause periods, time-locks, or cooldowns) and call `execute_scheduled` during that window. No privileged access is required — only a standard NEAR account and gas.

### Recommendation

Remove the "open to anyone" design for `execute_scheduled`. Restrict callers to either:
- The parent account (Aurora engine), which can be called by the EVM user via a new EVM transaction, **or**
- The EVM address owner (derivable from the router's sub-account name), authenticated via a signed message or NEAR function-call key

This mirrors the fix described in the original report: allow the legitimate owner to trigger execution while also permitting the engine (acting on behalf of the user) to do so.

### Proof of Concept

```
# Attacker steps (no privileged access required):

1. Monitor NEAR RPC for calls to `{address}.aurora` router contracts:
   near view {address}.aurora get_version  # confirm router exists

2. Watch for `schedule` calls (logged as "Promise scheduled at nonce N"):
   # Attacker sees: User scheduled promise at nonce 0 with attached_balance = 5 NEAR

3. Identify a window where the target contract rejects the call
   (e.g., target contract is paused, or has a block-height time-lock not yet reached)

4. Call execute_scheduled before the user does:
   near call {address}.aurora execute_scheduled '{"nonce": "0"}' \
     --accountId attacker.near --gas 300000000000000

# Result:
# - Promise executes immediately and fails (target contract rejects)
# - scheduled_promises[0] is permanently deleted
# - 5 NEAR is refunded to the router contract balance
# - User's 5 NEAR is stranded in the router; user must pay gas for a new XCC tx to recover
``` [1](#0-0) [6](#0-5) [3](#0-2)

### Citations

**File:** etc/xcc-router/src/lib.rs (L135-144)
```rust
    /// Similar security considerations here as for `execute`.
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

**File:** etc/xcc-router/src/lib.rs (L176-184)
```rust
    pub fn send_refund(&self) -> Promise {
        let parent = self.get_parent().unwrap_or_else(env_panic);

        require_caller(&parent)
            .and_then(|_| require_no_failed_promises())
            .unwrap_or_else(env_panic);

        Promise::new(parent).transfer(REFUND_AMOUNT)
    }
```

**File:** engine/src/xcc.rs (L289-330)
```rust
    let withdraw_id = if required_near == ZERO_YOCTO {
        setup_id
    } else {
        let withdraw_call_args = WithdrawWnearToRouterArgs {
            target: sender,
            amount: required_near,
        };
        let withdraw_call = PromiseCreateArgs {
            target_account_id: current_account_id.clone(),
            method: "withdraw_wnear_to_router".into(),
            args: borsh::to_vec(&withdraw_call_args).unwrap(),
            attached_balance: ZERO_YOCTO,
            attached_gas: WITHDRAW_GAS,
        };
        // Safety: This promise is safe. Even though this is a call from the engine account to
        // itself invoking the `call` method (which could be dangerous), the argument to `call`
        // is controlled entirely by us (not any user). This call will only execute the wnear
        // exit precompile, and only for the necessary amount. Note that this amount will always
        // be present, otherwise the user's call to the xcc precompile would have failed.
        let id = match setup_id {
            None => handler.promise_create_call(&withdraw_call),
            Some(setup_id) => handler.promise_attach_callback(setup_id, &withdraw_call),
        };
        let refund_needed = match deploy_needed {
            AddressVersionStatus::DeployNeeded { create_needed } => create_needed,
            AddressVersionStatus::UpToDate => false,
        };
        if refund_needed {
            let refund_call = PromiseCreateArgs {
                target_account_id: promise.target_account_id.clone(),
                method: "send_refund".into(),
                args: Vec::new(),
                attached_balance: ZERO_YOCTO,
                attached_gas: REFUND_GAS,
            };
            // Safety: This call is safe because the router's `send_refund` method
            // does not violate any security invariants. It only sends NEAR back to this contract.
            Some(handler.promise_attach_callback(id, &refund_call))
        } else {
            Some(id)
        }
    };
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
