### Title
Unbounded Delay on Scheduled XCC Promises Permanently Locks User NEAR Funds - (File: `etc/xcc-router/src/lib.rs`)

---

### Summary

The XCC router's `schedule` / `execute_scheduled` flow has no expiry or timeout. When an EVM user submits a `CrossContractCallArgs::Delayed` XCC call, the engine immediately withdraws the required NEAR from the user's wNEAR EVM balance and deposits it into the router sub-account. The corresponding `PromiseArgs` is stored in the router's `scheduled_promises` map with no timestamp. `execute_scheduled` can be called by anyone at any arbitrary future time — or never. There is no cancellation path. Funds are frozen in the router until execution occurs.

---

### Finding Description

`CrossContractCallArgs::Delayed` is defined as:

> "The promise is to be stored in the router contract, and can be executed in a future transaction." [1](#0-0) 

When the engine processes a `Delayed` XCC call in `handle_precompile_promise`, it calls `withdraw_wnear_to_router` to convert the user's wNEAR ERC-20 balance into actual NEAR and deposit it into the router sub-account before calling `schedule`: [2](#0-1) 

The router's `schedule` method stores the `PromiseArgs` keyed only by a monotonically incrementing nonce — no block height, no timestamp, no expiry: [3](#0-2) 

The router's `scheduled_promises` field is a plain `LookupMap<u64, PromiseArgs>` with no time metadata: [4](#0-3) 

`execute_scheduled` is explicitly open to any caller and has no deadline check: [5](#0-4) 

There is no `cancel_scheduled`, no refund path, and no mechanism to recover NEAR from a promise that is never executed.

---

### Impact Explanation

When a `Delayed` XCC call is submitted, the user's wNEAR ERC-20 balance is immediately debited and the equivalent NEAR is deposited into the router sub-account. Those NEAR tokens are locked in the router until `execute_scheduled` is called. If the nonce is lost, the user forgets, or no one ever calls the function, the NEAR is frozen indefinitely — effectively permanently. There is no on-chain recovery path. This constitutes **permanent freezing of user funds** (Critical) in the worst case, and **temporary freezing** (High) in the general case.

Additionally, because `execute_scheduled` is callable by anyone with no deadline, a third party can trigger execution at an arbitrarily chosen future moment, causing unexpected state changes in the target NEAR contract at a time the original user did not intend.

---

### Likelihood Explanation

The `Delayed` variant is a documented, intentional feature of the XCC precompile, reachable by any EVM user who calls the cross-contract call precompile address. No special privileges are required. The only precondition is that the user holds sufficient wNEAR ERC-20 balance to cover the attached NEAR. The freeze occurs automatically the moment the `Delayed` call is submitted — no further attacker action is needed to lock the funds. [6](#0-5) 

---

### Recommendation

**Short term:** Record a block timestamp or block height alongside each scheduled promise entry. In `execute_scheduled`, enforce that the promise is executed within a bounded window (e.g., within N blocks of scheduling). If the deadline passes without execution, allow the user (or the parent engine) to reclaim the locked NEAR via a `cancel_scheduled` method that refunds the attached NEAR back to the originating EVM address.

**Long term:** Expose a `cancel_scheduled` entrypoint callable only by the parent engine (on behalf of the originating EVM address) so users can recover funds from stale scheduled promises. Ensure the off-chain UI surfaces all pending scheduled promises and their associated locked NEAR amounts.

---

### Proof of Concept

1. Alice holds 10 wNEAR as an ERC-20 balance inside Aurora.
2. Alice calls the XCC precompile at `cross_contract_call::ADDRESS` with `CrossContractCallArgs::Delayed(promise)` where `promise` carries `attached_balance = 5 NEAR`.
3. The engine executes `handle_precompile_promise` → `withdraw_wnear_to_router`: Alice's EVM wNEAR balance is debited 5 NEAR; 5 NEAR is deposited into Alice's router sub-account (`{alice_addr}.aurora`).
4. The engine calls `schedule` on the router; the promise is stored at nonce `0` with no expiry.
5. Alice's 5 NEAR is now locked in the router. She has no way to cancel or recover it.
6. Days, weeks, or months later, Eve (any NEAR account) calls `execute_scheduled({"nonce": "0"})` on Alice's router sub-account, executing the promise at an arbitrary time of Eve's choosing.
7. If Eve never calls it, Alice's 5 NEAR remains frozen in the router permanently. [7](#0-6) [8](#0-7)

### Citations

**File:** engine-types/src/parameters/promise.rs (L279-284)
```rust
    /// The promise is to be stored in the router contract, and can be executed in a future transaction.
    /// The purpose of this is to expand how much NEAR gas can be made available to a cross contract call.
    /// For example, if an expensive EVM call ends with a NEAR cross contract call, then there may not be
    /// much gas left to perform it. In this case, the promise could be `Delayed` (stored in the router)
    /// and executed in a separate transaction with a fresh 300 Tgas available for it.
    Delayed(PromiseArgs),
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

**File:** engine/src/xcc.rs (L382-393)
```rust
pub fn withdraw_wnear_to_router<I: IO + Copy, E: Env, M: ModExpAlgorithm, H: PromiseHandler>(
    recipient: &AccountId,
    amount: Yocto,
    wnear_address: Address,
    engine: &mut Engine<I, E, M>,
    handler: &mut H,
) -> EngineResult<(SubmitResult, Vec<PromiseId>)> {
    let mut interceptor = PromiseInterceptor::new(handler);
    let withdraw_call_args = withdraw_wnear_call_args(recipient, amount, wnear_address);
    let result = engine.call_with_args(withdraw_call_args, &mut interceptor)?;
    Ok((result, interceptor.promises))
}
```

**File:** etc/xcc-router/src/lib.rs (L58-59)
```rust
    /// The storage for the scheduled promises.
    scheduled_promises: LookupMap<u64, PromiseArgs>,
```

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
