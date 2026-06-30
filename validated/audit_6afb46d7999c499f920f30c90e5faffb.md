### Title
Scheduled XCC Promises Cannot Be Canceled and `execute_scheduled` Is Callable by Any Account — (File: `etc/xcc-router/src/lib.rs`)

---

### Summary

The XCC Router contract stores promises via the access-controlled `schedule()` function, but provides no cancellation mechanism and exposes `execute_scheduled()` without any caller restriction. Any NEAR account can force-execute a pending scheduled promise at any time. If the forced execution fails (e.g., the target contract rejects the call due to wrong timing or state), the NEAR attached to the promise is refunded to the router contract, where it becomes permanently unrecoverable by the user because the router exposes no general withdrawal path.

---

### Finding Description

The `Router` contract in `etc/xcc-router/src/lib.rs` implements two distinct execution paths for XCC promises:

**`schedule()` (line 136)** — access-controlled. Only the parent Aurora Engine account may call it. It stores a `PromiseArgs` value keyed by an incrementing nonce in `scheduled_promises`. [1](#0-0) 

**`execute_scheduled()` (line 150)** — **no access control**. The function removes the stored promise and immediately dispatches it. The developer comment at line 146–148 explicitly acknowledges this is intentional: [2](#0-1) 

The unit test at line 169 of `etc/xcc-router/src/tests.rs` confirms the design: `"anyone can call this function"`. [3](#0-2) 

**There is no `cancel_scheduled()` function anywhere in the router.** A grep for `cancel` in `etc/xcc-router/src/lib.rs` returns zero results. The only ways NEAR leaves the router are through `execute()`, `execute_scheduled()`, and the deployment-only `send_refund()` (which sends a fixed `REFUND_AMOUNT` to the parent, not to the user). [4](#0-3) 

When a user invokes the XCC precompile with `CrossContractCallArgs::Delayed`, the engine deducts wNEAR from the user's ERC-20 balance and converts it to real NEAR held in the router sub-account. This NEAR is the `attached_balance` that will be forwarded when the scheduled promise is eventually executed. [5](#0-4) 

---

### Impact Explanation

**High — Temporary (potentially permanent) freezing of user funds.**

Concrete attack path:

1. Alice calls the XCC precompile with `CrossContractCallArgs::Delayed`, scheduling a promise that attaches 10 NEAR to a call on a target DeFi contract. Her wNEAR ERC-20 balance is debited; the equivalent NEAR is now held in her router sub-account.
2. Alice intends to execute the promise at a specific time (e.g., after a condition on the target contract is met).
3. Bob (any unprivileged NEAR account) calls `execute_scheduled(U64(0))` on Alice's router sub-account before Alice is ready.
4. The target contract rejects the call (wrong state, slippage guard, or the contract does not yet exist). NEAR protocol refunds the `attached_balance` back to the router contract.
5. The router has no function for Alice to withdraw this refunded NEAR. The only escape paths are `execute()` (parent-only) and `execute_scheduled()` (requires another scheduled promise, which itself requires going through the XCC precompile and spending more wNEAR). Alice's 10 NEAR is effectively frozen in the router.
6. Additionally, Alice cannot cancel the original promise before Bob executes it — there is no `cancel_scheduled()`.

The same path applies if Alice herself discovers the scheduled promise is erroneous (e.g., wrong target address, wrong method arguments) after scheduling it: she has no recourse.

---

### Likelihood Explanation

**Medium.** The `Delayed` XCC path (`CrossContractCallArgs::Delayed`) is a documented, production-facing feature. Any EVM contract or user that uses it and either (a) makes an error in the promise arguments or (b) relies on timing for correctness is exposed. An attacker monitoring the NEAR chain for `schedule` calls on router sub-accounts can trivially call `execute_scheduled` with the correct nonce. The nonce is a sequential `u64` starting at 0, making it trivially discoverable. [6](#0-5) 

---

### Recommendation

1. **Add a `cancel_scheduled()` function** restricted to the parent account (Aurora Engine), mirroring the access control on `schedule()`. This allows the engine to cancel a scheduled promise on behalf of the EVM user and refund the associated NEAR.
2. **Add a NEAR withdrawal function** to the router so that NEAR refunded from failed promise executions can be returned to the user (routed through the parent engine).
3. **Consider restricting `execute_scheduled()`** to the parent account, or at minimum to the EVM address owner, to prevent forced premature execution by third parties.

---

### Proof of Concept

```
# 1. Alice (EVM address 0xALICE) calls the XCC precompile with Delayed args,
#    scheduling a promise to call "risky_method" on "defi.near" with 10 NEAR attached.
#    The engine calls router_account.schedule(promise) — only parent can do this.
#    Alice's wNEAR ERC-20 balance is debited. Router sub-account now holds 10 NEAR.
#    Scheduled promise stored at nonce=0.

# 2. Bob (any NEAR account) observes the schedule call on-chain.

# 3. Bob calls:
near call <alice_address>.aurora execute_scheduled '{"nonce": "0"}' \
  --accountId bob.near --gas 300000000000000

# 4. "defi.near" rejects the call (wrong state). 10 NEAR refunded to router.

# 5. Alice has no cancel_scheduled() to call before step 3.
#    Alice has no withdraw() to recover the 10 NEAR after step 4.
#    Funds are frozen in the router sub-account.
``` [7](#0-6) [5](#0-4)

### Citations

**File:** etc/xcc-router/src/lib.rs (L135-156)
```rust
    /// Similar security considerations here as for `execute`.
    pub fn schedule(&mut self, #[serializer(borsh)] promise: PromiseArgs) {
        self.assert_preconditions();

        let nonce = self.nonce.get().unwrap_or_default();
        self.scheduled_promises.insert(nonce, promise);
        self.nonce.set(&(nonce + 1));

        near_sdk::log!("Promise scheduled at nonce {}", nonce);
    }

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

**File:** etc/xcc-router/src/tests.rs (L168-173)
```rust
    // promise executed after calling `execute_scheduled`
    // anyone can call this function
    testing_env!(VMContextBuilder::new()
        .predecessor_account_id(bob())
        .build());
    contract.execute_scheduled(0.into());
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
