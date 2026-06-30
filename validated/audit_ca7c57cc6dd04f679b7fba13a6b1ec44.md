### Title
Unauthenticated `execute_scheduled` Allows Any Caller to Force Early Execution of a User's Time-Sensitive Scheduled Promise — (`File: etc/xcc-router/src/lib.rs`)

---

### Summary

The XCC router contract exposes `execute_scheduled` with no access control. Any NEAR account can call it at any time to trigger execution of a promise that was scheduled on behalf of a specific Aurora EVM user. When the scheduled promise targets a time-sensitive NEAR protocol (e.g., a staking contract where rewards accrue over time), a third party can force early execution and cause the user to receive less yield than intended.

---

### Finding Description

When an Aurora EVM user calls the XCC precompile (`0x516cded1d16af10cad47d6d49128e2eb7d27b372`) with `CrossContractCallArgs::Delayed(promise)`, the Aurora engine calls `schedule` on the user's personal router contract. This stores the promise at a sequential nonce and emits a public log: [1](#0-0) 

The `schedule` function is correctly restricted to the parent (Aurora engine). However, `execute_scheduled` — which actually dispatches the stored promise — has **no caller restriction**: [2](#0-1) 

The comment claims "There is no security risk," but this reasoning is incomplete: while the *content* of the promise is fixed, the *timing* of execution is not. For any time-sensitive NEAR protocol (staking rewards, AMM price-sensitive swaps, CGDA-style incentives), early forced execution directly reduces the value the user receives.

The router account ID is fully deterministic — it is `{hex_encoded_evm_address}.{aurora_engine_account_id}` — and the nonce is publicly broadcast in the NEAR transaction log. Both pieces of information needed to trigger the attack are freely observable on-chain.

The `CrossContractCallArgs::Delayed` variant is explicitly designed for promises the user intends to execute in a *future* transaction of their own choosing: [3](#0-2) 

The XCC precompile routes `Delayed` calls to `schedule` on the router: [4](#0-3) 

---

### Impact Explanation

**High — Theft of unclaimed yield.**

A user who schedules a `Delayed` XCC call to a time-sensitive NEAR protocol (e.g., a staking contract where unclaimed rewards grow with time, or a NEAR-native CGDA-style incentive) can have that call executed by any third party at the worst possible moment. The user receives less yield than they would have received had they executed the promise themselves at their chosen time. The loss is bounded by the difference in protocol output between the forced early execution time and the user's intended execution time, which can be substantial for protocols with steep time-dependent reward curves.

---

### Likelihood Explanation

**Medium-High.**

- The router account ID is deterministic and publicly derivable from the user's EVM address.
- The nonce is emitted as a public NEAR log on every `schedule` call, making it trivially observable.
- No special privilege is required — any NEAR account can call `execute_scheduled`.
- The only precondition is that the user's scheduled promise targets a time-sensitive NEAR protocol, which is a natural and expected use case for the `Delayed` XCC variant (the feature exists precisely to allow users to make expensive NEAR calls in a separate transaction they control).

---

### Recommendation

Restrict `execute_scheduled` so that only the router's `parent` account (the Aurora engine instance) or the EVM address owner can trigger it. The simplest fix is to add the same `assert_preconditions()` guard already used by `execute` and `schedule`:

```rust
pub fn execute_scheduled(&mut self, nonce: U64) {
    self.assert_preconditions(); // add this
    let Some(promise) = self.scheduled_promises.remove(&nonce.0) else {
        env::panic_str("ERR_PROMISE_NOT_FOUND")
    };
    let promise_id = Self::promise_create(promise);
    env::promise_return(promise_id);
}
```

Alternatively, if open execution is desired for liveness reasons (e.g., to allow a relayer to execute on behalf of a user who cannot act), a time-lock or explicit user-signed authorization should be required before a third party can trigger execution.

---

### Proof of Concept

1. Alice (EVM address `0xALICE`) calls the XCC precompile on Aurora with `CrossContractCallArgs::Delayed(claim_staking_rewards_promise)`, where the target NEAR contract pays more rewards the longer Alice waits.
2. The Aurora engine calls `schedule` on Alice's router (`{hex(0xALICE)}.aurora`), storing the promise at nonce `0` and emitting the log `"Promise scheduled at nonce 0"`.
3. Bob observes the log on-chain, computes Alice's router account ID, and immediately calls:
   ```
   near call {hex(0xALICE)}.aurora execute_scheduled '{"nonce": "0"}' --accountId bob.near
   ```
4. The promise executes immediately. Alice's staking reward claim is processed at the current (low) reward level instead of the higher level she would have received by waiting.
5. Alice receives less yield than intended. Bob paid only the NEAR gas cost for the call. [2](#0-1) [1](#0-0)

### Citations

**File:** etc/xcc-router/src/lib.rs (L136-143)
```rust
    pub fn schedule(&mut self, #[serializer(borsh)] promise: PromiseArgs) {
        self.assert_preconditions();

        let nonce = self.nonce.get().unwrap_or_default();
        self.scheduled_promises.insert(nonce, promise);
        self.nonce.set(&(nonce + 1));

        near_sdk::log!("Promise scheduled at nonce {}", nonce);
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

**File:** engine-types/src/parameters/promise.rs (L279-284)
```rust
    /// The promise is to be stored in the router contract, and can be executed in a future transaction.
    /// The purpose of this is to expand how much NEAR gas can be made available to a cross contract call.
    /// For example, if an expensive EVM call ends with a NEAR cross contract call, then there may not be
    /// much gas left to perform it. In this case, the promise could be `Delayed` (stored in the router)
    /// and executed in a separate transaction with a fresh 300 Tgas available for it.
    Delayed(PromiseArgs),
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
