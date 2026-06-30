### Title
Unbounded `attached_gas` in Delayed XCC Calls Permanently Freezes Funds in Router Contract - (`engine-precompiles/src/xcc.rs`)

### Summary

The `CrossContractCallArgs::Delayed` path in the XCC precompile does not validate the user-controlled `attached_gas` field inside the stored `PromiseArgs` against NEAR's 300 Tgas per-transaction hard limit. Because the EVM gas cost check only accounts for the fixed `ROUTER_SCHEDULE` gas (5 Tgas) used to call `schedule`, not the gas embedded in the promise payload, a user can store a promise with `attached_gas > 300 Tgas` at negligible EVM cost. Any subsequent call to `execute_scheduled` will always panic in the NEAR runtime (gas exceeded), and since there is no cancel/withdraw function in the router, any NEAR tokens attached to that promise are permanently frozen.

### Finding Description

In `engine-precompiles/src/xcc.rs`, the two arms of the `CrossContractCallArgs` match are treated asymmetrically with respect to gas validation.

**Eager path** (lines 140–157): the user's `call.total_gas()` is added directly to `promise.attached_gas`, which is then converted to EVM gas and checked against the transaction's gas limit at line 174. This implicitly caps the user's gas. [1](#0-0) 

**Delayed path** (lines 159–172): `promise.attached_gas` is set to the fixed constant `costs::ROUTER_SCHEDULE` (5 Tgas). The user's `call.total_gas()` is serialised into `args` and stored verbatim in the router — it is **never** inspected or bounded. [2](#0-1) 

The EVM gas cost check at line 174 therefore only sees the 5 Tgas schedule cost, not the user's gas: [3](#0-2) 

The resulting EVM cost for a Delayed call is approximately:

```
343,650 + 4 × input_len + (5 × 10¹² / 175,000,000) ≈ 372,221 EVM gas
```

regardless of how large `attached_gas` is inside the payload.

When `execute_scheduled` is later called, the router deserialises the stored `PromiseArgs` and passes `attached_gas` directly to `env::promise_create`: [4](#0-3) [5](#0-4) 

NEAR's runtime panics with "Exceeded the prepaid gas" whenever the gas requested for a promise exceeds the transaction's prepaid gas (hard-capped at 300 Tgas). Because NEAR rolls back state on panic, the `scheduled_promises.remove` at line 151 is also rolled back, leaving the promise permanently in storage. [4](#0-3) 

The router contract exposes no function to cancel a scheduled promise or withdraw arbitrary NEAR from its balance. The only egress is `send_refund`, which transfers a fixed 2 NEAR storage refund and is callable only by the parent (Aurora Engine): [6](#0-5) 

### Impact Explanation

Any NEAR tokens the user attached to the promise (`attached_balance`) are transferred to the router via the `withdraw_wnear_to_router` callback chain before `schedule` is called: [7](#0-6) 

Once the promise is stored with `attached_gas > 300 Tgas`, those NEAR tokens sit in the router's balance with no reachable code path to recover them. This constitutes **permanent freezing of funds** (Critical).

### Likelihood Explanation

The entry point is the XCC precompile, reachable by any unprivileged EVM user or EVM contract. The attacker only needs to:

1. Hold wNEAR (to fund `attached_balance`).
2. Call the XCC precompile with `CrossContractCallArgs::Delayed` and set `attached_gas` to any value above 300 Tgas (e.g. `u64::MAX`).

The EVM gas cost is the same (~372 k gas) regardless of the chosen `attached_gas`. A malicious EVM contract can also induce a victim to trigger this path if the victim has approved the contract to spend their wNEAR.

### Recommendation

In the `Delayed` arm, validate `call.total_gas()` against a safe maximum (e.g. `300 Tgas` minus the overhead consumed by `execute_scheduled` itself) before serialising the call into the router's storage:

```rust
CrossContractCallArgs::Delayed(call) => {
    let call_gas = call.total_gas();
    // Reject if the stored gas can never be satisfied in a single NEAR tx
    if call_gas.as_u64() > MAX_SAFE_NEAR_GAS {
        return Err(revert_with_message("ERR_GAS_EXCEEDS_NEAR_LIMIT"));
    }
    ...
}
```

Mirror the same EVM-gas cost accounting used in the Eager arm so that the cost of the stored gas is also reflected in the EVM gas charge, giving users a consistent economic signal.

### Proof of Concept

```
1. Deploy a wNEAR ERC-20 on Aurora and approve the XCC precompile.
2. Construct:
     CrossContractCallArgs::Delayed(
       PromiseArgs::Create(PromiseCreateArgs {
         target_account_id: "victim.near",
         method: "noop",
         args: vec![],
         attached_balance: Yocto::new(1_000_000_000_000_000_000_000_000), // 1 NEAR
         attached_gas: NearGas::new(u64::MAX),   // >> 300 Tgas
       })
     )
3. Submit as an EVM transaction to the XCC precompile address
   (0x516cded1d16af10cad47d6d49128e2eb7d27b372).
   EVM gas cost ≈ 372 k gas — the call succeeds.
4. The engine's promise chain runs: wNEAR is unwrapped → 1 NEAR lands in
   the router → `schedule` stores the promise at nonce 0.
5. Call `execute_scheduled({"nonce": "0"})` with max_gas (300 Tgas).
   NEAR runtime panics: "Exceeded the prepaid gas".
   State rolls back; promise remains at nonce 0 forever.
6. The 1 NEAR in the router is permanently inaccessible.
``` [8](#0-7) [9](#0-8)

### Citations

**File:** engine-precompiles/src/xcc.rs (L140-157)
```rust
            CrossContractCallArgs::Eager(call) => {
                let call_gas = call.total_gas();
                let attached_near = call.total_near();
                let callback_count = call
                    .promise_count()
                    .checked_sub(1)
                    .ok_or_else(|| ExitError::Other(Cow::from(consts::ERR_INVALID_INPUT)))?;
                let router_exec_cost = costs::ROUTER_EXEC_BASE
                    + NearGas::new(callback_count * costs::ROUTER_EXEC_PER_CALLBACK.as_u64());
                let promise = PromiseCreateArgs {
                    target_account_id,
                    method: consts::ROUTER_EXEC_NAME.into(),
                    args: borsh::to_vec(&call)
                        .map_err(|_| ExitError::Other(Cow::from(consts::ERR_SERIALIZE)))?,
                    attached_balance: ZERO_YOCTO,
                    attached_gas: router_exec_cost.saturating_add(call_gas),
                };
                (promise, attached_near)
```

**File:** engine-precompiles/src/xcc.rs (L159-175)
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
        };
        cost += EthGas::new(promise.attached_gas.as_u64() / costs::CROSS_CONTRACT_CALL_NEAR_GAS);
        check_cost(cost)?;
```

**File:** etc/xcc-router/src/lib.rs (L136-156)
```rust
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

**File:** etc/xcc-router/src/lib.rs (L232-239)
```rust
    fn base_promise_create(promise: &PromiseCreateArgs) -> PromiseIndex {
        env::promise_create(
            promise.target_account_id.as_ref().parse().unwrap(),
            promise.method.as_str(),
            &promise.args,
            NearToken::from_yoctonear(promise.attached_balance.as_u128()),
            Gas::from_gas(promise.attached_gas.as_u64()),
        )
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
