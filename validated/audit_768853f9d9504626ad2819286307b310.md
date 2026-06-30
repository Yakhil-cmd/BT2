### Title
Indefinitely Persistent Scheduled XCC Promises With No Cancellation Mechanism Allow Permanent Fund Freeze - (File: `etc/xcc-router/src/lib.rs`)

### Summary

The `Router` contract's `execute_scheduled` function is callable by anyone with no expiration or cancellation mechanism. Once a user schedules a Delayed XCC promise via the XCC precompile, their wNEAR is immediately deducted from their EVM balance and moved to the router's NEAR account, but the stored promise persists indefinitely in `scheduled_promises` with no way to cancel it. A malicious recipient or any third party can execute the promise at any time, and if the promise fails on execution, the NEAR attached to it is permanently locked in the router with no recovery path.

### Finding Description

The `CrossContractCallArgs::Delayed` flow in Aurora Engine allows EVM users to schedule NEAR cross-contract calls for later execution. The flow works as follows:

1. The EVM user calls the XCC precompile (`engine-precompiles/src/xcc.rs`) with `CrossContractCallArgs::Delayed(call)`.
2. The precompile immediately deducts `required_near` worth of wNEAR from the user's EVM balance via `transferFrom` on the wNEAR ERC-20 contract.
3. The engine's `handle_precompile_promise` (`engine/src/xcc.rs`) creates a NEAR-level promise chain that withdraws the wNEAR to the router's NEAR account and calls `schedule` on the router.
4. The router's `schedule` function stores the `PromiseArgs` in `scheduled_promises: LookupMap<u64, PromiseArgs>` under a monotonically incrementing nonce — with **no timestamp, block height, or deadline**. [1](#0-0) 

The `execute_scheduled` function is explicitly documented as open to anyone: [2](#0-1) 

There is **no cancellation function** anywhere in the `Router` contract. Once a promise is scheduled, it can only be removed by executing it. There is no mechanism for the user (or even the parent Aurora Engine) to delete a scheduled promise without executing it.

The wNEAR deduction and NEAR transfer to the router happen at scheduling time, not at execution time: [3](#0-2) [4](#0-3) [5](#0-4) 

### Impact Explanation

**Permanent fund freeze (Critical):**

When a Delayed XCC promise includes `attached_balance > 0` (NEAR to be sent to the target contract), that NEAR is moved from the user's wNEAR EVM balance into the router's NEAR account at scheduling time. If `execute_scheduled` is called and the target contract rejects the call (e.g., the target contract's state has changed, it is paused, or the call parameters are stale), the NEAR is returned to the router by the NEAR runtime. However, the user has no mechanism to withdraw NEAR from the router — only the parent Aurora Engine can call `execute` or `schedule` on the router, and there is no `withdraw` or `cancel` function. The NEAR is permanently locked in the router sub-account.

**Theft / unintended execution (High):**

A user who schedules a promise with incorrect parameters (wrong recipient, wrong amount, wrong method) cannot cancel it. Any third party — including the malicious recipient — can call `execute_scheduled` at any time to trigger the transfer. Since the user's wNEAR was already deducted at scheduling time, the user suffers the loss with no recourse.

Additionally, a malicious actor can time the execution of a stale promise (e.g., a DEX swap or token transfer) to maximize harm to the user, since there is no deadline after which the promise becomes invalid.

### Likelihood Explanation

The `Delayed` XCC path is a production-supported feature explicitly designed for cases where gas is insufficient to execute the promise immediately. Users and EVM contracts regularly use it. Mistakes in promise parameters (wrong recipient, wrong amount) are realistic. The `execute_scheduled` function requires no special privilege — any NEAR account can call it. The combination of irrevocable fund commitment at scheduling time and indefinite promise persistence makes this exploitable without any privileged access.

### Recommendation

1. **Add a cancellation function** callable only by the parent (Aurora Engine), which removes a scheduled promise and triggers a refund of the associated NEAR back to the user's router or EVM balance.
2. **Add an expiration timestamp or block height** to each scheduled promise. `execute_scheduled` should reject execution of expired promises and trigger a refund.
3. **Add a refund path for failed `execute_scheduled` calls**: if the executed promise fails, the NEAR should be returned to the user's EVM balance (as wNEAR) rather than remaining locked in the router.

### Proof of Concept

**Permanent fund freeze:**

1. EVM contract at address `A` calls the XCC precompile with:
   ```
   CrossContractCallArgs::Delayed(PromiseArgs::Create(PromiseCreateArgs {
       target_account_id: "some.contract.near",
       method: "deposit",
       args: b"{}",
       attached_balance: Yocto::new(1_000_000_000_000_000_000_000_000), // 1 NEAR
       attached_gas: NearGas::new(10_000_000_000_000),
   }))
   ```
2. The XCC precompile deducts 1 wNEAR from `A`'s EVM balance immediately.
3. The NEAR-level promise chain moves 1 NEAR to the router sub-account for `A` and stores the promise at nonce `0`.
4. `some.contract.near` is subsequently paused or deleted.
5. Anyone calls `execute_scheduled({"nonce": "0"})` on the router.
6. The call to `some.contract.near.deposit` fails; 1 NEAR is returned to the router by the NEAR runtime.
7. The 1 NEAR is permanently locked in the router. `A` has lost 1 wNEAR with no recovery path.

The `schedule` function stores with no expiry: [6](#0-5) 

The `execute_scheduled` function has no caller restriction, no expiry check, and no refund on failure: [7](#0-6) 

The `Router` struct confirms no expiry field exists alongside stored promises: [8](#0-7)

### Citations

**File:** etc/xcc-router/src/lib.rs (L48-62)
```rust
#[derive(PanicOnDefault)]
#[near(contract_state)]
pub struct Router {
    /// The account id of the Aurora Engine instance that controls this router.
    parent: LazyOption<AccountId>,
    /// The version of the router contract that was last deployed
    version: LazyOption<u32>,
    /// A sequential id to keep track of how many scheduled promises this router has executed.
    /// This allows multiple promises to be scheduled before any of them are executed.
    nonce: LazyOption<u64>,
    /// The storage for the scheduled promises.
    scheduled_promises: LookupMap<u64, PromiseArgs>,
    /// Account ID for the wNEAR contract.
    wnear_account: AccountId,
}
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

**File:** engine-precompiles/src/xcc.rs (L184-216)
```rust
        if required_near != ZERO_YOCTO {
            let engine_implicit_address = aurora_engine_sdk::types::near_account_to_evm_address(
                self.engine_account_id.as_bytes(),
            );
            let tx_data = transfer_from_args(
                sender.0.into(),
                engine_implicit_address.raw().0.into(),
                required_near.as_u128().into(),
            );
            let wnear_address = state::get_wnear_address(&self.io);
            let context = aurora_evm::Context {
                address: wnear_address.raw(),
                caller: cross_contract_call::ADDRESS.raw(),
                apparent_value: U256::zero(),
            };
            let (exit_reason, return_value) =
                handle.call(wnear_address.raw(), None, tx_data, None, false, &context);
            match exit_reason {
                // Transfer successful, nothing to do
                aurora_evm::ExitReason::Succeed(_) => (),
                aurora_evm::ExitReason::Revert(r) => {
                    return Err(PrecompileFailure::Revert {
                        exit_status: r,
                        output: return_value,
                    });
                }
                aurora_evm::ExitReason::Error(e) => {
                    return Err(PrecompileFailure::Error { exit_status: e });
                }
                aurora_evm::ExitReason::Fatal(f) => {
                    return Err(PrecompileFailure::Fatal { exit_status: f });
                }
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
