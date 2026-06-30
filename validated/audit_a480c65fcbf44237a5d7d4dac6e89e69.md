### Title
Scheduled XCC Promises Execute Without Re-Validating Engine Running State, Bypassing the Pause Mechanism — (`File: etc/xcc-router/src/lib.rs`)

---

### Summary

The XCC Router's `execute_scheduled` function can be called by **any** NEAR account and executes stored `PromiseArgs` without checking whether the Aurora Engine (the parent) is still running. This is structurally identical to the LayerZero `retryMessage()` issue: a stored/pending operation can be executed after the authorization context that created it has been revoked (engine paused, silo whitelist changed). The engine's pause mechanism is thereby bypassed for all previously-scheduled cross-contract calls.

---

### Finding Description

The XCC Router contract (`etc/xcc-router/src/lib.rs`) exposes two distinct entry points for executing NEAR cross-contract calls:

**`execute`** (line 128–133) — requires `assert_preconditions()`, which enforces:
1. Contract is initialized
2. `predecessor_account_id == self.parent` (only the Aurora Engine may call)
3. No failed promise results in the callback chain [1](#0-0) 

**`schedule`** (line 136–143) — also requires `assert_preconditions()`, so only the Aurora Engine can store a promise into `scheduled_promises`. [2](#0-1) 

**`execute_scheduled`** (line 150–156) — explicitly **skips** `assert_preconditions()` and is callable by anyone: [3](#0-2) 

The inline comment justifies this design with: *"There is no security risk to allowing this function to be open because it can only act on promises that were created via `schedule`."* This reasoning is flawed for the same reason as the LayerZero case: it does not account for the state of the authorizing system (the Aurora Engine) at the time of execution.

The Aurora Engine enforces a `require_running` check on every EVM-facing entry point, including the XCC precompile path that ultimately calls `schedule`: [4](#0-3) [5](#0-4) 

However, `execute_scheduled` is a direct NEAR call to the router sub-account — it never passes through the engine at all. The engine's pause state is never consulted.

The `PromiseArgs` stored by `schedule` can encode powerful NEAR operations including `Transfer`, `FunctionCall`, `DeployContract`, and `AddFullAccessKey`: [6](#0-5) [7](#0-6) 

---

### Impact Explanation

**High — Temporary freezing of funds bypass / potential theft of in-motion funds.**

When the Aurora Engine owner pauses the engine (e.g., in response to a critical exploit), the intent is to halt all EVM-originated operations, including outbound NEAR cross-contract calls. However, any promises that were already stored in a router's `scheduled_promises` map before the pause can still be executed by any NEAR account by calling `execute_scheduled(nonce)` directly on the router sub-account. This completely circumvents the pause.

Concretely, the router contract holds NEAR (deposited via `fund_xcc_sub_account` and `withdraw_wnear_to_router`). A scheduled promise of type `Transfer { amount }` or a `FunctionCall` to a DeFi protocol with attached NEAR will execute and move those funds even while the engine is paused. If the pause was triggered precisely because a malicious EVM contract was draining funds via XCC, the already-queued scheduled promises from that contract continue to execute.

---

### Likelihood Explanation

**Medium.** The scenario requires:
1. One or more `Delayed` XCC calls to have been scheduled (i.e., `CrossContractCallArgs::Delayed` submitted via the XCC precompile) before the engine is paused.
2. The engine to be paused while those promises remain unexecuted in storage.

Both conditions are realistic in a security-incident response scenario, which is precisely when the pause mechanism is most critical. The attacker entry point (`execute_scheduled`) is a public, permissionless NEAR function call requiring no special access.

---

### Recommendation

Add a re-validation step inside `execute_scheduled` that calls back to the parent (Aurora Engine) to confirm it is still in a running state before executing the stored promise. Alternatively, add a cancellation mechanism (callable only by the parent) so the engine can purge scheduled promises when it is paused. At minimum, document that `execute_scheduled` is not subject to the engine's pause and evaluate whether this is acceptable.

---

### Proof of Concept

1. EVM user calls the XCC precompile with `CrossContractCallArgs::Delayed(call)` where `call` encodes a NEAR token transfer of 10 NEAR to attacker-controlled account `attacker.near`.
2. The engine calls `schedule` on the user's router (`{address}.aurora`), storing the `PromiseArgs` at nonce `N` in `scheduled_promises`.
3. The Aurora Engine owner discovers a critical exploit and calls `pause` on the engine. All subsequent `submit` / XCC precompile calls now fail at `require_running`.
4. The attacker (or anyone) calls `execute_scheduled(N)` directly on `{address}.aurora` — a plain NEAR transaction, no engine involvement.
5. `execute_scheduled` removes the promise from storage and calls `env::promise_create` / `env::promise_return` with the stored `Transfer { amount: 10 NEAR }` action.
6. 10 NEAR is transferred to `attacker.near`. The engine pause had no effect. [8](#0-7) [9](#0-8)

### Citations

**File:** etc/xcc-router/src/lib.rs (L128-133)
```rust
    pub fn execute(&self, #[serializer(borsh)] promise: PromiseArgs) {
        self.assert_preconditions();

        let promise_id = Self::promise_create(promise);
        env::promise_return(promise_id);
    }
```

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

**File:** etc/xcc-router/src/lib.rs (L196-208)
```rust
    /// These preconditions must be checked on methods where are important for
    /// the security of the contract (e.g. `execute`).
    fn require_preconditions(&self) -> Result<(), Error> {
        let parent = self.get_parent()?;
        require_caller(&parent)?;
        require_no_failed_promises()?;
        Ok(())
    }

    /// Panics if any of the preconditions checked in `require_preconditions` are not met.
    fn assert_preconditions(&self) {
        self.require_preconditions().unwrap_or_else(env_panic);
    }
```

**File:** etc/xcc-router/src/lib.rs (L210-216)
```rust
    fn promise_create(promise: PromiseArgs) -> PromiseIndex {
        match promise {
            PromiseArgs::Create(call) => Self::base_promise_create(&call),
            PromiseArgs::Callback(cb) => Self::cb_promise_create(&cb),
            PromiseArgs::Recursive(p) => Self::recursive_promise_create(&p),
        }
    }
```

**File:** etc/xcc-router/src/lib.rs (L289-354)
```rust
    #[cfg(feature = "all-promise-actions")]
    fn add_batch_actions(id: PromiseIndex, actions: &[PromiseAction]) {
        for action in actions.iter() {
            match action {
                PromiseAction::CreateAccount => env::promise_batch_action_create_account(id),
                PromiseAction::Transfer { amount } => env::promise_batch_action_transfer(
                    id,
                    NearToken::from_yoctonear(amount.as_u128()),
                ),
                PromiseAction::DeployContract { code } => {
                    env::promise_batch_action_deploy_contract(id, code)
                }
                PromiseAction::FunctionCall {
                    name,
                    args,
                    attached_yocto,
                    gas,
                } => env::promise_batch_action_function_call(
                    id,
                    name,
                    args,
                    NearToken::from_yoctonear(attached_yocto.as_u128()),
                    Gas::from_gas(gas.as_u64()),
                ),
                PromiseAction::Stake { amount, public_key } => env::promise_batch_action_stake(
                    id,
                    NearToken::from_yoctonear(amount.as_u128()),
                    &to_sdk_pk(public_key),
                ),
                PromiseAction::AddFullAccessKey { public_key, nonce } => {
                    env::promise_batch_action_add_key_with_full_access(
                        id,
                        &to_sdk_pk(public_key),
                        *nonce,
                    )
                }
                PromiseAction::AddFunctionCallKey {
                    public_key,
                    nonce,
                    allowance,
                    receiver_id,
                    function_names,
                } => {
                    let receiver_id = receiver_id.as_ref().parse().unwrap();
                    env::promise_batch_action_add_key_allowance_with_function_call(
                        id,
                        &to_sdk_pk(public_key),
                        *nonce,
                        near_sdk::Allowance::limited(NearToken::from_yoctonear(
                            allowance.as_u128(),
                        ))
                        .unwrap(),
                        &receiver_id,
                        function_names,
                    )
                }
                PromiseAction::DeleteKey { public_key } => {
                    env::promise_batch_action_delete_key(id, &to_sdk_pk(public_key))
                }
                PromiseAction::DeleteAccount { beneficiary_id } => {
                    let beneficiary_id = beneficiary_id.as_ref().parse().unwrap();
                    env::promise_batch_action_delete_account(id, &beneficiary_id)
                }
            }
        }
    }
```

**File:** engine/src/contract_methods/xcc.rs (L29-35)
```rust
    with_logs_hashchain(io, env, function_name!(), |io| {
        let state = state::get_state(&io)?;
        require_running(&state)?;
        env.assert_private_call()?;
        if matches!(handler.promise_result_check(), Some(false)) {
            return Err(b"ERR_CALLBACK_OF_FAILED_PROMISE".into());
        }
```

**File:** engine-precompiles/src/xcc.rs (L99-133)
```rust
impl<I: IO> HandleBasedPrecompile for CrossContractCall<I> {
    #[allow(clippy::too_many_lines)]
    fn run_with_handle(
        &self,
        handle: &mut impl PrecompileHandle,
    ) -> Result<PrecompileOutput, PrecompileFailure> {
        let input = handle.input();
        let target_gas = handle.gas_limit().map(EthGas::new);
        let context = handle.context();
        utils::validate_no_value_attached_to_precompile(context.apparent_value)?;
        let is_static = handle.is_static();

        // This only includes the cost we can easily derive without parsing the input.
        // This allows failing fast without wasting computation on parsing.
        let input_len = u64::try_from(input.len()).map_err(utils::err_usize_conv)?;
        let mut cost =
            costs::CROSS_CONTRACT_CALL_BASE + costs::CROSS_CONTRACT_CALL_BYTE * input_len;
        let check_cost = |cost: EthGas| -> Result<(), PrecompileFailure> {
            if let Some(target_gas) = target_gas
                && cost > target_gas
            {
                return Err(PrecompileFailure::Error {
                    exit_status: ExitError::OutOfGas,
                });
            }
            Ok(())
        };
        check_cost(cost)?;

        // It's not allowed to call cross contract call precompile in static or delegate mode
        if is_static {
            return Err(revert_with_message(consts::ERR_STATIC));
        } else if context.address != cross_contract_call::ADDRESS.raw() {
            return Err(revert_with_message(consts::ERR_DELEGATE));
        }
```
