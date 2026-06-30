### Title
Missing Scheduled-Promise Cancellation Allows Irrecoverable NEAR Drain from XCC Router — (`File: etc/xcc-router/src/lib.rs`)

### Summary

The XCC Router contract stores user-scheduled cross-contract promises under sequential nonces via `schedule()`, but provides no mechanism to cancel or invalidate a stored promise. `execute_scheduled()` is intentionally open to any caller. Once a `Delayed` XCC promise is stored in the router, the user has no on-chain path to cancel it, and any third party can force its execution at any time, irrevocably sending the router's NEAR balance to the promise's target.

### Finding Description

The `Router` contract in `etc/xcc-router/src/lib.rs` implements a two-phase cross-contract call flow:

1. **`schedule()`** — restricted to the parent (Aurora Engine). Stores a `PromiseArgs` at a sequential nonce in `scheduled_promises` and increments the nonce. [1](#0-0) 

2. **`execute_scheduled()`** — explicitly open to any caller. Removes the stored promise and executes it unconditionally. [2](#0-1) 

3. **No `cancel_scheduled()` or equivalent function exists anywhere in the contract.** [3](#0-2) 

The comment at line 146–148 asserts "There is no security risk to allowing this function to be open because it can only act on promises that were created via `schedule`." This reasoning is incomplete: it ignores the case where the user wants to cancel a scheduled promise before it executes.

On the EVM side, the XCC precompile only exposes `CrossContractCallArgs::Eager` and `CrossContractCallArgs::Delayed` — there is no `Cancel` variant and no EVM-level path to remove a stored promise. [4](#0-3) 

The precompile, when given `Delayed`, calls `schedule` on the router with the full `PromiseArgs` including `attached_balance` (NEAR to be forwarded to the target). [5](#0-4) 

The `attached_balance` field in `PromiseCreateArgs` is the NEAR that will be transferred from the router's account to the target contract when the promise executes. [6](#0-5) 

### Impact Explanation

Once a `Delayed` XCC promise with `attached_balance > 0` is stored in the router:

- The user has **no on-chain mechanism** to cancel it — neither via the EVM XCC precompile nor directly on the NEAR router contract.
- Any third party can call `execute_scheduled(nonce)` at any time, forcing the NEAR transfer to the target encoded in the promise.
- If the user made an error (wrong target account, wrong amount), the NEAR is irrecoverably sent to the wrong destination.
- Even if no error was made, the user cannot delay or prevent execution — a watcher can front-run any hypothetical cancellation.

The router holds up to `STORAGE_AMOUNT` = 2 NEAR in native balance plus any NEAR unwrapped from wNEAR for the promise's `attached_balance`. [7](#0-6) 

**Impact: High — Temporary freezing of funds** (user cannot recover NEAR from the router once a promise is scheduled) escalating to **permanent loss** if the target is incorrect or malicious.

### Likelihood Explanation

The `Delayed` XCC path is a production feature used in integration tests and documented as the mechanism for gas-expansion of expensive cross-contract calls. [8](#0-7) 

Any Aurora EVM user who calls the XCC precompile with `CrossContractCallArgs::Delayed` and includes a nonzero `attached_balance` is exposed. The attacker entry point — calling `execute_scheduled` — requires no privilege, no keys, and no special setup. Likelihood is **Medium**: the scenario requires a user to schedule a promise they later want to cancel, but the complete absence of any cancellation path makes this a systemic gap rather than an edge case.

### Recommendation

Add a `cancel_scheduled` function to the `Router` contract, callable only by the parent (Aurora Engine), that removes a stored promise by nonce:

```rust
pub fn cancel_scheduled(&mut self, nonce: U64) {
    self.assert_preconditions(); // parent-only
    if self.scheduled_promises.remove(&nonce.0).is_none() {
        env::panic_str("ERR_PROMISE_NOT_FOUND");
    }
}
```

Additionally, expose a corresponding cancellation path in the XCC precompile (a new `CrossContractCallArgs::Cancel(nonce)` variant) so EVM users can cancel their own scheduled promises from the Aurora EVM side.

### Proof of Concept

1. Alice (EVM address `0xALICE`) calls the XCC precompile with:
   ```
   CrossContractCallArgs::Delayed(PromiseArgs::Create(PromiseCreateArgs {
       target_account_id: "wrong.near",
       method: "receive",
       args: b"{}",
       attached_balance: Yocto::new(1_000_000_000_000_000_000_000_000), // 1 NEAR
       attached_gas: NearGas::new(10_000_000_000_000),
   }))
   ```
2. Aurora Engine calls `schedule()` on Alice's router (`0xalice.aurora`), storing the promise at nonce `0`. Alice's router now holds 1 NEAR earmarked for `wrong.near`.
3. Alice realizes the target is wrong and wants to cancel. She has no EVM or NEAR function to call.
4. Attacker (any NEAR account) calls:
   ```
   router_contract.execute_scheduled({"nonce": "0"})
   ```
5. The router executes the promise, sending 1 NEAR to `wrong.near`. Alice's funds are permanently lost.

The test in `etc/xcc-router/src/tests.rs` explicitly confirms that `execute_scheduled` succeeds when called by an arbitrary account (`bob()`), not just the parent: [9](#0-8)

### Citations

**File:** etc/xcc-router/src/lib.rs (L64-185)
```rust
#[near]
impl Router {
    #[init(ignore_state)]
    #[must_use]
    pub fn initialize(wnear_account: AccountId, must_register: bool) -> Self {
        // The first time this function is called there is no state and the parent is set to be
        // the predecessor account id. In subsequent calls, only the original parent is allowed to
        // call this function. The idea is that the Create, Deploy and Initialize actions are done in a single
        // NEAR batch when a new router is deployed by the engine, so the caller will be the Aurora
        // engine instance that the user's address belongs to. If we update this contract and deploy
        // a new version of it, again the Deploy and Initialize actions will be done in a single batch
        // by the engine.
        let caller = env::predecessor_account_id();
        let mut parent = LazyOption::new(StorageKey::Parent, None);
        match parent.get() {
            None => {
                parent.set(&caller);
            }
            Some(parent) => {
                // Allow self-calls to `initialize` also.
                // This happens during the upgrade flow.
                if (caller != parent) && (caller != env::current_account_id()) {
                    env::panic_str(ERR_ILLEGAL_CALLER);
                }
            }
        }

        if must_register {
            env::promise_create(
                wnear_account.clone(),
                "storage_deposit",
                b"{}",
                WNEAR_REGISTER_AMOUNT,
                WNEAR_REGISTER_GAS,
            );
        }

        let mut version = LazyOption::new(StorageKey::Version, None);
        if version.get().unwrap_or_default() != CURRENT_VERSION {
            // Future migrations would go here

            version.set(&CURRENT_VERSION);
        }

        let nonce = LazyOption::new(StorageKey::Nonce, None);
        let scheduled_promises = LookupMap::new(StorageKey::Map);
        Self {
            parent,
            version,
            nonce,
            scheduled_promises,
            wnear_account,
        }
    }

    pub fn get_version(&self) -> u32 {
        self.version.get().unwrap_or_default()
    }

    /// This function can only be called by the parent account (i.e. Aurora engine) to ensure that
    /// no one can create calls on behalf of the user this router contract is deployed for.
    /// The engine only calls this function when the special precompile in the EVM for NEAR cross
    /// contract calls is used by the address associated with the sub-account this router contract
    /// is deployed at.
    pub fn execute(&self, #[serializer(borsh)] promise: PromiseArgs) {
        self.assert_preconditions();

        let promise_id = Self::promise_create(promise);
        env::promise_return(promise_id);
    }

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

    /// Allows the parent contract to trigger an update to the logic of this contract
    /// (by deploying a new contract to this account);
    #[payable]
    pub fn deploy_upgrade(&mut self, #[serializer(borsh)] args: DeployUpgradeParams) {
        self.assert_preconditions();

        let promise_id = env::promise_batch_create(&env::current_account_id());
        env::promise_batch_action_deploy_contract(promise_id, &args.code);
        env::promise_batch_action_function_call(
            promise_id,
            INITIALIZE,
            &args.initialize_args,
            NearToken::default(),
            INITIALIZE_GAS,
        );
        env::promise_return(promise_id);
    }

    pub fn send_refund(&self) -> Promise {
        let parent = self.get_parent().unwrap_or_else(env_panic);

        require_caller(&parent)
            .and_then(|_| require_no_failed_promises())
            .unwrap_or_else(env_panic);

        Promise::new(parent).transfer(REFUND_AMOUNT)
    }
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

**File:** engine-types/src/parameters/promise.rs (L275-285)
```rust
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub enum CrossContractCallArgs {
    /// The promise is to be executed immediately (as part of the same NEAR transaction as the EVM call).
    Eager(PromiseArgs),
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

**File:** engine-precompiles/src/xcc.rs (L254-255)
```rust
    /// Amount of NEAR needed to cover storage for a router contract.
    pub const STORAGE_AMOUNT: Yocto = Yocto::new(2_000_000_000_000_000_000_000_000);
```

**File:** etc/xcc-router/src/tests.rs (L168-186)
```rust
    // promise executed after calling `execute_scheduled`
    // anyone can call this function
    testing_env!(VMContextBuilder::new()
        .predecessor_account_id(bob())
        .build());
    contract.execute_scheduled(0.into());

    assert_eq!(contract.nonce.get().unwrap(), 1);
    assert!(!contract.scheduled_promises.contains_key(&0));

    let mut receipts = test_utils::get_created_receipts();
    assert_eq!(receipts.len(), 1);
    let receipt = receipts.pop().unwrap();
    assert_eq!(
        receipt.receiver_id.as_str(),
        promise.target_account_id.as_ref()
    );
    validate_function_call_action(&receipt.actions, promise, 0);
}
```
