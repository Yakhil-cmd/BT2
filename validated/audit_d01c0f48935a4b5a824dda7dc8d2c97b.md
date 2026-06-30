### Title
Unauthenticated `execute_scheduled` Allows Any Caller to Force-Execute a User's Scheduled XCC Promise at Arbitrary Timing - (File: `etc/xcc-router/src/lib.rs`)

---

### Summary

The `execute_scheduled` function in the XCC router contract applies no access control, allowing any NEAR account to trigger execution of a user's scheduled cross-contract call promise at any time. Because the scheduled promise nonce is publicly logged on-chain, an adversary can observe it and front-run the user's own `execute_scheduled` call, forcing the promise to execute at an unfavorable moment. Since there is no cancellation mechanism, the user cannot abort or retry the promise once it has been consumed. If the forced execution fails, any NEAR tokens attached to the promise are refunded to the router contract, where they are temporarily frozen with no direct withdrawal path.

---

### Finding Description

The XCC router contract (`etc/xcc-router/src/lib.rs`) exposes three promise-related entry points:

- `execute` (line 128): gated by `assert_preconditions()`, which enforces `predecessor_account_id == self.parent` (the Aurora engine). [1](#0-0) 
- `schedule` (line 136): also gated by `assert_preconditions()`. [2](#0-1) 
- `execute_scheduled` (line 150): **no access control at all**. [3](#0-2) 

The code comment at line 146 explicitly acknowledges this is intentional:

> "It is intentional that this function can be called by anyone (not just the parent). There is no security risk to allowing this function to be open because it can only act on promises that were created via `schedule`."

This reasoning is incorrect. The promise *content* is user-controlled (it was created via the XCC precompile), but the *timing* of execution is security-relevant. The function removes the promise from storage and executes it immediately:

```rust
pub fn execute_scheduled(&mut self, nonce: U64) {
    let Some(promise) = self.scheduled_promises.remove(&nonce.0) else {
        env::panic_str("ERR_PROMISE_NOT_FOUND")
    };
    let promise_id = Self::promise_create(promise);
    env::promise_return(promise_id);
}
``` [4](#0-3) 

The nonce of each scheduled promise is publicly broadcast via a NEAR log at the time of scheduling:

```rust
near_sdk::log!("Promise scheduled at nonce {}", nonce);
``` [5](#0-4) 

Any NEAR account can observe this log, then call `execute_scheduled` with that nonce before the user does. The promise is consumed (removed from `scheduled_promises`) on first execution, so the user cannot retry it. There is no `cancel_scheduled` or equivalent function in the router. [6](#0-5) 

The `CrossContractCallArgs::Delayed` variant is specifically designed for cases where the user needs a fresh 300 Tgas budget in a separate transaction — meaning the user *must* use `execute_scheduled` to trigger the promise, and cannot fall back to the eager path after scheduling. [7](#0-6) 

**Attack path:**

1. An EVM contract at address `0xABCD…` calls the XCC precompile with `CrossContractCallArgs::Delayed(promise)`, where `promise` carries a non-zero `attached_balance` (NEAR to be sent to a target NEAR contract). The engine calls `schedule` on the router `abcd….aurora`, storing the promise at nonce `N` and emitting the log.
2. An adversary observes the log on-chain and immediately calls `execute_scheduled(N)` on the router before the user does.
3. The promise is executed at an adversary-chosen time — e.g., when the target contract is paused, when the recipient lacks storage registration, or when market conditions are unfavorable.
4. If the promise fails, the `attached_balance` NEAR is refunded to the router contract. The router has no general-purpose NEAR withdrawal function; the only outbound NEAR paths are `send_refund` (fixed 2 NEAR, parent-only) and future promise executions. [8](#0-7) 
5. To recover the stranded NEAR, the user must schedule a new promise via the XCC precompile. The adversary can front-run that execution too, sustaining the freeze.

The unit test in `etc/xcc-router/src/tests.rs` explicitly confirms that `bob()` (a non-parent account) can call `execute_scheduled` successfully: [9](#0-8) 

---

### Impact Explanation

**High — Temporary freezing of funds.**

When an adversary forces execution of a scheduled promise at a time when the target contract rejects the call, any NEAR tokens encoded in `attached_balance` of the `PromiseCreateArgs` are refunded to the router contract. The router has no direct withdrawal mechanism for arbitrary NEAR balances. The user's funds are frozen in the router until they can schedule and successfully execute a recovery promise — but the adversary can repeatedly front-run each recovery attempt, extending the freeze indefinitely. In the worst case this becomes a sustained, practically permanent freeze of the user's NEAR tokens held in the router.

---

### Likelihood Explanation

**Medium.** The scheduled promise nonce is emitted as a public NEAR log at the time of scheduling, making it trivially discoverable by any on-chain observer. The adversary only needs to submit a single NEAR transaction to `execute_scheduled` with the observed nonce before the user does. No privileged access, leaked keys, or governance capture is required. The attack is most profitable when the user's scheduled promise carries a significant `attached_balance`.

---

### Recommendation

Restrict `execute_scheduled` to the parent account (Aurora engine) or to the EVM address that owns the router sub-account, consistent with the access control applied to `execute` and `schedule`. If open execution is desired for gas-budget reasons, add a time-lock (minimum delay before anyone can call it) or a cancellation function so the user retains the ability to abort a scheduled promise before it is force-executed.

---

### Proof of Concept

```
1. User's EVM contract (address 0xABCD…) calls the XCC precompile:
     CrossContractCallArgs::Delayed(PromiseArgs::Create(PromiseCreateArgs {
         target_account_id: "some-defi.near",
         method: "swap",
         args: <swap_args>,
         attached_balance: Yocto::new(1_000_000_000_000_000_000_000_000), // 1 NEAR
         attached_gas: NearGas::new(100_000_000_000_000),
     }))

2. Aurora engine calls router.schedule(promise) → nonce 0 stored,
   log emitted: "Promise scheduled at nonce 0"

3. Adversary observes the log and calls:
     router_account = "abcd….aurora"
     router_account.execute_scheduled({"nonce": "0"})
   — no access check, call succeeds.

4. "some-defi.near" is paused at this moment; the swap fails.
   1 NEAR is refunded to the router contract.

5. User's 1 NEAR is now frozen in the router.
   User schedules a recovery promise → adversary front-runs again.
   Funds remain frozen.
```

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

**File:** etc/xcc-router/src/tests.rs (L169-185)
```rust
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
```
