### Title
No Expiration or Cancellation for Scheduled XCC Promises — (File: `etc/xcc-router/src/lib.rs`)

---

### Summary

The XCC router's `schedule` function stores `PromiseArgs` in persistent on-chain storage with no expiration timestamp and no cancellation mechanism. The `execute_scheduled` function is callable by any external actor at any future time. NEAR tokens attached to a scheduled promise are locked in the router contract indefinitely, and the promise can be triggered at an arbitrarily stale point in time, with no way for the originating user to recover funds or abort execution.

---

### Finding Description

When an Aurora EVM user calls the XCC precompile with `CrossContractCallArgs::Delayed`, the engine:

1. Charges the user's wNEAR ERC-20 balance upfront for the full `attached_near` amount required by the promise (via `transferFrom` inside `run_with_handle`).
2. Constructs a `PromiseCreateArgs` targeting the router's `schedule` method and emits it as a log.
3. The engine's `filter_promises_from_logs` dispatches this as a real NEAR promise, causing `Router::schedule` to be called.

Inside `Router::schedule`, the `PromiseArgs` — including its `attached_balance` field (NEAR tokens) — is inserted into `scheduled_promises: LookupMap<u64, PromiseArgs>` keyed by a monotonically increasing nonce:

```rust
// etc/xcc-router/src/lib.rs
pub fn schedule(&mut self, #[serializer(borsh)] promise: PromiseArgs) {
    self.assert_preconditions();
    let nonce = self.nonce.get().unwrap_or_default();
    self.scheduled_promises.insert(nonce, promise);
    self.nonce.set(&(nonce + 1));
    near_sdk::log!("Promise scheduled at nonce {}", nonce);
}
``` [1](#0-0) 

No expiration block height or timestamp is stored alongside the promise. The `execute_scheduled` function is explicitly open to any caller with no time-based guard:

```rust
/// It is intentional that this function can be called by anyone (not just the parent).
#[payable]
pub fn execute_scheduled(&mut self, nonce: U64) {
    let Some(promise) = self.scheduled_promises.remove(&nonce.0) else {
        env::panic_str("ERR_PROMISE_NOT_FOUND")
    };
    let promise_id = Self::promise_create(promise);
    env::promise_return(promise_id);
}
``` [2](#0-1) 

There is no `cancel_scheduled` function anywhere in the `Router` contract. The complete set of public methods is `initialize`, `get_version`, `execute`, `schedule`, `execute_scheduled`, `deploy_upgrade`, and `send_refund`. [3](#0-2) 

The `PromiseArgs` stored in `scheduled_promises` carries `attached_balance` (yoctoNEAR). These tokens are held in the router sub-account's NEAR balance from the moment the wNEAR was unwrapped. They remain locked there until `execute_scheduled` is called — which can happen at any future time by any external actor. [4](#0-3) 

The `CrossContractCallArgs::Delayed` variant is the user-facing entry point through the EVM XCC precompile: [5](#0-4) 

---

### Impact Explanation

**High — Temporary freezing of funds.**

Any NEAR tokens attached to a `Delayed` XCC promise (`promise.attached_balance > 0`) are locked in the router sub-account from the moment the EVM transaction is processed. Because there is no expiration and no cancellation path, the user cannot recover these tokens if:

- The target contract's state changes (e.g., a DeFi protocol is paused, drained, or upgraded).
- The user's intent changes (e.g., a swap or governance action is no longer desired).
- The promise becomes economically harmful to execute (e.g., a token transfer at a stale price).

The NEAR remains frozen in the router until an external actor (anyone) calls `execute_scheduled`, which can happen arbitrarily far in the future. The user has no on-chain mechanism to abort this.

---

### Likelihood Explanation

**Medium.** Every Aurora EVM user who uses `CrossContractCallArgs::Delayed` with a non-zero `attached_balance` is affected. The `execute_scheduled` function is intentionally open to any caller (documented in the source), so any external actor can trigger execution at any time. The scenario where a user schedules a promise and later wants to cancel it is realistic in any DeFi or governance context.

---

### Recommendation

1. **Add an expiration field** to each stored promise entry (e.g., a `scheduled_at_block` or `expires_at_block`). In `execute_scheduled`, reject execution if the current block height exceeds the expiration.
2. **Add a `cancel_scheduled` function** callable only by the parent Aurora Engine (on behalf of the originating EVM address) that removes the promise from `scheduled_promises` and returns the locked NEAR to the router's balance (or back to the user via wNEAR).

---

### Proof of Concept

1. Alice calls the XCC precompile from her EVM address with `CrossContractCallArgs::Delayed(PromiseArgs::Create(promise))` where `promise.attached_balance = 10_000_000_000_000_000_000_000_000` (10 NEAR).
2. The engine charges Alice's wNEAR ERC-20 balance and dispatches `Router::schedule`. The 10 NEAR is now locked in Alice's router sub-account.
3. Alice realizes the target contract has been exploited and she no longer wants the transfer to execute.
4. Alice searches the `Router` ABI — there is no `cancel_scheduled` method.
5. Alice's 10 NEAR remains locked in the router indefinitely.
6. Six months later, Bob (any external actor) calls `execute_scheduled({"nonce": "0"})` on Alice's router sub-account. The stale promise executes, sending Alice's 10 NEAR to the now-compromised target contract.
7. Alice's funds are lost. [6](#0-5)

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
