### Title
Unbounded Delay on Scheduled XCC Promises Enables Front-Running and Sandwich Attacks — (File: etc/xcc-router/src/lib.rs)

---

### Summary

The XCC router's `execute_scheduled` function imposes no expiry or deadline on stored promises. Any third party can trigger execution of a user's scheduled cross-contract call at an arbitrarily chosen future time. When the scheduled promise encodes a time-sensitive financial operation (e.g., a token swap on a NEAR-native DEX), an attacker can sandwich the execution — manipulating on-chain state before and after — causing the user to receive less value than intended, constituting direct theft of user funds.

---

### Finding Description

**Root cause — no deadline field in `PromiseArgs` / `PromiseCreateArgs`:**

`PromiseCreateArgs` carries only `target_account_id`, `method`, `args`, `attached_balance`, and `attached_gas`. There is no `deadline` or `not_after` field. [1](#0-0) 

**Root cause — `execute_scheduled` is callable by anyone with no time check:**

The router explicitly documents and implements open access: [2](#0-1) 

The comment on line 146 states the design assumption: "There is no security risk to allowing this function to be open because it can only act on promises that were created via `schedule`." This assumption is violated when the promise encodes a price-sensitive DeFi operation.

**How a promise reaches the router:**

An EVM contract calls the XCC precompile with `CrossContractCallArgs::Delayed(promise_args)`. The engine routes this to the router's `schedule` method (callable only by the Aurora Engine parent), which stores the promise under a monotonically increasing nonce with no timestamp: [3](#0-2) [4](#0-3) 

**Exploit flow:**

1. Victim EVM contract calls the XCC precompile with `Delayed(swap_promise)` where `swap_promise.args` encodes a DEX swap (e.g., Ref Finance `swap` call) with no `deadline` field in the swap args.
2. The engine calls `router.schedule(swap_promise)` — stored at nonce `N` in `scheduled_promises`.
3. Attacker observes the NEAR chain (the `schedule` call is public on-chain).
4. Attacker executes a large opposing trade on the DEX, moving the price adversely for the victim.
5. Attacker calls `victim_router.execute_scheduled({"nonce": "N"})` — no access control, no time check.
6. Victim's swap executes at the manipulated price; victim receives far fewer tokens.
7. Attacker reverses their trade, pocketing the spread.

The `execute_scheduled` function removes the promise from storage and fires it unconditionally: [5](#0-4) 

---

### Impact Explanation

**Impact: High — Direct theft of user funds (value in motion).**

A user who schedules a DeFi operation via `CrossContractCallArgs::Delayed` has their financial intent frozen in the router with no expiry. An attacker with zero privilege can choose the exact block in which the promise executes, enabling a classic sandwich attack. The victim loses the price-impact difference; the attacker captures it. The loss is bounded only by the size of the scheduled operation and the attacker's capital to move the DEX price.

---

### Likelihood Explanation

**Likelihood: Medium.**

- The XCC `Delayed` path is a documented, production-supported feature used when a user needs more gas than a single NEAR transaction provides.
- NEAR chain state is fully public; any observer can enumerate `scheduled_promises` by watching `schedule` calls.
- No special privilege is required to call `execute_scheduled`.
- The attack requires the attacker to have capital to move a DEX price, which is realistic for any liquid pool.
- The window of opportunity is unlimited — the promise never expires.

---

### Recommendation

1. **Add an optional `deadline` field to `PromiseArgs` / `PromiseCreateArgs`** (or as a wrapper in `CrossContractCallArgs::Delayed`) that records the block height or timestamp after which the promise must not be executed.
2. **Enforce the deadline in `execute_scheduled`**: compare `env::block_timestamp()` (or `env::block_index()`) against the stored deadline and panic if exceeded.
3. **Alternatively**, restrict `execute_scheduled` so that only the router's parent (Aurora Engine) or the originating EVM address can trigger execution, removing the open-access property that enables the timing attack.

---

### Proof of Concept

```
1. Deploy a NEAR DEX pool (e.g., Ref Finance fork) with TOKEN_A / TOKEN_B.
2. Victim EVM contract calls XCC precompile:
     CrossContractCallArgs::Delayed(PromiseArgs::Create(PromiseCreateArgs {
         target_account_id: "dex.near",
         method: "swap",
         args: b'{"token_in":"token_a","amount_in":"1000","min_amount_out":"1"}',
         attached_balance: Yocto::new(1),
         attached_gas: NearGas::new(50_000_000_000_000),
     }))
   Engine calls router.schedule(promise) → stored at nonce 0.
3. Attacker observes nonce 0 in victim's router storage.
4. Attacker submits large TOKEN_A → TOKEN_B swap on DEX, crashing TOKEN_B price.
5. Attacker calls:
     victim_router.execute_scheduled({"nonce": "0"})
   (no access control, succeeds immediately)
6. Victim's swap executes at the manipulated price; victim receives ~1 TOKEN_B
   instead of the fair-market ~950 TOKEN_B.
7. Attacker reverses their trade, capturing the spread.
```

The `execute_scheduled` open-access design is confirmed by the router test suite: [6](#0-5)

### Citations

**File:** engine-types/src/parameters/promise.rs (L8-14)
```rust
#[must_use]
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub enum PromiseArgs {
    Create(PromiseCreateArgs),
    Callback(PromiseWithCallbackArgs),
    Recursive(NearPromise),
}
```

**File:** engine-types/src/parameters/promise.rs (L272-285)
```rust
/// Args passed to the cross contract call precompile.
/// That precompile is used by Aurora contracts to make calls to the broader NEAR ecosystem.
/// See `https://github.com/aurora-is-near/AIPs/pull/2` for design details.
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

**File:** etc/xcc-router/src/tests.rs (L168-173)
```rust
    // promise executed after calling `execute_scheduled`
    // anyone can call this function
    testing_env!(VMContextBuilder::new()
        .predecessor_account_id(bob())
        .build());
    contract.execute_scheduled(0.into());
```
