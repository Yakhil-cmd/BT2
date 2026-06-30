### Title
Unrestricted `execute_scheduled` in XCC Router Enables Sandwich Attacks on Scheduled DEX Swaps - (File: `etc/xcc-router/src/lib.rs`)

---

### Summary

The `execute_scheduled` function in the XCC router contract is intentionally callable by any NEAR account with no access control. Because scheduled promises can include DEX swaps on NEAR-native protocols (e.g., Ref Finance), an attacker can control the exact timing of execution, enabling a classic sandwich attack: front-run the swap to manipulate the pool price, trigger the victim's swap at the manipulated price, then back-run to extract profit at the victim's expense.

---

### Finding Description

The XCC router (`etc/xcc-router/src/lib.rs`) stores user-scheduled cross-contract promises in a public `LookupMap<u64, PromiseArgs>`. The `execute_scheduled` function removes and executes any stored promise by nonce:

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

The comment's security reasoning — "it can only act on promises that were created via `schedule`" — addresses *content* integrity but completely ignores *timing* control. The `schedule` function is correctly restricted to the parent (Aurora Engine), so the content of the promise is legitimate. However, the *moment of execution* is now controlled by any external NEAR account, not the original user.

NEAR contract storage is publicly readable. The `scheduled_promises` map uses a sequential nonce (`LazyOption<u64>`), making enumeration trivial. An attacker can:

1. Poll or subscribe to state changes on any XCC router sub-account (named `<evm_address>.<aurora_engine_account>`).
2. Decode the stored `PromiseArgs` to identify DEX swap calls (e.g., calls to `ft_transfer_call` on a NEAR DEX contract with swap parameters in the `msg` field).
3. Front-run: execute a buy of the output token on the target DEX pool, moving the price adversely for the victim.
4. Call `execute_scheduled` with the victim's nonce, triggering the swap at the now-manipulated price.
5. Back-run: sell the output token at the inflated price.

The victim (the EVM user who scheduled the swap) receives fewer tokens than expected. The attacker extracts the difference.

The `schedule` entry point is gated by `assert_preconditions` (requires `predecessor == parent`), so only Aurora Engine can create scheduled promises. But `execute_scheduled` has no such gate.

---

### Impact Explanation

**Critical — Direct theft of user funds in motion.**

When an EVM user uses the XCC precompile to schedule a NEAR DEX swap, their tokens are committed to the swap parameters at schedule time. The attacker controls when the swap executes, allowing them to guarantee the worst possible execution price for the victim. The value difference between the expected output and the actual output is extracted by the attacker. There is no mechanism for the victim to cancel a scheduled promise before it is executed (the `execute_scheduled` call removes it atomically).

---

### Likelihood Explanation

**Medium-High.** NEAR state is publicly readable with no special tooling. XCC router sub-accounts follow a deterministic naming scheme (`<hex_address>.<engine_account_id>`), making them discoverable. Any NEAR account can call `execute_scheduled` — no privileged access, no leaked keys, no social engineering required. The attacker only needs to monitor state and submit two NEAR transactions around the victim's scheduled call.

---

### Recommendation

Remove the open-caller assumption from `execute_scheduled`. Options:

1. **Restrict to parent only**: Apply `self.assert_preconditions()` (same as `execute` and `schedule`), requiring the Aurora Engine to be the caller. The engine can then expose a separate EVM-callable mechanism for the user to trigger their own scheduled promise.
2. **Restrict to the owning address**: Derive the owner from the sub-account name and require `predecessor == owner` or `predecessor == parent`.
3. **Add a deadline parameter to `PromiseArgs`**: Reject execution if the current block timestamp is outside the user-specified window, limiting the attacker's ability to choose an optimal moment.

---

### Proof of Concept

1. Alice (EVM address `0xALICE`) calls the XCC precompile to schedule a swap of 1,000 USDC → NEAR on Ref Finance. Aurora Engine calls `schedule` on `0xalice.<aurora>.near`, storing the promise at nonce `0`.
2. Attacker Bob reads `0xalice.<aurora>.near`'s storage, decodes the `PromiseArgs`, and identifies the Ref Finance swap call.
3. Bob submits a NEAR transaction buying NEAR from the USDC/NEAR pool, raising the NEAR price (pool reserves shift: NEAR decreases, USDC increases).
4. Bob calls `execute_scheduled` on `0xalice.<aurora>.near` with `nonce: 0`. The stored promise executes: Alice's 1,000 USDC is swapped at the now-worse rate, yielding significantly fewer NEAR.
5. Bob sells his NEAR back to the pool at the inflated price, pocketing the spread.
6. Alice's swap completes but she receives materially fewer NEAR than the pre-manipulation price would have given her. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** etc/xcc-router/src/lib.rs (L123-133)
```rust
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
