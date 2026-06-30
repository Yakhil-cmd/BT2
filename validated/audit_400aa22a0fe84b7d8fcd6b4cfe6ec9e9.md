### Title
Unrestricted `execute_scheduled` Caller Enables Timing-Based Fund Theft via Sandwich Attacks on XCC Router - (File: `etc/xcc-router/src/lib.rs`)

### Summary
The XCC router's `execute_scheduled` function is intentionally callable by any unprivileged account. This allows an attacker to choose the exact moment a victim's scheduled NEAR cross-contract call executes, enabling front-running, back-running, and sandwiching attacks against price-sensitive operations. This is a direct analog to the report's finding that "the redeemer of a delegation chain can freely choose the time of redemption and can also influence the chain state for a redemption or wait for a particular state that is considered favorable."

### Finding Description

The XCC router contract exposes `execute_scheduled` with no access control on the caller: [1](#0-0) 

The comment explicitly acknowledges this is intentional:

> "It is intentional that this function can be called by anyone (not just the parent). There is no security risk to allowing this function to be open because it can only act on promises that were created via `schedule`."

However, this reasoning ignores the timing dimension. The `schedule` method, which stores a promise, requires the parent (Aurora Engine) as caller and is gated by `assert_preconditions()`: [2](#0-1) [3](#0-2) 

But `execute_scheduled` has none of these precondition checks. Contrast with `execute`, which enforces `assert_preconditions()` (caller must be parent, no failed promises): [4](#0-3) 

The scheduled promise is stored on-chain in `scheduled_promises` and is publicly readable. Any observer can:
1. Read the pending promise content and nonce
2. Manipulate on-chain state (e.g., DEX prices) before execution
3. Call `execute_scheduled(nonce)` at the optimal moment for their attack

The EVM-side entry point that creates scheduled promises is `CrossContractCallArgs::Delayed` in the XCC precompile: [5](#0-4) 

This is reachable by any unprivileged EVM user sending a transaction to the XCC precompile at address `0x516cded1d16af10cad47d6d49128e2eb7d27b372`. [6](#0-5) 

### Impact Explanation

**Classification: High — Theft of user funds.**

A user who schedules a NEAR cross-contract call involving a price-sensitive operation (e.g., a token swap on a NEAR DEX, a collateral liquidation, or a time-sensitive token transfer) has no control over when `execute_scheduled` is invoked. An attacker who monitors the router's `scheduled_promises` storage can:

1. Observe the pending promise (target contract, method, args, attached NEAR)
2. Front-run by manipulating the relevant on-chain state (e.g., buy tokens to inflate price)
3. Trigger `execute_scheduled` to execute the victim's promise at the worst possible price
4. Back-run to profit from the price impact

The victim's funds are transferred at an attacker-controlled time and state, resulting in direct financial loss. The attacker captures the difference between the expected and actual execution price.

### Likelihood Explanation

**Medium.** The attack requires:
- Monitoring the XCC router's on-chain storage for scheduled promises (trivially done via NEAR RPC)
- Capital to manipulate the relevant market
- Ability to call `execute_scheduled` before the legitimate user does

All three conditions are achievable by any unprivileged on-chain actor. The nonce is sequential and predictable: [7](#0-6) 

There is no race condition protection, no time-lock, and no slippage guard at the router level.

### Recommendation

1. **Restrict `execute_scheduled` to the parent (Aurora Engine) or the router's own account**, consistent with how `execute` and `schedule` are protected. If open execution is desired, add a configurable time-lock so the scheduling user has a window to execute before others can.
2. **Alternatively**, document clearly that scheduled promises must not contain price-sensitive operations without application-level slippage protection in the promise arguments themselves.
3. Consider adding a `min_execution_block` or `earliest_execution_timestamp` field to `PromiseArgs` for scheduled calls, enforced inside `execute_scheduled`.

### Proof of Concept

**Attacker-controlled entry path:**

1. Victim calls the XCC precompile from an EVM transaction with `CrossContractCallArgs::Delayed(PromiseArgs::Create(...))` — e.g., a call to a NEAR DEX's `swap` method. [5](#0-4) 

2. The engine routes this to the router's `schedule` method, storing the promise at nonce `N` in `scheduled_promises`. [2](#0-1) 

3. Attacker reads `scheduled_promises[N]` from on-chain state, sees the DEX swap details.

4. Attacker front-runs: buys the output token on the DEX, inflating its price.

5. Attacker calls `execute_scheduled({"nonce": N})` on the router contract — no access check, succeeds unconditionally: [8](#0-7) 

6. Victim's swap executes at the inflated price. Attacker back-runs by selling the output token.

7. Victim receives fewer tokens than expected; attacker profits the spread.

### Citations

**File:** etc/xcc-router/src/lib.rs (L128-133)
```rust
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

**File:** etc/xcc-router/src/lib.rs (L198-208)
```rust
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

**File:** engine-precompiles/src/xcc.rs (L86-97)
```rust
    ///
    /// Address: `0x516cded1d16af10cad47d6d49128e2eb7d27b372`
    /// This address is computed as: `&keccak("nearCrossContractCall")[12..]`
    pub const ADDRESS: Address = make_address(0x516cded1, 0xd16af10cad47d6d49128e2eb7d27b372);

    /// Sentinel value used to indicate the following topic field is how much NEAR the
    /// cross-contract call will require.
    pub const AMOUNT_TOPIC: H256 = crate::make_h256(
        0x0072657175697265645f6e656172,
        0x0072657175697265645f6e656172,
    );
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
