### Title
Native Resource Griefing via Uncapped Callee Consumption Causes Full Transaction Revert — (`basic_bootloader/src/bootloader/runner.rs`)

---

### Summary

ZKsync OS unconditionally transfers **all** native resources from the caller frame to the callee frame on every external call. There is no per-frame cap analogous to EVM's 63/64 rule for native resources. A malicious callee can deliberately exhaust the entire native resource budget, triggering a `FatalRuntimeError` that reverts the **entire transaction** — not merely the sub-call. Any on-chain protocol that calls a user-controlled contract (e.g., ERC-20 transfer hooks, ERC-721 `onReceived` callbacks, flash-loan callbacks) is therefore vulnerable to a griefing attack that permanently prevents the caller from completing a critical operation.

---

### Finding Description

**Root cause — `give_native_to` in `runner.rs`**

When the bootloader prepares a callee frame for a non-entry-frame call, it first computes the ergs to pass (applying the 63/64 rule), then unconditionally moves every remaining native unit to the callee:

```rust
// Give native resource to the callee.
resources_in_caller_frame.give_native_to(&mut callee_resources);
```

After this line `resources_in_caller_frame` holds **zero** native resources. The callee receives the full budget. [1](#0-0) 

This is explicitly documented as a design property:

> "The native resources are passed fully from frame to frame, a call cannot set a limit on how much of it the callee can spend." [2](#0-1) 

**Fatal propagation — out-of-native reverts the whole transaction**

Unlike EVM out-of-gas in a sub-call (which only reverts the sub-call and returns 0 gas to the caller), exhausting native resources raises a `FatalRuntimeError`. The bootloader catches this at the transaction level and reverts the entire transaction:

```rust
RootCause::Runtime(e @ RuntimeError::FatalRuntimeError(_)) => {
    context.resources.main_resources.exhaust_ergs();
    system.finish_global_frame(Some(&main_body_rollback_handle))?;
    (ExecutionResult::Revert { output: &[] }, None)
}
``` [3](#0-2) 

The same pattern applies to L1 transactions: [4](#0-3) 

**How a callee exhausts native resources**

Every EVM operation charges both ergs and native. Storage reads/writes, memory expansion, and even basic arithmetic all consume native: [5](#0-4) 

A malicious contract can loop over storage reads or writes until native is exhausted. Because native is passed fully and cannot be capped, the caller has no defence.

**Contrast with ergs (EVM gas)**

For ergs, the 63/64 rule is applied before the transfer:

```rust
let max_passable_ergs =
    gas_utils::apply_63_64_rule(resources_available_in_caller_frame.ergs());
let ergs_to_pass = core::cmp::min(call_request.ergs_to_pass, max_passable_ergs);
``` [6](#0-5) 

No equivalent rule exists for native resources. The caller retains 1/64 of ergs but **zero** native after any call.

---

### Impact Explanation

Any ZKsync OS protocol that calls a user-supplied or user-controlled contract address is vulnerable:

- **ERC-20 / ERC-721 callbacks** (`onERC20Received`, `onERC721Received`, `tokensReceived`): the recipient contract exhausts native resources, reverting the transfer transaction entirely.
- **Flash-loan callbacks**: the borrower exhausts native resources, preventing the lender from completing the loan cycle.
- **DEX / AMM hooks**: a malicious pool or token contract exhausts native resources, preventing settlement.
- **Any `CALL` to an attacker-controlled address**: the attacker deploys a contract that loops over `SSTORE`/`SLOAD` until native is zero.

The victim's transaction is permanently reverted. The attacker pays only the gas for their own contract's execution (which is refunded as part of the revert). The victim loses their gas and cannot complete the operation.

---

### Likelihood Explanation

- **Attacker-controlled entry path**: any unprivileged user can deploy a contract on ZKsync OS and cause any caller that calls it to have their transaction reverted.
- **No special privilege required**: the attack requires only deploying a contract and having a victim protocol call it.
- **Realistic scenario**: ERC-20 tokens with transfer hooks, ERC-721 safe transfers, and flash-loan callbacks are ubiquitous in DeFi. Any such protocol deployed on ZKsync OS is immediately exposed.
- **Asymmetric cost**: the attacker's native consumption is bounded by the victim's native budget (which the attacker receives for free via the call), making the attack essentially free for the attacker.

---

### Recommendation

1. **Introduce a native resource cap per call frame**, analogous to the 63/64 rule for ergs. The caller should be able to specify a maximum native budget for the callee, retaining the remainder.
2. **Alternatively**, treat out-of-native in a sub-call as a sub-call revert (returning 0 native to the caller) rather than a fatal transaction-level error, matching EVM semantics for out-of-gas.
3. **Document the risk** prominently for protocol developers: any `CALL` to a user-controlled address on ZKsync OS can exhaust native resources and revert the entire transaction.

---

### Proof of Concept

**Setup**:
- Victim protocol `V` calls `token.transfer(recipient, amount)` where `recipient` is attacker-controlled.
- `recipient` is a contract with `onERC20Received` that loops: `for i in 0..N { sstore(i, 1); }` until native is exhausted.

**Execution trace**:
1. `V` initiates `token.transfer(recipient, amount)` — all native resources transferred to `token` frame.
2. `token` calls `recipient.onERC20Received(...)` — all native resources transferred to `recipient` frame.
3. `recipient` executes `SSTORE` in a loop, consuming native at `COLD_NEW_STORAGE_WRITE_EXTRA_NATIVE_COST` per iteration.
4. Native reaches zero → `DecreasingNative::charge` returns `out_of_native_resources!()` error. [7](#0-6) 
5. Error propagates as `FatalRuntimeError` through the call stack.
6. Bootloader catches it at transaction level, exhausts ergs, rolls back entire transaction. [3](#0-2) 
7. `V`'s `transfer` call is permanently reverted. `V` cannot complete the operation regardless of how many times it retries with the same gas limit, because the attacker will always exhaust the native budget.

### Citations

**File:** basic_bootloader/src/bootloader/runner.rs (L703-705)
```rust
        // Give native resource to the callee.
        resources_in_caller_frame.give_native_to(&mut callee_resources);
        callee_resources
```

**File:** docs/double_resource_accounting.md (L21-21)
```markdown
The native resources are passed fully from frame to frame, a call cannot set a limit on how much of it the callee can spend.
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/mod.rs (L357-366)
```rust
            Err(e) => match e.root_cause() {
                RootCause::Runtime(e @ RuntimeError::FatalRuntimeError(_)) => {
                    system_log!(
                        system,
                        "Transaction ran out of native resources or memory: {e:?}\n"
                    );
                    context.resources.main_resources.exhaust_ergs();
                    system.finish_global_frame(Some(&main_body_rollback_handle))?;
                    (ExecutionResult::Revert { output: &[] }, None)
                }
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L218-235)
```rust
                    match e.root_cause() {
                        // Out of native / memory is converted to a top-level
                        // revert so post-execution L1 accounting can still run.
                        RootCause::Runtime(runtime @ RuntimeError::FatalRuntimeError(_)) => {
                            system_log!(
                                system,
                                "L1 transaction ran out of native resources or memory {runtime:?}\n"
                            );
                            resources.exhaust_ergs();
                            system.finish_global_frame(Some(&rollback_handle))?;
                            (
                                false,
                                Vec::new_in(system.get_allocator()),
                                None,
                                S::Resources::empty(),
                                memories,
                            )
                        }
```

**File:** evm_interpreter/src/gas.rs (L76-89)
```rust
    #[inline(always)]
    /// Spend gas and "native" (proving) resource. This double accounting approach is used to keep track of actual proving cost
    pub(crate) fn spend_gas_and_native(&mut self, gas: u64, native: u64) -> Result<(), ExitCode> {
        use zk_ee::system::Computational;
        let Some(ergs_cost) = gas.checked_mul(ERGS_PER_GAS) else {
            return Err(EvmError::OutOfGas.into());
        };
        let resource_cost = S::Resources::from_ergs_and_native(
            Ergs(ergs_cost),
            Computational::from_computational(native),
        );
        self.resources.charge(&resource_cost)?;
        Ok(())
    }
```

**File:** evm_interpreter/src/ee_trait_impl.rs (L325-327)
```rust
        let max_passable_ergs =
            gas_utils::apply_63_64_rule(resources_available_in_caller_frame.ergs());
        let ergs_to_pass = core::cmp::min(call_request.ergs_to_pass, max_passable_ergs);
```

**File:** zk_ee/src/reference_implementations/mod.rs (L27-31)
```rust
    fn charge(&mut self, to_charge: &Self) -> Result<(), SystemError> {
        if self.0 < to_charge.0 {
            self.0 = 0;
            return Err(out_of_native_resources!().into());
        }
```
