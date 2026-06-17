### Title
Callee Can Exhaust All Native Resources Despite Limited EVM Gas, Causing Entire Transaction Revert — (`basic_bootloader/src/bootloader/runner.rs`)

---

### Summary

ZKsync OS implements a **double resource accounting** model: EVM gas (ergs) and a separate **native resource** (proving cost). While EVM gas forwarded to a subcall is bounded by the 63/64 rule and the caller-specified gas limit, **native resources are transferred in full to every callee with no per-call limit**. A malicious callee can exhaust the entire native budget, triggering a `FatalRuntimeError::OutOfNativeResources` that propagates unconditionally to the top level and reverts the **entire transaction** — not just the subcall. The caller has no mechanism to prevent or catch this.

---

### Finding Description

**Vulnerability class:** Resource accounting bug — analogous to M-17's "staticcall burns 63/64 gas unexpectedly."

**Root cause — `runner.rs` line 703–704:**

```rust
// Give native resource to the callee.
resources_in_caller_frame.give_native_to(&mut callee_resources);
``` [1](#0-0) 

`give_native_to` moves **all** remaining native resources from the caller frame into the callee frame unconditionally:

```rust
fn give_native_to(&mut self, other: &mut Self) {
    let n = core::mem::replace(&mut self.native, Native::empty());
    other.native = n;
}
``` [2](#0-1) 

This is explicitly documented as a design property:

> "The native resources are passed fully from frame to frame, a call cannot set a limit on how much of it the callee can spend." [3](#0-2) 

**Contrast with EVM gas:** The 63/64 rule is correctly applied to ergs only:

```rust
let max_passable_ergs =
    gas_utils::apply_63_64_rule(resources_available_in_caller_frame.ergs());
let ergs_to_pass = core::cmp::min(call_request.ergs_to_pass, max_passable_ergs);
``` [4](#0-3) 

Native resources receive no analogous cap.

**Fatal propagation path:** When native resources are exhausted, the error is a `FatalRuntimeError::OutOfNativeResources`: [5](#0-4) 

This propagates to the top-level transaction handler, which exhausts all ergs and reverts the **entire transaction**:

```rust
RootCause::Runtime(e @ RuntimeError::FatalRuntimeError(_)) => {
    context.resources.main_resources.exhaust_ergs();
    system.finish_global_frame(Some(&main_body_rollback_handle))?;
    (ExecutionResult::Revert { output: &[] }, None)
}
``` [6](#0-5) 

The same pattern applies to L1 transactions: [7](#0-6) 

**Native cost per opcode is non-trivial.** Every opcode charges native resources. For example:

```
CALL_NATIVE_COST:     1_500
STATICCALL_NATIVE_COST: 1_500
DIV_NATIVE_COST:      1_500
MULMOD_NATIVE_COST:   4_000
CREATE_NATIVE_COST:   25_000
``` [8](#0-7) 

A malicious contract can loop through expensive opcodes or expand heap aggressively (`HEAP_EXPANSION_PER_BYTE_NATIVE_COST = 1` per byte) to drain the native budget. [9](#0-8) 

---

### Impact Explanation

A caller that issues `CALL{gas: N}(malicious_contract)` expects the subcall to be bounded by `N` gas. On Ethereum, if the subcall reverts or runs out of gas, the caller continues with its remaining gas. On ZKsync OS, if the callee exhausts native resources, the **entire transaction** reverts unconditionally — the caller cannot catch this with try/catch patterns, and the user loses their entire gas fee.

Concrete impact:
- **DOS of any contract that calls untrusted addresses** (e.g., DEX routers, token transfer hooks, reentrancy guards using limited-gas calls, ERC-777/ERC-1155 callbacks).
- **Full gas fee loss** for the victim: the transaction reverts with all gas consumed (`exhaust_ergs()` is called).
- **Unprovability / state divergence**: the forward runner and prover may disagree on whether a transaction reverted due to native exhaustion vs. EVM OOG, since native resource limits are derived from `gasPrice` which can vary.

---

### Likelihood Explanation

- Any contract that calls an untrusted address (token callbacks, DEX integrations, arbitrary `call` targets) is exposed.
- The attacker only needs to deploy a contract that loops expensive opcodes or allocates large heap memory.
- No privileged access is required; any unprivileged transaction sender can deploy the malicious callee.
- The attack is deterministic and reproducible.

---

### Recommendation

1. **Apply a native resource cap per subcall**, analogous to the 63/64 rule for ergs. The callee should receive at most `min(all_native, proportional_native_for_ergs_passed)` native resources.
2. Alternatively, treat `OutOfNativeResources` in a subcall as a **subcall-level revert** (returning 0 on the stack) rather than a fatal transaction-level revert, so the caller can continue.
3. Document clearly that any call to an untrusted address risks transaction-level revert due to native exhaustion, so protocol developers can avoid this pattern.

---

### Proof of Concept

```solidity
// Malicious callee: drains native resources via heap expansion + expensive opcodes
contract NativeDrainer {
    fallback() external {
        assembly {
            // Expand heap to maximum to drain HEAP_EXPANSION_PER_BYTE_NATIVE_COST
            // Then loop MULMOD (4000 native each) until native is exhausted
            let i := 0
            for {} lt(i, 100000) { i := add(i, 1) } {
                pop(mulmod(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
                           0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
                           3))
            }
        }
    }
}

// Victim contract: calls malicious contract with limited gas
contract Victim {
    function safeCheck(address target) external {
        // Caller expects this to be bounded by 10000 gas
        // But native resources are passed in full — entire tx reverts
        (bool ok,) = target.call{gas: 10000}("");
        require(ok, "check failed"); // never reached
    }
}
```

When `Victim.safeCheck(NativeDrainer)` is called:
1. `call_impl` creates `EVMCallRequest` with `ergs_to_pass = 10000 * ERGS_PER_GAS`.
2. `read_callee_and_prepare_frame_state` applies 63/64 to ergs but calls `give_native_to`, transferring **all** native resources to `NativeDrainer`.
3. `NativeDrainer` exhausts native resources → `FatalRuntimeError::OutOfNativeResources`.
4. Top-level handler exhausts ergs and reverts the entire transaction.
5. The caller's `require(ok, ...)` is never reached; the entire transaction reverts with full gas consumed. [10](#0-9) [11](#0-10) [12](#0-11)

### Citations

**File:** basic_bootloader/src/bootloader/runner.rs (L682-705)
```rust
    let resources_for_callee_frame = if !IS_ENTRY_FRAME {
        // now we should ask current EE to calculate resources for the callee frame
        let mut callee_resources =
            match SupportedEEVMState::<S>::calculate_resources_passed_in_external_call(
                caller_ee_version,
                &mut resources_in_caller_frame,
                &call_request,
                &callee_account_properties,
            ) {
                Ok(x) => x,
                Err(x) => {
                    if let RootCause::Runtime(RuntimeError::OutOfErgs(_)) = x.root_cause() {
                        return Ok(CallPreparationResult::OutOfErgs {
                            resources_in_caller_frame,
                        });
                    } else {
                        return Err(wrap_error!(x));
                    }
                }
            };

        // Give native resource to the callee.
        resources_in_caller_frame.give_native_to(&mut callee_resources);
        callee_resources
```

**File:** zk_ee/src/reference_implementations/mod.rs (L180-183)
```rust
    fn give_native_to(&mut self, other: &mut Self) {
        let n = core::mem::replace(&mut self.native, Native::empty());
        other.native = n;
    }
```

**File:** docs/double_resource_accounting.md (L19-21)
```markdown
If a transaction execution runs out of native resources, the entire transaction is reverted. If the same happens during transaction validation, the transaction is considered invalid.

The native resources are passed fully from frame to frame, a call cannot set a limit on how much of it the callee can spend.
```

**File:** evm_interpreter/src/ee_trait_impl.rs (L325-327)
```rust
        let max_passable_ergs =
            gas_utils::apply_63_64_rule(resources_available_in_caller_frame.ergs());
        let ergs_to_pass = core::cmp::min(call_request.ergs_to_pass, max_passable_ergs);
```

**File:** zk_ee/src/system/errors/runtime.rs (L12-14)
```rust
pub enum FatalRuntimeError {
    OutOfNativeResources(Metadata),
    OutOfReturnMemory(Metadata),
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/mod.rs (L357-365)
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
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L217-234)
```rust
                Err(e) => {
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
```

**File:** evm_interpreter/src/native_resource_constants.rs (L64-65)
```rust
pub const HEAP_EXPANSION_BASE_NATIVE_COST: u64 = 35;
pub const HEAP_EXPANSION_PER_BYTE_NATIVE_COST: u64 = 1;
```

**File:** evm_interpreter/src/native_resource_constants.rs (L86-91)
```rust
pub const CREATE_NATIVE_COST: u64 = 25_000;
pub const CREATE2_NATIVE_COST: u64 = 25_000;
pub const CALL_NATIVE_COST: u64 = 1_500;
pub const CALLCODE_NATIVE_COST: u64 = 1_500;
pub const DELEGATECALL_NATIVE_COST: u64 = 1_500;
pub const STATICCALL_NATIVE_COST: u64 = 1_500;
```

**File:** evm_interpreter/src/instructions/host.rs (L472-484)
```rust
        // at this preemption point we give all resources to the system
        let all_resources = self.gas.take_resources();

        *external_call_dest = Some(EVMCallRequest {
            ergs_to_pass: Ergs(gas_to_pass.saturating_mul(ERGS_PER_GAS)),
            call_value: value,
            destination_address: to,
            input_data: calldata,
            modifier: call_modifier,
            full_caller_resources: all_resources,
        });

        Err(ExitCode::ExternalCall)
```
