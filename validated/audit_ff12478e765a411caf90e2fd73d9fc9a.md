### Title
Incomplete CREATE Collision Check Misses Non-Empty Storage Condition - (File: `evm_interpreter/src/ee_trait_impl.rs`)

### Summary
The `before_executing_frame` function in the EVM interpreter checks for CREATE/CREATE2 collision by verifying `deployee_code_len != 0 || deployee_nonce != 0`, but omits the EVM-specified third condition: that the target address must also have empty storage. This mirrors the original report's pattern exactly — a guard that checks conditions A and B but silently skips condition C — allowing a CREATE to succeed in ZKsync OS at an address where Ethereum would reject it with a collision.

### Finding Description

In `evm_interpreter/src/ee_trait_impl.rs`, `before_executing_frame` performs the CREATE collision check:

```rust
if deployee_code_len != 0 || deployee_nonce != 0 {
    // Burn all gas and return false (collision)
}
```

The EVM specification (EIP-161 / Yellow Paper) defines a collision as: `nonce ≠ 0 ∨ code ≠ ∅ ∨ storage ≠ ∅`. ZKsync OS checks only the first two conditions. The code itself acknowledges the gap with a comment:

> "NB: EVM also specifies that the address should have empty storage, but we cannot perform such a check for now."

This means an account at the CREATE2 target address that has `nonce == 0`, `code_len == 0`, but **non-zero storage slots** will pass the collision guard and allow the constructor to execute, whereas Ethereum would abort the CREATE with a collision failure and burn all gas.

The root cause is in `before_executing_frame`: [1](#0-0) 

The incomplete guard checks only two of the three EVM collision conditions: [2](#0-1) 

The acknowledged missing check is documented inline: [3](#0-2) 

### Impact Explanation

**EVM semantic mismatch / state-transition divergence.** An attacker can craft a scenario where:

1. A contract writes to a storage slot at a deterministic CREATE2 target address `X` (e.g., via a helper contract that calls `SSTORE` at `X`).
2. The attacker then issues a CREATE2 transaction targeting `X`.
3. In ZKsync OS: `code_len == 0` and `nonce == 0` → collision guard passes → constructor executes → contract deployed at `X` with pre-existing storage inherited.
4. On Ethereum: `storage ≠ ∅` → collision detected → CREATE2 fails, all gas burned, no deployment.

The deployed contract at `X` silently inherits the pre-seeded storage. Any logic in the constructor or the deployed contract that assumes a clean slate (e.g., initializing a mapping, setting an owner) can be bypassed or corrupted by the attacker-controlled pre-existing storage values. This constitutes a provable forward/proving divergence: the sequencer's forward execution produces a different state root than Ethereum would for the same transaction sequence.

### Likelihood Explanation

**Medium.** The attack requires two transactions: one to seed storage at the target address, and one to CREATE2 at that address. Both are fully unprivileged. The target address is deterministically computable from `keccak256(0xff ++ deployer ++ salt ++ initcode_hash)`, so an attacker can pre-compute it and seed storage before deploying. No special access or leaked keys are required.

### Recommendation

Implement a storage-emptiness check as part of the CREATE collision guard. Before executing the constructor frame, verify that the target address has no non-zero storage slots. If the storage model cannot support a full scan, a per-transaction "dirty slot" counter or a flag set on first write to an address can serve as a conservative proxy. The check should be added alongside the existing `deployee_code_len` and `deployee_nonce` checks in `before_executing_frame`.

### Proof of Concept

```solidity
// Step 1: Seed storage at the future CREATE2 address
contract Seeder {
    function seed(address target, bytes32 slot, bytes32 val) external {
        assembly { sstore(add(target, slot), val) } // simplified; use delegatecall pattern
    }
}

// Step 2: Deploy via CREATE2 at the same address
contract Factory {
    function deploy(bytes32 salt, bytes memory initcode) external returns (address) {
        address addr;
        assembly { addr := create2(0, add(initcode, 0x20), mload(initcode), salt) }
        // On ZKsync OS: succeeds, addr has pre-seeded storage
        // On Ethereum:  fails (collision), addr == address(0)
        return addr;
    }
}
```

The attacker pre-computes the CREATE2 address, seeds a storage slot there via a helper contract, then calls `Factory.deploy`. ZKsync OS returns a valid contract address; Ethereum returns `address(0)`. The resulting state roots diverge. [4](#0-3)

### Citations

**File:** evm_interpreter/src/ee_trait_impl.rs (L372-447)
```rust
    fn before_executing_frame<'a, 'i: 'ee, 'h: 'ee>(
        system: &mut System<S>,
        frame_state: &mut ExecutionEnvironmentLaunchParams<'i, S>,
        tracer: &mut impl Tracer<S>,
    ) -> Result<bool, Self::SubsystemError>
    where
        S::IO: IOSubsystemExt,
    {
        if let Some(error) = check_depth_and_balance(
            system,
            &mut frame_state.external_call,
            frame_state.environment_parameters.callstack_depth,
        )? {
            tracer.evm_tracer().on_call_error(&error);
            return Ok(false);
        }

        if frame_state.external_call.modifier == CallModifier::Constructor {
            // Increase nonce. Ignore, if we are in the root frame - caller's nonce already incremented before.
            if frame_state.environment_parameters.callstack_depth > 0 {
                match frame_state
                    .external_call
                    .available_resources
                    .with_infinite_ergs(|inf_resources| {
                        system.io.increment_nonce(
                            THIS_EE_TYPE,
                            inf_resources,
                            &frame_state.external_call.caller,
                            1u64,
                        )
                    }) {
                    Ok(_) => {}
                    Err(SubsystemError::LeafUsage(InterfaceError(
                        NonceError::NonceOverflow,
                        _,
                    ))) => {
                        tracer.evm_tracer().on_call_error(&EvmError::NonceOverflow);
                        return Ok(false);
                    }
                    Err(e) => return Err(wrap_error!(e)),
                };
            };

            let deployee_code_len = frame_state
                .environment_parameters
                .callee_account_properties
                .unpadded_code_len;
            let deployee_nonce = frame_state
                .environment_parameters
                .callee_account_properties
                .nonce;

            // Check there's no contract already deployed at this address.
            // NB: EVM also specifies that the address should have empty storage,
            // but we cannot perform such a check for now.
            // We need to check this here (not when we actually deploy the code)
            // because if this check fails the constructor shouldn't be executed.
            if deployee_code_len != 0 || deployee_nonce != 0 {
                system_log!(system, "Deployment on existing account\n",);
                frame_state
                    .external_call
                    .available_resources
                    .charge(&S::Resources::from_ergs(
                        frame_state.external_call.available_resources.ergs(),
                    ))
                    .expect("Should succeed"); // Burn all gas

                tracer
                    .evm_tracer()
                    .on_call_error(&EvmError::CreateCollision);
                return Ok(false);
            }
        }

        Ok(true)
    }
```
