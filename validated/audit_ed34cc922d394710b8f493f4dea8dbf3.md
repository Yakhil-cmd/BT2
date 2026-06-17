### Title
Caller Nonce Incremented Before Collision Check in `before_executing_frame`, Leaving Permanent State Mutation on Failed CREATE - (`evm_interpreter/src/ee_trait_impl.rs`)

### Summary

In `evm_interpreter/src/ee_trait_impl.rs`, the `before_executing_frame` function for the EVM execution environment increments the **caller's nonce** before performing the collision check on the deployee address. When a `CREATE`/`CREATE2` fails due to a collision (`deployee_code_len != 0 || deployee_nonce != 0`), the function returns `Ok(false)` but the caller's nonce has already been permanently mutated. Because `before_executing_frame` is explicitly called outside the rollback snapshot in `runner.rs`, this nonce increment is never reverted. This violates the Checks-Effects-Interactions ordering principle and produces an EVM semantic mismatch: in standard EVM, a failed `CREATE` due to collision does not alter the caller's nonce.

### Finding Description

In `before_executing_frame`, for a nested `Constructor` call (`callstack_depth > 0`), the sequence is:

1. **Nonce increment** (state mutation) — caller's nonce is incremented unconditionally.
2. **Collision check** — if the deployee address already has code or a non-zero nonce, the function returns `Ok(false)` with `CreateCollision`. [1](#0-0) 

The caller's nonce is incremented at line 396 before the collision check at line 429. When the collision check fires and the function returns `Ok(false)`, the nonce increment is already committed.

In `runner.rs`, `before_executing_frame` is explicitly documented as containing "Pre-checks and operations that should not be rolled back if call fails", and the rollback snapshot (`start_global_frame`) is created only **after** `before_executing_frame` returns: [2](#0-1) 

This means any state change made inside `before_executing_frame` — including the nonce increment — is outside the rollback scope and is permanent, even when the call fails.

### Impact Explanation

An unprivileged attacker can deploy a contract that executes a `CREATE` or `CREATE2` opcode targeting an address already occupied by a deployed contract. The inner `CREATE` will fail with `CreateCollision`, but the **caller contract's nonce is permanently incremented**. This produces:

1. **EVM semantic mismatch / state-transition bug**: In standard EVM, a failed `CREATE` due to collision does not modify the caller's nonce. ZKsync OS diverges from this, producing a different post-state than Ethereum would.
2. **Nonce griefing**: Any contract whose nonce is used for deterministic address prediction (e.g., future `CREATE` address computation) can have its nonce advanced by an attacker, causing subsequent deployments to land at unexpected addresses.
3. **Forward/proving divergence**: The forward execution and proof will agree on the wrong post-state (incremented nonce), but this state is incorrect relative to the EVM specification, meaning the proven state transition is semantically invalid.

### Likelihood Explanation

The attack path is straightforward and requires no privileged access:

1. Identify any deployed contract address `T` (trivially available on-chain).
2. Deploy an attacker contract `A` that executes `CREATE` with initcode that computes to address `T` (or use `CREATE2` with a salt chosen to collide with `T`).
3. Call `A`. The inner `CREATE` fails with `CreateCollision`, but `A`'s nonce is permanently incremented.

This is fully reachable by any unprivileged transaction sender. The only constraint is finding a salt/nonce combination that produces a collision, which is trivially achievable with `CREATE2` by choosing the salt to target any known occupied address.

### Recommendation

Move the collision check **before** the caller nonce increment inside `before_executing_frame`. The corrected order should be:

1. Check depth and balance.
2. Read `deployee_code_len` and `deployee_nonce` from `callee_account_properties`.
3. If collision (`deployee_code_len != 0 || deployee_nonce != 0`), return `Ok(false)` immediately — **before** any state mutation.
4. Only if no collision, increment the caller's nonce.

This matches the Checks-Effects-Interactions pattern: all checks must pass before any state is mutated.

### Proof of Concept

```
1. Deploy contract A with bytecode that executes:
   CREATE2(value=0, offset=0, size=0, salt=S)
   where S is chosen so that CREATE2 address = address of an already-deployed contract B.

2. Call contract A from an EOA.

3. Observe:
   - The CREATE2 fails with CreateCollision (correct).
   - Contract A's nonce has been incremented by 1 (incorrect per EVM spec).
   - Repeated calls to A keep incrementing A's nonce.
   - Any future CREATE from A now deploys to a different address than expected.
```

The root cause is at: [3](#0-2) 

The nonce increment at line 396 (`system.io.increment_nonce(... &frame_state.external_call.caller ...)`) executes before the collision guard at line 429, and the runner's architecture ensures this increment is never rolled back: [2](#0-1)

### Citations

**File:** evm_interpreter/src/ee_trait_impl.rs (L389-443)
```rust
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
```

**File:** basic_bootloader/src/bootloader/runner.rs (L253-276)
```rust
        // Pre-checks and operations that should not be rolled back if call fails
        match SupportedEEVMState::before_executing_frame(
            interpret_as_ee_type,
            self.system,
            &mut external_call_launch_params,
            tracer,
        ) {
            Ok(success) => {
                if !success {
                    return Ok((
                        external_call_launch_params
                            .external_call
                            .available_resources,
                        CallResult::Failed {
                            return_values: ReturnValues::empty(),
                        },
                    ));
                }
            }
            Err(e) => return Err(wrap_error!(e)),
        }

        // Create snapshot for rollbacks
        let rollback_handle = self.system.start_global_frame()?;
```
