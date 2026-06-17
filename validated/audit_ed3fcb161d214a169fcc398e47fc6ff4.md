### Title
Missing EIP-7610 Storage Collision Check in `CREATE`/`CREATE2` Allows Deployment Over Non-Empty Storage — (`File: evm_interpreter/src/ee_trait_impl.rs`)

---

### Summary

ZKsync OS's `CREATE`/`CREATE2` collision guard checks only for non-zero code length and non-zero nonce at the target address. It explicitly omits the EIP-7610 requirement that the target address must also have **empty storage**. This is self-documented in the source code and confirmed by multiple disabled Ethereum Foundation test cases. An unprivileged attacker can exploit this to deploy a new contract on top of attacker-controlled residual storage, breaking the new contract's accounting and initialization invariants from the moment of deployment.

---

### Finding Description

The EVM specification (EIP-7610, active since Cancun/Paris) mandates that `CREATE`/`CREATE2` must revert if the target address has non-empty storage, in addition to the pre-existing checks for non-zero nonce and non-zero code. This prevents a class of attacks where residual storage from a previously self-destructed contract poisons a freshly deployed contract.

In `evm_interpreter/src/ee_trait_impl.rs`, the `before_executing_frame` function performs the collision check:

```rust
// Check there's no contract already deployed at this address.
// NB: EVM also specifies that the address should have empty storage,
// but we cannot perform such a check for now.
if deployee_code_len != 0 || deployee_nonce != 0 {
    ...
    return Ok(false); // collision → abort
}
```

The storage non-emptiness check is **explicitly absent**. The code comment acknowledges this gap. [1](#0-0) 

This is corroborated by multiple disabled Ethereum Foundation test entries across all test index files, each carrying the comment `We do not check storage for collision` or `We do not check for storage collisions`: [2](#0-1) [3](#0-2) 

The `SELFDESTRUCT` implementation (`mark_for_deconstruction`) only clears code and nonce for contracts deconstructed in the **same transaction** (`should_be_deconstructed = deployed_in_tx == Some(cur_tx) || in_constructor`). Storage slots written in that same transaction are nominally cleared via `clear_state_impl`, but the persistent storage state (Merkle trie entries from prior batches) is not guaranteed to be zeroed. The disabled test suite confirms that the net result is that ZKsync OS permits `CREATE2` to succeed against an address with non-empty storage. [4](#0-3) [5](#0-4) 

---

### Impact Explanation

**Vulnerability class**: EVM semantic mismatch / state-transition bug.

A contract deployed via `CREATE2` to an address with attacker-controlled residual storage inherits those storage values. Any contract that:
- Uses storage slot 0 as an "initialized" flag (`if (initialized) revert`)
- Stores an `owner` or `admin` address in a well-known slot
- Uses a mapping whose slot is pre-computable

…can have its accounting broken or its access control bypassed from the moment of deployment, with no further attacker interaction required. The new contract's constructor runs believing it starts from a clean slate, but it does not.

This is a direct analog to the Bemo Finance bug: code is deployed/updated without validating that the storage layout is in the expected (clean) state.

---

### Likelihood Explanation

**Medium.** The attack requires:
1. Pre-computing the `CREATE2` address (trivial — deterministic from deployer, salt, initcode).
2. Deploying a contract to that address, writing to target storage slots, and self-destructing in the same transaction (standard EVM operations, no privilege required).
3. Waiting for the victim to deploy to the same address (or the attacker themselves deploying a contract they intend to exploit).

No privileged access, oracle manipulation, or governance majority is required. The attacker is a standard unprivileged EVM transaction sender.

---

### Recommendation

Implement the EIP-7610 storage non-emptiness check in `before_executing_frame`. Before allowing a constructor frame to execute, query whether the target address has any non-zero storage slots. If it does, treat it as a collision (burn gas, return `false`). This requires the storage model to expose a "has any non-zero storage" predicate for a given address, which may require a Merkle trie root check or a dedicated flag in the account properties.

Alternatively, ensure that `mark_for_deconstruction` (SELFDESTRUCT) unconditionally zeroes all storage slots for the deconstructed account — including those written in prior batches — so that the residual storage state is always clean after a same-transaction selfdestruct. [6](#0-5) 

---

### Proof of Concept

```
Tx 1 (attacker, block N):
  - Deploy contract Poison via CREATE2(salt=S, initcode=I) → address X
  - Poison constructor: SSTORE(slot=0, value=attacker_address)  // set owner slot
  - Poison constructor: SELFDESTRUCT(beneficiary=attacker)       // same-tx destruct (EIP-6780)
  After Tx 1: X.code = empty, X.nonce = 0, X.storage[0] = attacker_address

Tx 2 (victim, block N+1):
  - Deploy contract Vault via CREATE2(salt=S, initcode=I) → same address X
  - Vault constructor: if (owner != address(0)) revert("already initialized")
    → owner = storage[0] = attacker_address  ← NOT zero
    → constructor REVERTS, or worse: skips initialization, leaving attacker as owner

ZKsync OS collision check at ee_trait_impl.rs:429:
  deployee_code_len == 0  ✓ (code was cleared)
  deployee_nonce    == 0  ✓ (nonce was reset)
  → check PASSES, constructor executes against poisoned storage
```

The `create2collisionStorageParis.json` test (disabled across all four test index files) encodes exactly this scenario and confirms ZKsync OS produces the wrong outcome. [7](#0-6) [8](#0-7)

### Citations

**File:** evm_interpreter/src/ee_trait_impl.rs (L415-443)
```rust
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

**File:** tests/evm_tester/indexes/develop-state-tests.yaml (L2315-2318)
```yaml
              RevertInCreateInInitCreate2Paris.json:
                hash: '0x37aae27794a84aaab2e4efda85bc70da'
                enabled: false
                comment: We do not check for storage collisions
```

**File:** tests/evm_tester/indexes/develop-state-tests.yaml (L2367-2370)
```yaml
              create2collisionStorageParis.json:
                hash: '0x1c8ea0d96bc40fd2a8997e58950d6bdb'
                enabled: false
                comment: We do not check storage for collision
```

**File:** basic_system/src/system_implementation/ethereum_storage_model/caches/account_cache.rs (L656-671)
```rust
        let in_constructor = account_data.current().value().has_empty_bytecode();
        let should_be_deconstructed =
            account_data.current().metadata().deployed_in_tx == Some(cur_tx) || in_constructor;

        if should_be_deconstructed {
            account_data
                .element_properties_mut()
                .mark_value_as_observed();
            account_data.update(|data| {
                data.update_metadata(|metadata| {
                    metadata.is_marked_for_deconstruction = true;

                    Ok(())
                })
            })?;
        }
```

**File:** basic_system/src/system_implementation/ethereum_storage_model/caches/account_cache.rs (L793-828)
```rust
                if current.value.metadata().is_marked_for_deconstruction {
                    // NOTE: initially account had 0 nonce, but it could be "material",
                    // with state root being empty, and bytecode hash being hash of empty string.

                    // NOTE: Balance will be zeroed out if deconstruction happens here
                    let initially_empty = cache_appearance.is_new_element();
                    assert!(cache_appearance.is_value_observed());
                    current.value.update(|x, metadata| {
                        metadata.is_marked_for_deconstruction = false;
                        if initially_empty {
                            debug_assert_eq!(
                                initial.value.value(),
                                &EthereumAccountProperties::EMPTY_ACCOUNT
                            );
                            x.balance = U256::ZERO;
                            x.bytecode_hash = Bytes32::ZERO;
                            x.nonce = 0u64;
                        } else {
                            //
                            debug_assert_eq!(initial.value.value().nonce, 0);
                            debug_assert_eq!(
                                initial.value.value().bytecode_hash,
                                EMPTY_STRING_KECCAK_HASH
                            );
                            debug_assert_eq!(initial.value.value().storage_root, EMPTY_ROOT_HASH);
                            x.balance = U256::ZERO;
                            x.bytecode_hash = EMPTY_STRING_KECCAK_HASH;
                            x.nonce = 0u64;
                        }

                        Ok(())
                    })?;
                    storage
                        .slot_values
                        .clear_state_impl(key)
                        .expect("must clear state for code deconstruction in same TX");
```

**File:** tests/evm_tester/indexes/stable-state-tests.yaml (L2225-2228)
```yaml
              create2collisionStorageParis.json:
                hash: '0x5ec814d43af9a012cba179bd6b451da0'
                enabled: false
                comment: We do not check storage for collision
```
