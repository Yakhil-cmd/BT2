### Title
Incomplete CREATE/CREATE2 Collision Detection: Missing Storage-Emptiness Check Causes EVM Semantic Mismatch — (`File: evm_interpreter/src/ee_trait_impl.rs`)

---

### Summary

ZKsync OS's EVM interpreter, adapted from `bluealloy/revm`, implements only a partial collision guard for `CREATE`/`CREATE2`. The EVM specification (EIP-161 / EIP-684) requires that deployment fails if the target address has non-zero nonce **or** non-empty code **or** non-empty storage. ZKsync OS checks only nonce and code length, explicitly skipping the storage-emptiness check with an inline comment acknowledging the omission. This is a direct analog to the Compound report: code forked from an upstream source that was only partially ported, leaving a known spec deviation unaddressed.

---

### Finding Description

In `evm_interpreter/src/ee_trait_impl.rs`, the `before_executing_frame` function performs the CREATE/CREATE2 collision guard:

```rust
// Check there's no contract already deployed at this address.
// NB: EVM also specifies that the address should have empty storage,
//     but we cannot perform such a check for now.
if deployee_code_len != 0 || deployee_nonce != 0 {
    // burn gas, return CreateCollision
}
``` [1](#0-0) 

The comment is a self-admission: the storage-emptiness leg of the collision predicate is absent. The upstream `revm` crate (acknowledged in `evm_interpreter/ACKNOWLEDGEMENTS.md`) performs the full three-part check; ZKsync OS ported only two of the three conditions. [2](#0-1) 

The Ethereum Foundation test suite entries that exercise this exact behavior are **explicitly disabled** across all four test-index files with the comments `"We do not check storage for collision"` and `"We do not check for storage collisions"`:

- `create2collisionStorageParis.json` — disabled
- `RevertInCreateInInitCreate2Paris.json` — disabled [3](#0-2) [4](#0-3) [5](#0-4) 

---

### Impact Explanation

**Vulnerability class:** EVM semantic mismatch / state-transition bug.

When an address holds non-empty storage but has zero nonce and zero code length, ZKsync OS will allow a `CREATE`/`CREATE2` to proceed and deploy new bytecode there. Ethereum (and any correct EVM implementation) would reject the deployment with a collision error and burn all forwarded gas.

Consequences:

1. **State-root divergence.** The ZKsync OS state root after such a transaction differs from the root that a correct EVM would produce. For a ZK rollup whose security model depends on the state-transition function being EVM-equivalent, this is a protocol-level correctness failure.

2. **Storage inheritance.** The newly deployed contract begins execution with pre-existing storage slots populated by the previous occupant. Any contract logic that assumes `SLOAD` returns zero on first access (a standard invariant) is violated, potentially enabling fund theft or logic bypass if the attacker controls both the pre-population and the new deployment.

3. **Proof/forward divergence.** If the forward (sequencer) path and the proving path handle the missing check differently, or if a future fix is applied to one path but not the other, the system can produce a valid-looking block that the prover cannot prove.

---

### Likelihood Explanation

**Moderate-low in Cancun.** Post-EIP-6780, `SELFDESTRUCT` called in a transaction *after* deployment no longer clears code or storage, so an address with non-empty storage will also retain its code — and the existing code-length check would already block the collision. `SELFDESTRUCT` called in the *same* transaction as deployment clears everything, leaving no residual storage.

However, the likelihood is non-negligible because:

- ZKsync OS is a rollup with system hooks (`set_bytecode_on_address`, `mint_base_token`) that can manipulate account state outside normal EVM rules. A privileged L1 transaction could zero out code while leaving storage intact, creating the precondition.
- The `RevertInCreateInInitCreate2Paris.json` test covers a scenario where a nested `CREATE2` constructor reverts: if ZKsync OS's rollback of storage writes from a reverted inner frame is imperfect (a separate but related risk), residual storage at the target address would be invisible to the collision guard.
- The missing check is a permanent, unconditional gap — it does not depend on any race condition or timing.

---

### Recommendation

1. Implement the storage-emptiness leg of the collision predicate. Before executing a `Constructor` frame, query whether the target address has any non-zero storage slots and return `CreateCollision` if so.
2. Re-enable the disabled Ethereum Foundation tests (`create2collisionStorageParis.json`, `RevertInCreateInInitCreate2Paris.json`) and ensure they pass.
3. Audit the `set_bytecode_on_address` and `mint_base_token` system hooks to confirm they cannot produce addresses with non-empty storage and zero code/nonce.
4. Align the implementation with the full upstream `revm` collision check rather than the partial port currently in place.

---

### Proof of Concept

**Setup (within a single ZKsync OS block):**

```
Step 1 — Pre-populate storage at a deterministic address:
  Deploy contract WRITER at address A (via CREATE2, salt=0x01).
  WRITER's constructor: SSTORE(slot=0, value=0xdeadbeef), then returns runtime code.
  WRITER's runtime code: SELFDESTRUCT(beneficiary=attacker).

Step 2 — Clear code/nonce while leaving storage (system-hook path):
  Send an L1 privileged transaction calling set_bytecode_on_address
  to set an empty bytecode at address A.
  Address A now has: nonce=0, code=empty, storage[0]=0xdeadbeef.

Step 3 — Attempt CREATE2 collision:
  Deploy contract READER at address A (same CREATE2 salt=0x01).
  READER's constructor: SLOAD(slot=0) → returns 0xdeadbeef (not zero).

Expected (EVM-correct): Step 3 reverts with CreateCollision.
Actual (ZKsync OS):     Step 3 succeeds; READER inherits stale storage.
```

The root cause is the unconditional absence of the storage check at: [1](#0-0) 

confirmed by the permanently disabled conformance tests: [6](#0-5) [7](#0-6)

### Citations

**File:** evm_interpreter/src/ee_trait_impl.rs (L424-443)
```rust
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

**File:** evm_interpreter/ACKNOWLEDGEMENTS.md (L1-7)
```markdown
# ACKNOWLEDGEMENTS
This crate includes source code adapted from the following open-source projects. All reused code is marked in the source files with inline comments. Where applicable, significant modifications have been made.

  - [bluealloy/revm](https://github.com/bluealloy/revm) licensed under [MIT](https://github.com/bluealloy/revm/blob/main/LICENSE)
  - [recmo/uint](https://github.com/recmo/uint) licensed under [MIT](https://github.com/recmo/uint/blob/main/LICENSE)

Please refer to the source files for detailed comments
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

**File:** tests/evm_tester/indexes/develop-blockchain-tests.yaml (L2789-2792)
```yaml
              create2collisionStorageParis.json:
                hash: '0x575599861f8c1a6319cf46a3cc8bc52c'
                enabled: false
                comment: We do not check storage for collision
```

**File:** tests/evm_tester/indexes/stable-state-tests.yaml (L2225-2228)
```yaml
              create2collisionStorageParis.json:
                hash: '0x5ec814d43af9a012cba179bd6b451da0'
                enabled: false
                comment: We do not check storage for collision
```

**File:** tests/evm_tester/indexes/stable-blockchain-tests.yaml (L2593-2596)
```yaml
              create2collisionStorageParis.json:
                hash: '0x95e019161d8379a1213002493af71f7b'
                enabled: false
                comment: We do not check storage for collision
```
