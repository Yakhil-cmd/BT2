### Title
Missing Storage Collision Check in CREATE/CREATE2 Allows Deployment at Addresses with Non-Empty Storage - (`evm_interpreter/src/ee_trait_impl.rs`)

---

### Summary

ZKsync OS's EVM interpreter explicitly skips the EIP-684 storage-collision check during `CREATE`/`CREATE2` deployment. Per the EVM specification, a deployment must fail if the target address already has non-empty storage. ZKsync OS acknowledges this check is absent and cannot be performed. An unprivileged caller can exploit this to deploy a new contract at a recycled address that retains stale storage from a previously self-destructed contract, causing the new contract to inherit storage values it never wrote. This produces a state root that diverges from Ethereum mainnet for the same transaction sequence.

---

### Finding Description

In `evm_interpreter/src/ee_trait_impl.rs`, the `before_executing_frame` function performs the address-collision check for `Constructor` calls. It checks `deployee_code_len != 0 || deployee_nonce != 0` but explicitly omits the storage-root check required by EIP-684:

```rust
// Check there's no contract already deployed at this address.
// NB: EVM also specifies that the address should have empty storage,
// but we cannot perform such a check for now.
if deployee_code_len != 0 || deployee_nonce != 0 {
    ...
    return Ok(false); // CreateCollision
}
```

The comment "but we cannot perform such a check for now" confirms this is a known, unresolved gap. The test index files corroborate this with multiple disabled test cases:

- `create2collisionStorageParis.json` — disabled: *"We do not check storage for collision"*
- `RevertInCreateInInitCreate2Paris.json` — disabled: *"We do not check for storage collisions"*

In Cancun (EIP-6780), `SELFDESTRUCT` no longer clears an account's storage — it only clears code and resets nonce/balance. This means a self-destructed contract leaves its storage slots intact in the state tree. A subsequent `CREATE2` at the same address should fail per EIP-684 (non-empty storage root), but ZKsync OS allows it to succeed.

---

### Impact Explanation

A new contract deployed at a recycled address inherits stale storage values from the previously self-destructed contract. The new contract's constructor and runtime code observe pre-populated storage slots it never wrote. This leads to:

1. **Incorrect contract state at deployment**: Token balances, access-control mappings, counters, or any storage-backed invariants are pre-set to attacker-controlled values from the prior contract.
2. **State-transition divergence**: ZKsync OS produces a different post-block state root than Ethereum mainnet would for the same transaction sequence, breaking EVM equivalence guarantees.
3. **Proof validity concern**: The prover proves a state transition that is invalid by Ethereum rules, meaning the proven output state is incorrect relative to the canonical EVM.

---

### Likelihood Explanation

The attack requires no privileged access. Any unprivileged user can:
1. Deploy a contract via `CREATE2` with a known salt.
2. Have that contract write to storage and call `SELFDESTRUCT`.
3. Re-deploy at the same address via `CREATE2` with the same salt.

All steps are standard EVM operations available to any EOA. The sequence is deterministic and fully attacker-controlled. The only constraint is that the attacker must control the deployer address and salt, which is trivially satisfied by the attacker themselves being the deployer.

---

### Recommendation

Implement the EIP-684 storage-collision check. Before executing a constructor frame, read the deployee account's storage root (or check whether any storage slots are non-zero) and return `CreateCollision` if the storage is non-empty. In the flat storage model, this requires checking whether any storage keys under the target address exist in the state tree prior to deployment.

---

### Proof of Concept

1. Attacker deploys contract `A` at address `X` via `CREATE2(salt=S)`. `A`'s constructor writes `storage[0] = 0xdeadbeef`.
2. `A` calls `SELFDESTRUCT(beneficiary)`. Under EIP-6780 (Cancun), `A`'s code is cleared and nonce reset to 0, but `storage[0]` remains in the state tree.
3. Attacker calls `CREATE2(salt=S)` again, computing the same address `X`.
4. In Ethereum mainnet: deployment fails with `CreateCollision` because `X` has non-empty storage.
5. In ZKsync OS: `before_executing_frame` checks only `deployee_code_len != 0 || deployee_nonce != 0`. Both are 0 (code was cleared, nonce was reset). The check passes and the constructor executes.
6. The new contract `B` at `X` reads `storage[0]` and observes `0xdeadbeef` — a value it never wrote.

**Root cause line:** [1](#0-0) 

**Disabled test confirming the gap:** [2](#0-1) [3](#0-2)

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

**File:** tests/evm_tester/indexes/develop-blockchain-tests.yaml (L2737-2740)
```yaml
              RevertInCreateInInitCreate2Paris.json:
                hash: '0xd89c5a3c6ccc430e2e4a0c6bb5d2dd01'
                enabled: false
                comment: We do not check for storage collisions
```

**File:** tests/evm_tester/indexes/develop-blockchain-tests.yaml (L2789-2792)
```yaml
              create2collisionStorageParis.json:
                hash: '0x575599861f8c1a6319cf46a3cc8bc52c'
                enabled: false
                comment: We do not check storage for collision
```
