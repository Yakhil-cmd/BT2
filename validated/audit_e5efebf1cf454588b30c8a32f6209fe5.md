### Title
Missing Storage Collision Check in CREATE/CREATE2 Allows Attacker-Controlled Storage Inheritance - (`File: evm_interpreter/src/ee_trait_impl.rs`)

### Summary

ZKsync OS's EVM interpreter skips the EIP-7610 storage-non-empty collision check during `CREATE`/`CREATE2` deployment. An attacker who previously deployed and self-destructed a contract at a predictable `CREATE2` address can leave behind non-zero storage slots. When a victim later deploys a new contract at the same address, ZKsync OS allows the deployment to succeed — unlike Ethereum mainnet, which would revert — and the new contract silently inherits the attacker-controlled storage state.

### Finding Description

In `evm_interpreter/src/ee_trait_impl.rs`, the `before_executing_frame` function performs the collision check for constructor calls. It checks `code_len != 0 || nonce != 0`, but explicitly omits the storage-non-empty check required by EIP-7610:

```rust
// Check there's no contract already deployed at this address.
// NB: EVM also specifies that the address should have empty storage,
// but we cannot perform such a check for now.
if deployee_code_len != 0 || deployee_nonce != 0 {
    // ... revert
}
``` [1](#0-0) 

After a `SELFDESTRUCT`, the account's `code_len` and `nonce` are zeroed, but storage slots written during the prior deployment persist in the underlying storage tree. Because ZKsync OS only checks `code_len` and `nonce`, the subsequent `CREATE2` at the same address passes the collision guard and proceeds to execute the constructor — with the attacker's storage slots already in place.

This is explicitly acknowledged and confirmed by disabled test entries across all test index files: [2](#0-1) [3](#0-2) [4](#0-3) 

### Impact Explanation

A contract deployed via `CREATE2` at an address with pre-existing storage inherits attacker-controlled slot values. Any contract logic that assumes zero-initialized storage on deployment — access control mappings, balance accounting, initialization flags — can be bypassed or corrupted from the first instruction. This can lead to direct loss of funds or complete security bypass for contracts deployed on ZKsync OS that would be safe on Ethereum mainnet.

**Impact: Medium** — Requires a specific deployment pattern (CREATE2 with predictable salt), but the outcome is silent state corruption with potential fund loss.

### Likelihood Explanation

`CREATE2` addresses are fully deterministic and publicly computable from `(deployer, salt, initcode_hash)`. An attacker monitoring the mempool or knowing a protocol's deployment parameters can:
1. Compute the target address offline.
2. Deploy a contract there first, write storage slots, then self-destruct.
3. Wait for the victim's `CREATE2` transaction to execute.

The victim's deployment succeeds on ZKsync OS (unlike Ethereum), and the new contract starts with attacker-set storage. No privileged access is required.

**Likelihood: Medium** — Requires predicting the CREATE2 address and a prior deployment/selfdestruct at that address, which is realistic for known protocol deployments.

### Recommendation

Implement the EIP-7610 storage-non-empty collision check before executing a constructor frame. Before allowing a `CREATE`/`CREATE2` to proceed, verify that the target address has no non-zero storage slots. If the storage model cannot support a full scan, a per-address "has-ever-had-storage" flag written at first `SSTORE` and cleared only on full storage wipe would be a practical approximation.

### Proof of Concept

1. Attacker computes `addr = CREATE2(deployer=A, salt=S, initcode=I)`.
2. Attacker deploys a contract at `addr` (using the same `A`, `S`, `I`), writes `SSTORE(slot=0, value=1)`, then calls `SELFDESTRUCT`.
3. After the transaction, `addr` has `code_len=0`, `nonce=0`, but `storage[0]=1`.
4. Victim sends a `CREATE2` with the same parameters. On Ethereum (EIP-7610), this reverts. On ZKsync OS, `before_executing_frame` passes the `code_len==0 && nonce==0` check and the constructor executes.
5. The newly deployed contract reads `storage[0]` and finds `1` instead of `0`, violating its initialization invariants. [5](#0-4) [6](#0-5)

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

**File:** tests/evm_tester/indexes/develop-blockchain-tests.yaml (L864-874)
```yaml
      eip7610_create_collision:
        enabled: true
        entries:
          test_init_collision_create_opcode.json:
            hash: '0xf0e46f3aea9c4dce27e3679e2da73790'
            enabled: false
            comment: We do not check the storage
          test_init_collision_create_tx.json:
            hash: '0x3ec97d4636f319c42f2e150ca1f88fab'
            enabled: false
            comment: We do not check the storage
```

**File:** tests/evm_tester/indexes/develop-blockchain-tests.yaml (L3354-3357)
```yaml
              dynamicAccountOverwriteEmpty_Paris.json:
                hash: '0x34fa0f6aaf0b898eafda5e7e92e8f32c'
                enabled: false
                comment: Expects revert due to storage collision
```

**File:** tests/evm_tester/indexes/develop-state-tests.yaml (L2367-2370)
```yaml
              create2collisionStorageParis.json:
                hash: '0x1c8ea0d96bc40fd2a8997e58950d6bdb'
                enabled: false
                comment: We do not check storage for collision
```

**File:** evm_interpreter/src/instructions/host.rs (L333-354)
```rust
        let deployed_address = if IS_CREATE2 {
            let salt = self.stack.pop_1()?;
            Self::derive_address_for_deployment_create2(
                system,
                self.gas.resources_mut(),
                salt,
                &self.address,
                &self.heap[deployment_code.clone()],
            )?
        } else {
            let deployer_nonce = self.gas.resources.with_infinite_ergs(|inf_resources| {
                system
                    .io
                    .read_nonce(THIS_EE_TYPE, inf_resources, &self.address)
            })?;

            Self::derive_address_for_deployment_create(
                self.gas.resources_mut(),
                &self.address,
                deployer_nonce,
            )?
        };
```
