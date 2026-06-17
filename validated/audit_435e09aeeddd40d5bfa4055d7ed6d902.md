### Title
Missing Storage Collision Check in CREATE/CREATE2 Deployment Allows Attacker-Controlled Initial Storage State - (File: `evm_interpreter/src/ee_trait_impl.rs`)

### Summary
The `before_executing_frame` function in the EVM interpreter checks for deployment address collisions using only `deployee_code_len != 0 || deployee_nonce != 0`, explicitly omitting the storage-emptiness check that the EVM specification requires. An attacker who can predict a CREATE2 target address can pre-populate its storage (via deploy → write → selfdestruct), then allow the legitimate CREATE2 to proceed — which ZKsync OS permits — causing the newly deployed contract to inherit attacker-controlled storage slots. This is an EVM semantic mismatch: standard EVM rejects CREATE/CREATE2 when the target address has non-empty storage; ZKsync OS does not.

---

### Finding Description

In `evm_interpreter/src/ee_trait_impl.rs`, the `before_executing_frame` function handles the constructor path for both `CREATE` and `CREATE2`. The collision guard reads only `unpadded_code_len` and `nonce` from `callee_account_properties`:

```rust
// Check there's no contract already deployed at this address.
// NB: EVM also specifies that the address should have empty storage,
// but we cannot perform such a check for now.
// We need to check this here (not when we actually deploy the code)
// because if this check fails the constructor shouldn't be executed.
if deployee_code_len != 0 || deployee_nonce != 0 {
    // ... burn all gas, return CreateCollision
}
``` [1](#0-0) 

The comment is a self-admission: the EVM spec requires the target address to also have empty storage, but ZKsync OS cannot perform this check. The `CalleeAccountProperties` struct passed into this function contains no storage field at all — it only carries `nonce`, `unpadded_code_len`, `bytecode`, etc. — so there is no mechanism to perform the check even if the guard were extended. [2](#0-1) 

The Ethereum test suite entries that exercise this exact scenario are explicitly disabled across all three test index files with the comments `"We do not check storage for collision"` and `"We do not check for storage collisions"`: [3](#0-2) [4](#0-3) 

The CREATE2 address is deterministically derived from `(0xff ++ deployer ++ salt ++ keccak256(initcode))`, making it fully predictable by any observer who knows the deployer's address, the salt, and the initcode. [5](#0-4) 

---

### Impact Explanation

**Vulnerability class:** EVM semantic mismatch / state-transition bug.

A contract deployed via CREATE2 on ZKsync OS can begin execution with attacker-controlled, non-zero storage slots. Any contract that:
- uses storage slot 0 as an `initialized` flag (OpenZeppelin `Initializable` pattern),
- stores an `owner` or `admin` address in a well-known slot,
- uses a mapping whose slot is predictable (e.g., `balances[attacker]`),

can be compromised at deployment time. The constructor runs against a storage state the deployer did not set and cannot detect, because the EVM provides no opcode to enumerate existing storage. The resulting on-chain state diverges from what Ethereum mainnet would produce for the same transaction sequence, breaking cross-chain equivalence guarantees.

---

### Likelihood Explanation

The attack requires:
1. Knowing the CREATE2 parameters in advance (deployer address, salt, initcode). For factory contracts with public or predictable salts this is trivially satisfied.
2. Deploying a contract to that address first, writing to target storage slots, then selfdestructing. Under EIP-6780 (Cancun, which ZKsync OS targets), SELFDESTRUCT within the same transaction clears code and balance but leaves storage intact across transactions.
3. Waiting for the legitimate deployment.

Steps 1–3 are cheap, permissionless, and repeatable. Any factory pattern (Uniswap v2/v3 pool factories, proxy deployers, deterministic deployer contracts) that uses public or guessable salts is a realistic target.

---

### Recommendation

The storage collision check must be added to `before_executing_frame`. Because `CalleeAccountProperties` does not carry a storage-emptiness signal, the fix requires one of:

1. **Extend `CalleeAccountProperties`** with an `has_nonempty_storage: bool` field populated by the IO layer before the frame is launched, and add the guard:
   ```rust
   if deployee_code_len != 0 || deployee_nonce != 0 || deployee_has_nonempty_storage {
       // CreateCollision
   }
   ```
2. **Query storage emptiness** via the IO subsystem at the point of the collision check, using a dedicated oracle query for the target address's storage root (analogous to how `unpadded_code_len` and `nonce` are already read from account properties).

Re-enable the disabled test cases `create2collisionStorageParis.json` and `RevertInCreateInInitCreate2Paris.json` as regression coverage once the fix is in place. [6](#0-5) 

---

### Proof of Concept

```
Block 1, Tx 1 (attacker):
  PUSH32 <salt>
  PUSH32 <len(initcode)>
  PUSH32 0          // offset
  PUSH32 0          // value
  CREATE2           // deploys attacker contract to addr A
                    // attacker constructor: SSTORE(0, attacker_address)
                    //                      SELFDESTRUCT(attacker)
  // After tx: addr A has nonce=0, code=empty, storage[0]=attacker_address

Block 2, Tx 1 (victim factory):
  // Factory calls CREATE2 with same deployer, salt, initcode
  // ZKsync OS: deployee_code_len==0, deployee_nonce==0 → no collision detected
  // Constructor executes; storage[0] is already attacker_address
  // If constructor does: if (owner == address(0)) owner = msg.sender;
  //   → condition is FALSE, owner remains attacker_address
```

On Ethereum mainnet, Block 2 Tx 1 would revert with a collision error. On ZKsync OS it succeeds, and the deployed contract's `owner` slot is permanently set to the attacker's address.

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

**File:** zk_ee/src/common_structs/callee_account_properties.rs (L1-13)
```rust
use ruint::aliases::U256;

pub struct CalleeAccountProperties<'a> {
    pub ee_type: u8,
    pub nonce: u64,
    pub nominal_token_balance: U256,
    pub bytecode: &'a [u8],
    pub code_version: u8,
    pub unpadded_code_len: u32,
    pub artifacts_len: u32,
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

**File:** evm_interpreter/src/interpreter.rs (L475-517)
```rust
    pub fn derive_address_for_deployment_create2(
        system: &mut System<S>,
        resources: &mut <S as SystemTypes>::Resources,
        salt: &U256,
        deployer_address: &<S::IOTypes as SystemIOTypesConfig>::Address,
        deployment_code: &[u8],
    ) -> Result<<S::IOTypes as SystemIOTypesConfig>::Address, EvmSubsystemError> {
        use crypto::sha3::{Digest, Keccak256};
        // we need to compute address based on the hash of the code and salt
        let mut initcode_hash = ArrayBuilder::default();
        resources
            .with_infinite_ergs(|inf_resources| {
                S::SystemFunctions::keccak256(
                    deployment_code,
                    &mut initcode_hash,
                    inf_resources,
                    system.get_allocator(),
                )
            })
            .map_err(|e| -> EvmSubsystemError {
                match e.root_cause() {
                    RootCause::Runtime(e @ RuntimeError::FatalRuntimeError(_)) => {
                        e.clone_or_copy().into()
                    }
                    _ => internal_error!("Keccak in create2 cannot fail").into(),
                }
            })?;
        let initcode_hash = Bytes32::from_array(initcode_hash.build());

        let mut create2_buffer = [0xffu8; 1 + 20 + 32 + 32];
        create2_buffer[1..(1 + 20)]
            .copy_from_slice(&deployer_address.to_be_bytes::<{ B160::BYTES }>());
        create2_buffer[(1 + 20)..(1 + 20 + 32)]
            .copy_from_slice(&salt.to_be_bytes::<{ U256::BYTES }>());
        create2_buffer[(1 + 20 + 32)..(1 + 20 + 32 + 32)]
            .copy_from_slice(initcode_hash.as_u8_array_ref());

        let new_address = Keccak256::digest(&create2_buffer);
        #[allow(deprecated)]
        let new_address =
            B160::try_from_be_slice(&new_address.as_slice()[12..]).expect("must create address");

        Ok(new_address)
```
