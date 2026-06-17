Looking at the two storage model implementations of `mark_for_deconstruction` and the `in_constructor` heuristic, and cross-referencing with what happens when zero-length bytecode is deployed.

## Ethereum Storage Model — NOT Vulnerable

`has_empty_bytecode()` checks `bytecode_hash == Bytes32::ZERO` (the "never existed" sentinel). [1](#0-0) 

After deploying zero-length bytecode, `deploy_code` sets `bytecode_hash = keccak256([]) = EMPTY_STRING_KECCAK_HASH` (not `Bytes32::ZERO`). [2](#0-1) 

So `has_empty_bytecode()` returns **false** for a deployed zero-length contract. The ethereum storage model is safe.

## Flat Storage Model — VULNERABLE

The flat storage model uses a different, weaker heuristic: [3](#0-2) 

After deploying zero-length bytecode, `deploy_code` stores: [4](#0-3) [5](#0-4) 

So after tx 0: `observable_bytecode_len = 0`, `deployed_in_tx = Some(0)`.

In tx 1, `mark_for_deconstruction` evaluates:
- `in_constructor = (0 == 0)` → **true**
- `should_be_deconstructed = (Some(0) == Some(1)) || true` → **true**

The contract is deconstructed. Zero-length bytecode deployment is confirmed valid by the existing test suite: [6](#0-5) 

---

### Title
EIP-6780 Same-Transaction Constraint Bypassed via Zero-Length Bytecode `in_constructor` Heuristic — (`basic_system/src/system_implementation/flat_storage_model/account_cache.rs`)

### Summary
In the flat storage model, `mark_for_deconstruction` uses `observable_bytecode_len == 0` as a proxy for "contract is in its constructor." A legitimately deployed contract that returns zero bytes of runtime code also has `observable_bytecode_len == 0`, causing the heuristic to misfire in subsequent transactions and allowing EIP-6780-prohibited self-destruction.

### Finding Description
The comment at line 1158–1159 states the intent: "If it's empty, then the call must be in a constructor." This is only true if no deployed contract can have `observable_bytecode_len == 0`. However, the EVM permits a constructor to return zero bytes of runtime code (a `PUSH1 0 PUSH1 0 RETURN` init bytecode), and the system explicitly supports this — the test `zero_length_deployed_code` confirms it succeeds and records the deployed address.

After such a deployment in tx N, the account has `observable_bytecode_len = 0` and `deployed_in_tx = Some(N)`. In any subsequent tx M (M ≠ N), calling SELFDESTRUCT on that address causes:

```
in_constructor = (0 == 0)  // true — WRONG
should_be_deconstructed = (Some(N) == Some(M)) || true  // true
```

`is_marked_for_deconstruction` is set to `true`, and at `finish_tx` the account's balance is zeroed and storage is cleared — a full EIP-6780-prohibited self-destruct. [7](#0-6) 

### Impact Explanation
- **Balance theft**: The SELFDESTRUCT beneficiary receives the contract's entire balance, which should have been protected under EIP-6780.
- **Storage wipe**: The contract's storage is cleared at `finish_tx`, destroying persistent state.
- **EVM incompatibility / proving inconsistency**: If the ZK circuit enforces the EIP-6780 same-transaction constraint independently, the forward execution produces a state transition the circuit cannot prove, making valid blocks unprovable.

### Likelihood Explanation
The attack is fully unprivileged. Any user can deploy a zero-length bytecode contract (confirmed valid by the existing test), then call SELFDESTRUCT on it in a later transaction. No special access, governance role, or leaked key is required.

### Recommendation
Replace the `observable_bytecode_len == 0` heuristic with a dedicated boolean flag (e.g., `is_in_constructor`) set during the constructor frame and cleared upon successful `deploy_code`. Alternatively, add a separate `deployed_in_tx` check that also covers the constructor case by setting `deployed_in_tx` at the start of the constructor frame (before `deploy_code` is called), not only after it completes.

The ethereum storage model's approach — checking `bytecode_hash == Bytes32::ZERO` (the "never existed" sentinel, distinct from the keccak of empty bytes) — is safer and should be the reference. [8](#0-7) 

### Proof of Concept
1. **Tx 0**: Deploy a contract whose constructor executes `PUSH1 0 PUSH1 0 RETURN` (returns 0 bytes of runtime code). Record the deployed address `A`.
2. **Tx 1**: Call a contract that executes `SELFDESTRUCT` targeting address `A` as beneficiary.
3. **Assert**: Under EIP-6780, the account at `A` must NOT be deconstructed (balance and storage preserved). Under the buggy flat storage model, the account IS deconstructed and balance is transferred.
4. Compare against an EVM reference implementation (e.g., revm) which correctly preserves the account.

### Citations

**File:** basic_system/src/system_implementation/ethereum_storage_model/caches/account_properties.rs (L93-98)
```rust
    pub const EMPTY_ACCOUNT: Self = Self {
        nonce: 0,
        balance: U256::ZERO,
        bytecode_hash: Bytes32::ZERO, // Convention
        storage_root: EMPTY_ROOT_HASH,
    };
```

**File:** basic_system/src/system_implementation/ethereum_storage_model/caches/account_properties.rs (L207-209)
```rust
    pub fn has_empty_bytecode(&self) -> bool {
        self.bytecode_hash == Self::EMPTY_ACCOUNT.bytecode_hash
    }
```

**File:** basic_system/src/system_implementation/ethereum_storage_model/caches/account_cache.rs (L617-625)
```rust
        account_data.update(|cache_record| {
            cache_record.update(|v, m| {
                v.bytecode_hash = bytecode_hash;

                m.deployed_in_tx = Some(cur_tx);

                Ok(())
            })
        })?;
```

**File:** basic_system/src/system_implementation/flat_storage_model/account_cache.rs (L833-833)
```rust
        let observable_bytecode_len = deployed_code.len() as u32;
```

**File:** basic_system/src/system_implementation/flat_storage_model/account_cache.rs (L878-896)
```rust
        account_data.update(|cache_record| {
            cache_record.update(|v, m| {
                v.observable_bytecode_hash = observable_bytecode_hash;
                v.observable_bytecode_len = observable_bytecode_len;
                v.bytecode_hash = bytecode_hash;
                v.unpadded_code_len = observable_bytecode_len;
                v.artifacts_len = artifacts_len;
                v.versioning_data.set_as_deployed();
                v.versioning_data.set_ee_version(from_ee as u8);
                v.versioning_data.set_code_version(code_version);

                m.basic.deployed_in_tx = Some(cur_tx);
                // This is unlikely to happen, this case shouldn't be reachable by higher level logic
                // but just in case if force deployed contract was redeployed with regular deployment we want to publish it
                m.not_publish_bytecode = false;

                Ok(())
            })
        })?;
```

**File:** basic_system/src/system_implementation/flat_storage_model/account_cache.rs (L1125-1176)
```rust
    pub fn mark_for_deconstruction<const PROOF_ENV: bool>(
        &mut self,
        from_ee: ExecutionEnvironmentType,
        resources: &mut R,
        at_address: &B160,
        nominal_token_beneficiary: &B160,
        storage: &mut NewStorageWithAccountPropertiesUnderHash<A, SF, M, R, P>,
        preimages_cache: &mut BytecodeAndAccountDataPreimagesStorage<R, A>,
        oracle: &mut impl IOOracle,
    ) -> Result<U256, DeconstructionSubsystemError> {
        let cur_tx = self.current_tx_id;
        let mut account_data = self.materialize_element::<PROOF_ENV>(
            from_ee,
            resources,
            at_address,
            storage,
            preimages_cache,
            oracle,
            true,
            false,
        )?;
        resources.charge(&R::from_native(R::Native::from_computational(
            WARM_ACCOUNT_CACHE_WRITE_EXTRA_NATIVE_COST,
        )))?;

        let same_address = at_address == nominal_token_beneficiary;
        let transfer_amount = account_data.current().value().balance;

        // We consider two cases: either deconstruction happens within the same
        // tx as the address was deployed or it happens in constructor code.
        // Note that the contract is only deployed after finalization of
        // constructor, so in the second case `deployed_in_tx` won't be set
        // yet.
        // We identify if the call happens within a constructor by checking the bytecode
        // length. If it's empty, then the call must be in a constructor.
        let in_constructor = account_data.current().value().observable_bytecode_len == 0;
        let should_be_deconstructed = account_data.current().metadata().basic.deployed_in_tx
            == Some(cur_tx)
            || in_constructor;

        if should_be_deconstructed {
            account_data
                .element_properties_mut()
                .mark_value_as_observed();
            account_data.update(|data| {
                data.update_metadata(|metadata| {
                    metadata.basic.is_marked_for_deconstruction = true;

                    Ok(())
                })
            })?;
        }
```

**File:** tests/instances/evm/src/deployment_outcomes.rs (L25-49)
```rust
fn zero_length_deployed_code() {
    let init_bytecode = BytecodeBuilder::new().return_empty().finish();

    let signer = PrivateKeySigner::random();
    let sender = signer.address();
    let mut tester = new_tester().with_balance(sender, U256::from(DEFAULT_BALANCE));

    let tx = create_tx(signer, DEPLOY_GAS_LIMIT, init_bytecode);
    let output = tester.execute_block(vec![tx]);
    assert_eq!(output.tx_results.len(), 1);
    assert_tx_success!(output, 0);

    let tx_out = output.tx_results[0].as_ref().unwrap();
    match &tx_out.execution_result {
        rig::zksync_os_interface::types::ExecutionResult::Success(
            rig::zksync_os_interface::types::ExecutionOutput::Create(data, address),
        ) => {
            assert!(data.is_empty(), "runtime code must be empty");
            assert_ne!(
                *address,
                address!("0000000000000000000000000000000000000000")
            );
        }
        _ => panic!("expected successful create execution output"),
    }
```
