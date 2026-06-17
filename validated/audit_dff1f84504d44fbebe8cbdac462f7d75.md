### Title
`InteropRootStorage::push_root` Does Not Check for Duplicate `(chain_id, block_or_batch_number)` Entries, Corrupting the `interop_roots_rolling_hash` in the Batch Public Input - (File: `zk_ee/src/common_structs/interop_root_storage.rs`)

---

### Summary

The `InteropRootStorage::push_root` function appends every `InteropRoot` to an unbounded list without checking whether an entry with the same `(chain_id, block_or_batch_number)` key already exists. Because `calculate_interop_roots_rolling_hash` iterates over this list unconditionally, a single unprivileged transaction sender can emit the `InteropRootAdded` event multiple times with the same key, causing the same root to be folded into the rolling hash multiple times. This corrupts the `interop_roots_rolling_hash` field of the batch public input that is committed to on the settlement layer.

---

### Finding Description

**Entry path:**

Any unprivileged EVM transaction can call the `L2InteropRootStorage` system contract (deployed at `L2_INTEROP_ROOT_STORAGE_ADDRESS`). The contract emits an `InteropRootAdded(uint256 chain_id, uint256 block_or_batch_number, bytes32[] roots)` event for each root it processes. The system hook `interop_root_reporter_event_hook` intercepts every such event and calls `system.io.add_interop_root(...)`, which in turn calls `InteropRootStorage::push_root`.

**Root cause — `push_root` has no deduplication:**

```rust
// zk_ee/src/common_structs/interop_root_storage.rs  line 41-44
pub fn push_root(&mut self, interop_root: InteropRoot) -> Result<(), SystemError> {
    self.list.push(interop_root, ());
    Ok(())
}
```

There is no check against the existing list for a duplicate `(chain_id, block_or_batch_number)` pair before appending. The `HistoryList` is a plain append-only structure; it does not enforce key uniqueness.

**Rolling hash accumulation iterates the full list without deduplication:**

```rust
// basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/mod.rs  line 115-127
for root in roots {
    data[0..32].copy_from_slice(&rolling_hash.as_u8_ref());
    data[32..64].copy_from_slice(&root.chain_id.to_be_bytes::<{ U256::BYTES }>());
    data[64..96].copy_from_slice(&root.block_or_batch_number.to_be_bytes::<{ U256::BYTES }>());
    hasher.update(data);
    hasher.update(root.root.as_u8_ref());
    rolling_hash = hasher.finalize_reset().into()
}
```

Every element in `interop_root_storage` is folded in, including duplicates. The resulting `interop_roots_rolling_hash` is then embedded in the batch public input (`BatchOutput::interop_roots_rolling_hash`) and committed to on the settlement layer.

**Contrast with the only existing validation:**

The only guard in `interop_root_reporter_event_hook` is a zero-root check (enforced at the Solidity contract level, not in the hook itself) and structural checks on the event encoding. There is no check for duplicate `(chain_id, block_or_batch_number)` pairs anywhere in the Rust system hook or storage layer.

---

### Impact Explanation

An attacker who can submit a transaction that causes the `L2InteropRootStorage` contract to emit `InteropRootAdded` with the same `(chain_id, block_or_batch_number)` twice within a single block can make the `interop_roots_rolling_hash` in the batch public input diverge from the canonical value that the settlement layer expects. This breaks the cross-chain interoperability commitment: the settlement layer will either reject a valid proof or accept a proof whose interop-root commitment does not correspond to the actual set of unique roots processed. In a multi-chain ZKsync deployment, this can prevent legitimate cross-chain message inclusion proofs from being verified, or allow a manipulated rolling hash to be committed on-chain.

---

### Likelihood Explanation

The `L2InteropRootStorage` contract is a system contract callable by any transaction sender. The `interop_root_reporter_event_hook` is triggered by any `InteropRootAdded` event emitted from that address. A caller who can craft calldata that causes the contract to emit the same `(chain_id, block_or_batch_number)` pair twice in one transaction (or across two transactions in the same block) will trigger the bug. No privileged role is required; the attacker only needs to be able to send a transaction.

---

### Recommendation

Add a duplicate-key check in `InteropRootStorage::push_root` before appending:

```rust
pub fn push_root(&mut self, interop_root: InteropRoot) -> Result<(), SystemError> {
    // Reject duplicate (chain_id, block_or_batch_number) entries
    for existing in self.list.iter() {
        if existing.chain_id == interop_root.chain_id
            && existing.block_or_batch_number == interop_root.block_or_batch_number
        {
            return Err(/* SystemError variant for duplicate interop root */);
        }
    }
    self.list.push(interop_root, ());
    Ok(())
}
```

Alternatively, enforce uniqueness at the `interop_root_reporter_event_hook` level before calling `add_interop_root`, or use a set-like structure instead of a plain list.

---

### Proof of Concept

1. Deploy or interact with the `L2InteropRootStorage` contract at `L2_INTEROP_ROOT_STORAGE_ADDRESS`.
2. Submit a transaction that causes the contract to emit `InteropRootAdded` with `chain_id = 1`, `block_or_batch_number = 42`, `root = 0xABCD...` twice within the same block (e.g., by calling an import function twice with the same arguments, or by crafting a batch import that includes the same entry twice).
3. Observe that `interop_root_reporter_event_hook` is called twice with identical `InteropRoot` values.
4. `InteropRootStorage::push_root` appends both entries without error.
5. `calculate_interop_roots_rolling_hash` folds both entries into the hash, producing a value different from the canonical single-entry hash.
6. The corrupted `interop_roots_rolling_hash` is written into `BatchOutput` and committed to the settlement layer. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** zk_ee/src/common_structs/interop_root_storage.rs (L41-44)
```rust
    pub fn push_root(&mut self, interop_root: InteropRoot) -> Result<(), SystemError> {
        self.list.push(interop_root, ());

        Ok(())
```

**File:** system_hooks/src/event_hooks/interop_root_reporter.rs (L68-79)
```rust
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

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/public_input.rs (L76-78)
```rust
    /// Linear keccak256 hash of interop roots
    pub interop_roots_rolling_hash: Bytes32,
    /// Settlement layer chain id.
```

**File:** basic_system/src/system_implementation/system/io_subsystem.rs (L230-246)
```rust
    fn add_interop_root(
        &mut self,
        _ee_type: ExecutionEnvironmentType,
        resources: &mut Self::Resources,
        interop_root: InteropRoot,
    ) -> Result<(), SystemError> {
        // For native we charge for the storage and the computation of the rolling
        // hash (keccak of old hash || new root).
        let native = <Self::Resources as Resources>::Native::from_computational(
            INTEROP_ROOT_STORAGE_NATIVE_COST + per_root_computational_native_cost(),
        );

        let to_charge = Self::Resources::from_native(native);
        resources.charge(&to_charge)?;

        self.interop_root_storage.push_root(interop_root)
    }
```
