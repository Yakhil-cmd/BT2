### Title
Unvalidated Emitter Address and Chain ID in Interop Root Event Hook Allows Arbitrary Root Injection - (File: `system_hooks/src/event_hooks/interop_root_reporter.rs`)

---

### Summary

The `interop_root_reporter_event_hook` function accepts any `InteropRootAdded` event from any contract without validating the emitter address or the `chain_id` field. An unprivileged user can deploy a contract that emits a spoofed `InteropRootAdded` event with an arbitrary or zero `chain_id`, injecting a fabricated interop root into the batch commitment. This corrupts the `interop_roots_rolling_hash` field of `BatchOutput`, which is committed to the settlement layer as part of the batch public input.

---

### Finding Description

`interop_root_reporter_event_hook` in `system_hooks/src/event_hooks/interop_root_reporter.rs` is triggered by any contract emitting the `InteropRootAdded` event signature. The hook ignores the `_caller_ee` parameter (note the leading underscore) and performs no check on which contract emitted the event:

```rust
pub fn interop_root_reporter_event_hook<S: EthereumLikeTypes>(
    topics: &arrayvec::ArrayVec<...>,
    data: &[u8],
    _caller_ee: u8,   // ← caller is silently ignored
    system: &mut System<S>,
    resources: &mut S::Resources,
) -> Result<(), SystemError>
``` [1](#0-0) 

After matching the event signature, the hook extracts `chain_id` directly from `topics[1]` and stores it without any validation:

```rust
let chain_id = U256::from_be_bytes(topics[1].as_u8_array());
let block_or_batch_number = U256::from_be_bytes(topics[2].as_u8_array());
system.io.add_interop_root(
    ExecutionEnvironmentType::NoEE,
    resources,
    InteropRoot { root, block_or_batch_number, chain_id },
)?;
``` [2](#0-1) 

The `InteropRoot` struct documents that `chain_id` "must be non-zero", but this invariant is never enforced anywhere in the hook or storage layer: [3](#0-2) 

`InteropRootStorage::push_root` stores the root unconditionally: [4](#0-3) 

These injected roots are then folded into the `interop_roots_rolling_hash` that becomes part of `BatchOutput.hash()`, which is committed to the settlement layer: [5](#0-4) [6](#0-5) 

---

### Impact Explanation

An attacker injects interop roots with a wrong or zero `chain_id` into the `InteropRootStorage`. The `calculate_interop_roots_rolling_hash` function folds every stored root (including injected ones) into the batch commitment. The resulting `interop_roots_rolling_hash` in `BatchOutput` is committed to the settlement layer as part of the batch public input hash. This corrupts the cross-chain state commitment, causing the settlement layer to process incorrect interop root data — analogous to the Wormhole bug where a wrong chain ID caused cross-chain message validation to silently pass for the wrong chain.

**Impact: 5** — Corrupted batch public input committed to the settlement layer; cross-chain state integrity is broken.

---

### Likelihood Explanation

Any unprivileged user can deploy an EVM contract that emits `InteropRootAdded(uint256,uint256,bytes32[])` with an arbitrary `chain_id`. No special role or privilege is required. The hook fires on any matching event signature from any address.

**Likelihood: 3** — Straightforward to exploit; requires only deploying a contract and calling it within a block.

---

### Recommendation

1. **Validate the emitter address**: The hook should check that the event was emitted by the canonical `L2_INTEROP_ROOT_STORAGE_ADDRESS` contract. The `_caller_ee` parameter (or the emitting contract address) should be used for this check.

2. **Validate `chain_id != 0`**: Enforce the documented invariant in `push_root` or in the hook itself before storing the root.

```rust
// In interop_root_reporter_event_hook:
if chain_id.is_zero() {
    return Err(internal_error!("Interop root chain_id must be non-zero").into());
}
// Also check emitter == L2_INTEROP_ROOT_STORAGE_ADDRESS
```

---

### Proof of Concept

1. Attacker deploys an EVM contract with bytecode that emits:
   `InteropRootAdded(chain_id=0, block_or_batch_number=999, sides=[0xdeadbeef...])`
2. Attacker submits an L2 transaction calling this contract.
3. `interop_root_reporter_event_hook` fires — no emitter check, no `chain_id` check.
4. `InteropRoot { root: 0xdeadbeef..., block_or_batch_number: 999, chain_id: 0 }` is stored in `InteropRootStorage`.
5. At block finalization, `calculate_interop_roots_rolling_hash` folds this root into the rolling hash.
6. `BatchOutput.interop_roots_rolling_hash` is now corrupted and committed to the settlement layer via `BatchOutput.hash()`. [7](#0-6)

### Citations

**File:** system_hooks/src/event_hooks/interop_root_reporter.rs (L19-31)
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

**File:** zk_ee/src/common_structs/interop_root_storage.rs (L14-21)
```rust
pub struct InteropRoot {
    /// The merkle root hash (cannot be zero for valid roots)
    pub root: Bytes32,
    /// Block or batch number from the source chain
    pub block_or_batch_number: U256,
    /// Source chain identifier (must be non-zero)
    pub chain_id: U256,
}
```

**File:** zk_ee/src/common_structs/interop_root_storage.rs (L41-44)
```rust
    pub fn push_root(&mut self, interop_root: InteropRoot) -> Result<(), SystemError> {
        self.list.push(interop_root, ());

        Ok(())
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

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/public_input.rs (L76-103)
```rust
    /// Linear keccak256 hash of interop roots
    pub interop_roots_rolling_hash: Bytes32,
    /// Settlement layer chain id.
    pub settlement_layer_chain_id: U256,
}

impl BatchOutput {
    ///
    /// Calculate keccak256 hash of public input
    ///
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(self.chain_id.to_be_bytes::<32>());
        hasher.update(&self.first_block_timestamp.to_be_bytes());
        hasher.update(&self.last_block_timestamp.to_be_bytes());
        // Encode DA commitment scheme as U256 BE
        hasher.update([0u8; 31]);
        hasher.update([self.da_commitment_scheme as u8]);
        hasher.update(self.pubdata_commitment.as_u8_ref());
        hasher.update(self.number_of_layer_1_txs.to_be_bytes::<32>());
        hasher.update(self.number_of_layer_2_txs.to_be_bytes::<32>());
        hasher.update(self.priority_operations_hash.as_u8_ref());
        hasher.update(self.l2_logs_tree_root.as_u8_ref());
        hasher.update(self.upgrade_tx_hash.as_u8_ref());
        hasher.update(self.interop_roots_rolling_hash.as_u8_ref());
        hasher.update(self.settlement_layer_chain_id.to_be_bytes::<32>());
        hasher.finalize()
    }
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/post_tx_op_proving_singleblock_batch.rs (L114-118)
```rust
        let interop_roots_rolling_hash = calculate_interop_roots_rolling_hash(
            Bytes32::zero(),
            io.interop_root_storage.iter(),
            &mut crypto::sha3::Keccak256::new(),
        );
```
