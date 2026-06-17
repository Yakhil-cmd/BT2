### Title
Unprivileged Caller Can Inject Fake Interop Roots via Crafted Event Emission — (`system_hooks/src/event_hooks/interop_root_reporter.rs`)

---

### Summary

The `interop_root_reporter_event_hook` intercepts `InteropRootAdded` events to add interop roots to the system's in-block interop root storage. The hook filters only on the event signature topic, but **never verifies the address of the emitting contract**. Any unprivileged user can deploy a contract that emits a correctly-formatted `InteropRootAdded` event with attacker-controlled `chain_id`, `block_or_batch_number`, and `root` values, causing fake interop roots to be injected into the interop root storage and committed into the batch's `interop_roots_rolling_hash` public input.

---

### Finding Description

**Root cause — missing emitter address check:**

`interop_root_reporter_event_hook` in `system_hooks/src/event_hooks/interop_root_reporter.rs` is registered as a global event hook. It receives every event emitted during block execution. The only filtering it performs is on the event signature:

```rust
if topics.is_empty() || topics[0].as_u8_array() != INTEROP_ROOT_ADDED_EVENT_SIG {
    return Ok(());
}
``` [1](#0-0) 

There is no check that the event was emitted by `L2_INTEROP_ROOT_STORAGE_ADDRESS`. The `_caller_ee` parameter (execution environment type) is explicitly ignored (prefixed `_`), and no `caller_address` parameter exists at all:

```rust
pub fn interop_root_reporter_event_hook<S: EthereumLikeTypes>(
    topics: &arrayvec::ArrayVec<...>,
    data: &[u8],
    _caller_ee: u8,          // ← caller EE type, not address; intentionally unused
    system: &mut System<S>,
    resources: &mut S::Resources,
) -> Result<(), SystemError>
``` [2](#0-1) 

After passing the signature check and data-format checks, the hook unconditionally calls:

```rust
system.io.add_interop_root(
    ExecutionEnvironmentType::NoEE,
    resources,
    InteropRoot { root, block_or_batch_number, chain_id },
)?;
``` [3](#0-2) 

`InteropRootStorage::push_root` appends without any deduplication or authorization check:

```rust
pub fn push_root(&mut self, interop_root: InteropRoot) -> Result<(), SystemError> {
    self.list.push(interop_root, ());
    Ok(())
}
``` [4](#0-3) 

At block finalization, `io.interop_root_storage.iter()` is passed directly into `calculate_interop_roots_rolling_hash`, which folds every stored root (including attacker-injected ones) into the batch public input:

```rust
batch_data.apply_block(
    ...
    io.interop_root_storage.iter(),   // ← attacker roots included here
    ...
);
``` [5](#0-4) 

The rolling hash computation:

```rust
pub fn calculate_interop_roots_rolling_hash<'a>(
    old_rolling_hash: Bytes32,
    roots: impl Iterator<Item = &'a InteropRoot>,
    hasher: &mut crypto::sha3::Keccak256,
) -> Bytes32 {
``` [6](#0-5) 

**End-to-end attacker path:**

1. Attacker deploys a contract that executes `LOG3(data_ptr, 96, INTEROP_ROOT_ADDED_EVENT_SIG, attacker_chain_id, attacker_block_number)` with `data = abi.encode(32, 1, attacker_root)`.
2. Attacker submits a regular EIP-1559 L2 transaction calling this contract.
3. The EVM executes the `LOG3` opcode; the system hook dispatch fires `interop_root_reporter_event_hook`.
4. The hook passes all format checks (correct signature, `data.len() == 96`, `offset == 32`, `len == 1`, `topics.len() == 3`) and calls `add_interop_root` with attacker-controlled values.
5. At block finalization, the fake root is folded into `interop_roots_rolling_hash` and committed to the batch public input.

The intended design is that only the operator can add interop roots, exclusively via service transactions (`0x7D`) targeting `L2_INTEROP_ROOT_STORAGE_ADDRESS` with the `addInteropRootsInBatch` selector: [7](#0-6) 

This access control is completely bypassed by the missing emitter address check in the event hook.

---

### Impact Explanation

An unprivileged user can inject arbitrary `(chain_id, block_or_batch_number, root)` tuples into the batch's `interop_roots_rolling_hash`. This hash is part of the ZK proof public input committed to the settlement layer. Consequences:

- **Cross-chain message forgery**: If the settlement layer trusts interop roots from the batch commitment to authorize cross-chain messages, an attacker can forge roots for arbitrary chains and block numbers, enabling unauthorized cross-chain asset transfers or message execution.
- **Batch commitment corruption**: The `interop_roots_rolling_hash` in the public input will differ from what the settlement layer expects for legitimate interop operations, potentially causing valid interop proofs to be rejected.
- **Permanent state corruption**: Once a fake root is committed in a proven batch, it cannot be undone without a protocol upgrade.

---

### Likelihood Explanation

High. The attacker requires only a funded L2 account and knowledge of the `INTEROP_ROOT_ADDED_EVENT_SIG` event signature (`0x6b451b84...`), which is a public constant. No privileged keys, no operator access, no coordination with other parties is needed. The attack is executable in any regular (non-service) block via a standard EIP-1559 transaction.

---

### Recommendation

Add an emitter address parameter to `interop_root_reporter_event_hook` and reject events not originating from `L2_INTEROP_ROOT_STORAGE_ADDRESS`:

```rust
pub fn interop_root_reporter_event_hook<S: EthereumLikeTypes>(
    topics: &arrayvec::ArrayVec<...>,
    data: &[u8],
    caller_address: &B160,   // add this
    _caller_ee: u8,
    system: &mut System<S>,
    resources: &mut S::Resources,
) -> Result<(), SystemError> {
    // Guard: only the authorized interop root storage contract may add roots
    if caller_address != &L2_INTEROP_ROOT_STORAGE_ADDRESS {
        return Ok(());
    }
    if topics.is_empty() || topics[0].as_u8_array() != INTEROP_ROOT_ADDED_EVENT_SIG {
        return Ok(());
    }
    // ... rest unchanged
}
```

The hook dispatch layer must be updated to pass the emitting contract address.

---

### Proof of Concept

Deploy the following EVM bytecode (pseudocode) as a contract:

```
// Construct data: abi.encode(uint256(32), uint256(1), bytes32(fake_root))
// MSTORE(0,  32)          // offset
// MSTORE(32, 1)           // length = 1
// MSTORE(64, fake_root)   // the fake root value

// Emit LOG3 with:
//   topic0 = INTEROP_ROOT_ADDED_EVENT_SIG (0x6b451b84...)
//   topic1 = attacker_chain_id
//   topic2 = attacker_block_number
//   data   = 96 bytes from offset 0
LOG3(0, 96, 0x6b451b8422636e45b93bf7f594fa2c1769d039766c4254a6e7f9c0ee1715cdb0,
     attacker_chain_id, attacker_block_number)
```

Submit a regular EIP-1559 transaction calling this contract. The `interop_root_reporter_event_hook` will fire, pass all format checks, and call `add_interop_root` with the attacker-controlled values. At block finalization, `calculate_interop_roots_rolling_hash` will include the fake root in the batch public input, as confirmed by the code path in `post_tx_op_proving_singleblock_batch.rs` and `post_tx_op_proving_multiblock_batch.rs`. [8](#0-7)

### Citations

**File:** system_hooks/src/event_hooks/interop_root_reporter.rs (L19-26)
```rust
pub fn interop_root_reporter_event_hook<S: EthereumLikeTypes>(
    topics: &arrayvec::ArrayVec<<S::IOTypes as SystemIOTypesConfig>::EventKey, MAX_EVENT_TOPICS>,
    data: &[u8],
    _caller_ee: u8,
    system: &mut System<S>,
    resources: &mut S::Resources,
) -> Result<(), SystemError>
where
```

**File:** system_hooks/src/event_hooks/interop_root_reporter.rs (L28-31)
```rust
    // First, ensure we're capturing the InteropRootAdded event
    if topics.is_empty() || topics[0].as_u8_array() != INTEROP_ROOT_ADDED_EVENT_SIG {
        return Ok(());
    }
```

**File:** system_hooks/src/event_hooks/interop_root_reporter.rs (L71-79)
```rust
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

**File:** zk_ee/src/common_structs/interop_root_storage.rs (L41-45)
```rust
    pub fn push_root(&mut self, interop_root: InteropRoot) -> Result<(), SystemError> {
        self.list.push(interop_root, ());

        Ok(())
    }
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/post_tx_op_proving_multiblock_batch.rs (L172-182)
```rust
        batch_data.apply_block(
            chain_state_commitment_before.hash().into(),
            chain_state_commitment_after.hash().into(),
            metadata.block_timestamp(),
            U256::from(metadata.chain_id()),
            upgrade_tx_hash,
            multichain_root,
            io.interop_root_storage.iter(),
            settlement_layer_chain_id,
            block_data.current_transaction_number,
        );
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

**File:** basic_bootloader/src/bootloader/transaction/rlp_encoded/transaction_types/service_tx.rs (L40-47)
```rust
const SERVICE_DESTINATION_WHITELIST: &[(B160, [u8; 4])] = &[
    (
        L2_INTEROP_ROOT_STORAGE_ADDRESS,
        ADD_INTEROP_ROOTS_IN_BATCH_SELECTOR,
    ),
    (SYSTEM_CONTEXT_ADDRESS, SET_SL_CHAIN_ID_SELECTOR),
    (L2_INTEROP_CENTER_ADDRESS, SET_INTEROP_FEE_SELECTOR),
];
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/post_tx_op_proving_singleblock_batch.rs (L113-118)
```rust
        let upgrade_tx_hash = block_data.upgrade_tx_recorder.finish();
        let interop_roots_rolling_hash = calculate_interop_roots_rolling_hash(
            Bytes32::zero(),
            io.interop_root_storage.iter(),
            &mut crypto::sha3::Keccak256::new(),
        );
```
