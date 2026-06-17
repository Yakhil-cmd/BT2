### Title
Duplicate Interop Roots in `InteropRootStorage` Corrupt `interop_roots_rolling_hash` in Batch Public Input — (`system_hooks/src/event_hooks/interop_root_reporter.rs`, `zk_ee/src/common_structs/interop_root_storage.rs`)

---

### Summary

The `InteropRootStorage` list accepts `InteropRoot` entries via a simple append (`push_root`) with no uniqueness check on the `(chain_id, block_or_batch_number)` key. The `interop_root_reporter_event_hook` that feeds this list also performs no check on the emitting contract address — only on the event signature. If the same `(chain_id, block_or_batch_number)` pair is submitted twice (with different or identical roots), both entries are appended to the list and both are folded into `calculate_interop_roots_rolling_hash`, producing an incorrect rolling hash that is committed into the batch public input. This is the direct analog of the external report's "duplicate entries in a concatenated list cause incorrect accounting" vulnerability class.

---

### Finding Description

**Root cause 1 — No deduplication in `InteropRootStorage::push_root`:**

`push_root` is a plain `HistoryList::push` with no uniqueness enforcement:

```rust
pub fn push_root(&mut self, interop_root: InteropRoot) -> Result<(), SystemError> {
    self.list.push(interop_root, ());
    Ok(())
}
``` [1](#0-0) 

There is no check that `(chain_id, block_or_batch_number)` is unique before appending.

**Root cause 2 — `interop_root_reporter_event_hook` does not validate the emitting address:**

The hook fires for any event matching `INTEROP_ROOT_ADDED_EVENT_SIG` from **any** contract — there is no `address` parameter and no address filter:

```rust
pub fn interop_root_reporter_event_hook<S: EthereumLikeTypes>(
    topics: &arrayvec::ArrayVec<...>,
    data: &[u8],
    _caller_ee: u8,
    system: &mut System<S>,
    resources: &mut S::Resources,
) -> Result<(), SystemError>
``` [2](#0-1) 

The only validation is the event signature, data length (96), offset (32), array length (1), and topics count (3) — all trivially satisfiable by any user-deployed contract.

**Root cause 3 — `calculate_interop_roots_rolling_hash` blindly folds all list entries:**

```rust
for root in roots {
    data[0..32].copy_from_slice(&rolling_hash.as_u8_ref());
    data[32..64].copy_from_slice(&root.chain_id.to_be_bytes::<{ U256::BYTES }>());
    data[64..96].copy_from_slice(&root.block_or_batch_number.to_be_bytes::<{ U256::BYTES }>());
    hasher.update(data);
    hasher.update(root.root.as_u8_ref());
    rolling_hash = hasher.finalize_reset().into()
}
``` [3](#0-2) 

Every entry in the list — including duplicates — is hashed in. The resulting `interop_roots_rolling_hash` is then committed into `BatchOutput` and ultimately into the batch public input: [4](#0-3) [5](#0-4) 

In the multiblock batch path, the same accumulation happens in `ZKBatchDataKeeper::apply_block`: [6](#0-5) 

---

### Impact Explanation

If an unprivileged user deploys a contract that emits `InteropRootAdded(chain_id, block_or_batch_number, [root])` with the correct ABI encoding, the hook fires and appends the entry to `interop_root_storage`. Submitting the same `(chain_id, block_or_batch_number)` pair twice (with different roots) causes both to be folded into the rolling hash. The settlement layer, which expects a deduplicated map (the `L2InteropRootStorage` contract stores roots in a `mapping(uint256 => mapping(uint256 => bytes32))`), would compute a different rolling hash. This produces a **divergence between the ZKsync OS batch public input and the settlement layer's expected value**, causing:

- Batch proof verification failure on the settlement layer (denial of service for the entire batch), or
- If the settlement layer does not independently recompute the rolling hash, acceptance of a manipulated cross-chain state commitment.

The `interop_roots_rolling_hash` is a security-critical field: it commits to which cross-chain roots were processed in the batch.

---

### Likelihood Explanation

The attacker path requires:
1. Deploying a contract that emits `InteropRootAdded` with the correct 3-topic, 96-byte-data ABI layout — trivial for any EVM user.
2. The `interop_root_reporter_event_hook` being registered globally (not address-filtered). The hook implementation contains no address check; whether the registration is global is not confirmed from the available code, but the absence of an address parameter in the hook signature is a strong indicator.

If the hook is globally registered, this is reachable by any unprivileged transaction sender with no special privileges. The `run_processes_several_interop_roots` test confirms the system processes multiple roots in a single block without any uniqueness enforcement. [7](#0-6) 

---

### Recommendation

1. **In `InteropRootStorage::push_root`**: Before appending, check that no existing entry has the same `(chain_id, block_or_batch_number)`. Return an error if a duplicate is detected.

2. **In `interop_root_reporter_event_hook`**: Add an explicit check that the emitting address equals `L2_INTEROP_ROOT_STORAGE_ADDRESS` before processing the event.

3. **In `calculate_interop_roots_rolling_hash`**: Optionally assert that the input iterator yields no duplicate `(chain_id, block_or_batch_number)` pairs as a defense-in-depth measure.

---

### Proof of Concept

1. Deploy a contract `Attacker` that, when called, emits:
   ```
   emit InteropRootAdded(chain_id_X, block_N, [root_A])  // first emission
   emit InteropRootAdded(chain_id_X, block_N, [root_B])  // duplicate key, different root
   ```
   with topics `[INTEROP_ROOT_ADDED_EVENT_SIG, chain_id_X, block_N]` and 96-byte data encoding `(32, 1, root_A)` / `(32, 1, root_B)`.

2. Submit an EVM transaction calling `Attacker`. Both events fire the hook; `interop_root_storage` now contains two entries for `(chain_id_X, block_N)`.

3. At batch finalization, `calculate_interop_roots_rolling_hash` folds both entries: `H = keccak(keccak(0 || chain_id_X || block_N || root_A) || chain_id_X || block_N || root_B)`.

4. The settlement layer's `L2InteropRootStorage` mapping only stores `root_B` (the second write overwrites the first). The settlement layer computes `H' = keccak(0 || chain_id_X || block_N || root_B)`.

5. `H ≠ H'` → batch public input mismatch → proof verification failure or accepted incorrect commitment.

### Citations

**File:** zk_ee/src/common_structs/interop_root_storage.rs (L41-45)
```rust
    pub fn push_root(&mut self, interop_root: InteropRoot) -> Result<(), SystemError> {
        self.list.push(interop_root, ());

        Ok(())
    }
```

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

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/mod.rs (L115-125)
```rust
    for root in roots {
        data[0..32].copy_from_slice(&rolling_hash.as_u8_ref());
        data[32..64].copy_from_slice(&root.chain_id.to_be_bytes::<{ U256::BYTES }>());
        data[64..96].copy_from_slice(&root.block_or_batch_number.to_be_bytes::<{ U256::BYTES }>());
        hasher.update(data);

        // Note: now we have only one side
        hasher.update(root.root.as_u8_ref());

        rolling_hash = hasher.finalize_reset().into()
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

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/post_tx_op_proving_singleblock_batch.rs (L185-198)
```rust
        let batch_output = BatchOutput {
            chain_id: U256::from(metadata.chain_id()),
            first_block_timestamp: metadata.block_timestamp(),
            last_block_timestamp: metadata.block_timestamp(),
            da_commitment_scheme: io.da_commitment_scheme.unwrap(),
            pubdata_commitment: da_commitment,
            number_of_layer_1_txs: U256::try_from(number_of_layer_1_txs).unwrap(),
            number_of_layer_2_txs: U256::from(number_of_layer_2_txs),
            priority_operations_hash,
            l2_logs_tree_root: full_l2_to_l1_logs_root,
            upgrade_tx_hash,
            interop_roots_rolling_hash,
            settlement_layer_chain_id,
        };
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/batch_data.rs (L103-107)
```rust
        self.interop_roots_rolling_hash = calculate_interop_roots_rolling_hash(
            self.interop_roots_rolling_hash,
            interop_roots,
            &mut crypto::sha3::Keccak256::new(),
        );
```

**File:** tests/instances/interop/src/lib.rs (L276-296)
```rust
fn run_processes_several_interop_roots() {
    let mut interop_roots = Vec::new();
    for i in 1..=20 {
        interop_roots.push(StoredInteropRoot {
            root: Bytes32::from_u256_be(&U256::from(0x1000 + i)),
            block_or_batch_number: U256::from(100 + i),
            chain_id: U256::from(i),
        });
    }

    let (mut tester, output) = run_interop_roots_test_inner(interop_roots.clone());
    assert_single_successful_call(&output, 20);
    for root in interop_roots {
        assert_eq!(
            read_interop_root_slot(&mut tester, root.chain_id, root.block_or_batch_number),
            Some(root.root)
        );
    }
    // TODO(EVM-1227): when batch commitment extraction from prover input is exposed in
    // `TestingFramework`, assert interop_roots_rolling_hash for multi-root import.
}
```
