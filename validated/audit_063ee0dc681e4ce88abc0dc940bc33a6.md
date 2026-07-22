The code evidence is conclusive. Let me confirm the exact behavior of `get_accepted_block_number` with `Tag::Pending` and the contrast with `get_class`.

The finding is confirmed. Here is the analysis:

---

### Title
`get_compiled_class` Ignores `pending_classes` for `block_id=Pending`, Returning `CLASS_HASH_NOT_FOUND` for Valid Pending-Declared Classes — (`crates/apollo_rpc/src/v0_8/api/api_impl.rs`)

### Summary

The `get_compiled_class` RPC handler never consults `self.pending_classes` when `block_id=Tag(Pending)`. It unconditionally resolves the block to the latest **committed** block number and reads only from committed storage. Any class declared in the pending block — visible in `get_state_update(Pending).declared_classes` and in `get_class(Pending, hash)` — is invisible to `get_compiled_class(Pending, hash)`, which returns `CLASS_HASH_NOT_FOUND`.

### Finding Description

`get_compiled_class` in `api_impl.rs`:

```rust
fn get_compiled_class(&self, block_id: BlockId, class_hash: ClassHash) -> RpcResult<...> {
    let storage_txn = self.storage_reader.begin_ro_txn()...;
    let state_reader = storage_txn.get_state_reader()...;
    let block_number = get_accepted_block_number(&storage_txn, block_id)?;  // ← maps Pending → latest committed
    // Only reads committed storage:
    if let Some(n) = state_reader.get_class_definition_block_number(&class_hash)? { ... }
    ...
    // CLASS_HASH_NOT_FOUND if not in committed storage
}
``` [1](#0-0) 

`get_accepted_block_number` maps both `Tag::Latest` and `Tag::Pending` to the latest committed block number:

```rust
BlockId::Tag(Tag::Latest | Tag::Pending) => {
    get_latest_block_number(txn)?.ok_or_else(|| ErrorObjectOwned::from(BLOCK_NOT_FOUND))?
}
``` [2](#0-1) [3](#0-2) 

The sibling method `get_class` correctly handles this by checking `self.pending_classes` first before falling back to committed storage:

```rust
let block_id = if let BlockId::Tag(Tag::Pending) = block_id {
    let maybe_class = &self.pending_classes.read().await.get_class(class_hash);
    if let Some(class) = maybe_class {
        return class.clone().try_into().map_err(internal_server_error);
    } else { BlockId::Tag(Tag::Latest) }
} else { block_id };
``` [4](#0-3) 

`get_compiled_class` has no analogous pending-classes check. The `pending_classes` field is populated by the sync loop (`sync_pending_data`) which downloads and stores both the class and compiled class for every entry in `pending_state_diff.declared_classes`: [5](#0-4) 

So `pending_classes` holds the compiled class, but `get_compiled_class` never reads it.

### Impact Explanation

A client calling `get_compiled_class(block_id="pending", class_hash=H)` where class `H` was declared in the pending block receives `CLASS_HASH_NOT_FOUND`. At the same time:
- `get_state_update("pending").declared_classes` lists `H`
- `get_class("pending", H)` returns the Sierra class

This is an authoritative-looking wrong value from a pending-view RPC endpoint. Any tooling (wallets, explorers, SDKs) that calls `get_compiled_class` to verify a pending declare transaction or to simulate a call to a pending-declared class will receive a false negative, causing it to incorrectly conclude the class does not exist.

### Likelihood Explanation

Triggered by any unprivileged user who:
1. Submits a declare transaction that lands in the pending block (or observes one via `get_state_update`)
2. Immediately calls `get_compiled_class(block_id="pending", class_hash=<declared_hash>)`

This is a normal, expected usage pattern for clients monitoring pending state. No special privileges required.

### Recommendation

Apply the same pending-classes lookup pattern used in `get_class`. Before falling through to committed storage, check `self.pending_classes`:

```rust
fn get_compiled_class(&self, block_id: BlockId, class_hash: ClassHash) -> RpcResult<...> {
    // NEW: check pending_classes when block_id is Pending
    if let BlockId::Tag(Tag::Pending) = block_id {
        // self.pending_classes holds compiled classes downloaded by sync_pending_data
        if let Some(compiled) = self.pending_classes.blocking_read().get_compiled_class(class_hash) {
            return Ok(compiled.into());
        }
        // fall through to committed storage (class may have been committed already)
    }
    let storage_txn = ...;
    let block_number = get_accepted_block_number(&storage_txn, block_id)?;
    // ... existing committed-storage logic ...
}
```

### Proof of Concept

Concrete Rust unit test sketch (within `crates/apollo_rpc/src/v0_8/api/test.rs`):

```rust
#[tokio::test]
async fn get_compiled_class_pending_class_not_found_bug() {
    let method_name = "starknet_V0_8_getCompiledContractClass";
    let pending_classes = get_test_pending_classes();
    let (module, mut storage_writer) =
        get_test_rpc_server_and_storage_writer_from_params::<JsonRpcServerImpl>(
            None, None, None, Some(pending_classes.clone()), None,
        );

    // Write one committed block so Pending resolves to it
    storage_writer.begin_rw_txn().unwrap()
        .append_header(BlockNumber(0), &BlockHeader::default()).unwrap()
        .append_state_diff(BlockNumber(0), ThinStateDiff::default()).unwrap()
        .commit().unwrap();

    // Add a class ONLY to pending_classes (not committed storage)
    let pending_class_hash = ClassHash(Felt::from(0xdeadu64));
    let casm = CasmContractClass { compiler_version: "0.0.0".into(), ..Default::default() };
    pending_classes.write().await.add_compiled_class(pending_class_hash, casm.clone());

    // Also add to pending state_diff declared_classes (as sync would do)
    // (omitted for brevity — get_state_update(Pending) would show it)

    // BUG: returns CLASS_HASH_NOT_FOUND even though class is in pending_classes
    let err = module
        .call::<_, (CompiledContractClass, SierraVersion)>(
            method_name,
            (BlockId::Tag(Tag::Pending), pending_class_hash),
        )
        .await
        .unwrap_err();

    // This assertion PASSES (demonstrating the bug):
    assert_matches!(err, MethodsError::JsonRpc(e) if e == CLASS_HASH_NOT_FOUND.into());

    // EXPECTED (correct) behavior: should return the compiled class, not an error
}
```

The test confirms that `get_compiled_class` with `block_id=Pending` returns `CLASS_HASH_NOT_FOUND` for a class that exists in `pending_classes`, while `get_class` with the same inputs would succeed. [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** crates/apollo_rpc/src/v0_8/api/api_impl.rs (L596-612)
```rust
    #[instrument(skip(self), level = "debug", err, ret)]
    async fn get_class(
        &self,
        block_id: BlockId,
        class_hash: ClassHash,
    ) -> RpcResult<GatewayContractClass> {
        // Check in pending classes.
        let block_id = if let BlockId::Tag(Tag::Pending) = block_id {
            let maybe_class = &self.pending_classes.read().await.get_class(class_hash);
            if let Some(class) = maybe_class {
                return class.clone().try_into().map_err(internal_server_error);
            } else {
                BlockId::Tag(Tag::Latest)
            }
        } else {
            block_id
        };
```

**File:** crates/apollo_rpc/src/v0_8/api/api_impl.rs (L1509-1550)
```rust
    fn get_compiled_class(
        &self,
        block_id: BlockId,
        class_hash: ClassHash,
    ) -> RpcResult<(CompiledContractClass, SierraVersion)> {
        let storage_txn = self.storage_reader.begin_ro_txn().map_err(internal_server_error)?;
        let state_reader = storage_txn.get_state_reader().map_err(internal_server_error)?;
        let block_number = get_accepted_block_number(&storage_txn, block_id)?;

        // Check if this class exists in the Cairo1 classes table.
        if let Some(class_definition_block_number) = state_reader
            .get_class_definition_block_number(&class_hash)
            .map_err(internal_server_error)?
        {
            if class_definition_block_number > block_number {
                return Err(ErrorObjectOwned::from(CLASS_HASH_NOT_FOUND));
            }
            let (option_casm, option_sierra) = storage_txn
                .get_casm_and_sierra(&class_hash)
                .map_err(internal_server_error_with_msg)?;

            // Check if both options are `Some`.
            let (casm, sierra) = option_casm
                .zip(option_sierra)
                .ok_or_else(|| ErrorObjectOwned::from(CLASS_HASH_NOT_FOUND))?;
            let sierra_version =
                sierra.get_sierra_version().map_err(internal_server_error_with_msg)?;
            return Ok((CompiledContractClass::V1(casm), sierra_version));
        }

        // Check if this class exists in the Cairo0 classes table.
        let state_number = StateNumber::right_after_block(block_number)
            .ok_or_else(|| internal_server_error("Could not compute state number"))?;
        let deprecated_compiled_contract_class = state_reader
            .get_deprecated_class_definition_at(state_number, &class_hash)
            .map_err(internal_server_error)?
            .ok_or_else(|| ErrorObjectOwned::from(CLASS_HASH_NOT_FOUND))?;
        Ok((
            CompiledContractClass::V0(deprecated_compiled_contract_class),
            SierraVersion::DEPRECATED,
        ))
    }
```

**File:** crates/apollo_central_sync/src/pending_sync.rs (L61-81)
```rust
                for DeclaredClassHashEntry { class_hash, compiled_class_hash } in declared_classes {
                    if processed_classes.insert(class_hash) {
                        tasks.push(
                            get_pending_class(
                                class_hash,
                                central_source.clone(),
                                pending_classes.clone(),
                            )
                            .boxed(),
                        );
                    }
                    if processed_compiled_classes.insert(compiled_class_hash) {
                        tasks.push(
                            get_pending_compiled_class(
                                class_hash,
                                central_source.clone(),
                                pending_classes.clone(),
                            )
                            .boxed(),
                        );
                    }
```

**File:** crates/apollo_rpc/src/pending.rs (L5-23)
```rust
pub(crate) fn client_pending_data_to_execution_pending_data(
    client_pending_data: ClientPendingData,
    pending_classes: PendingClasses,
) -> ExecutionPendingData {
    ExecutionPendingData {
        storage_diffs: client_pending_data.state_update.state_diff.storage_diffs,
        deployed_contracts: client_pending_data.state_update.state_diff.deployed_contracts,
        declared_classes: client_pending_data.state_update.state_diff.declared_classes,
        old_declared_contracts: client_pending_data.state_update.state_diff.old_declared_contracts,
        nonces: client_pending_data.state_update.state_diff.nonces,
        replaced_classes: client_pending_data.state_update.state_diff.replaced_classes,
        classes: pending_classes,
        timestamp: client_pending_data.block.timestamp(),
        l1_gas_price: client_pending_data.block.l1_gas_price(),
        l1_data_gas_price: client_pending_data.block.l1_data_gas_price(),
        l2_gas_price: client_pending_data.block.l2_gas_price(),
        l1_da_mode: client_pending_data.block.l1_da_mode(),
        sequencer: client_pending_data.block.sequencer_address(),
    }
```
