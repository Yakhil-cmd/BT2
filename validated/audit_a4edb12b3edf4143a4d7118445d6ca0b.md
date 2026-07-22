The code confirms the vulnerability. Here is the full analysis:

---

### Title
`get_storage_at` with `block_id=Pending` returns `CONTRACT_NOT_FOUND` instead of `Felt::default()` for contracts deployed only in pending state — (`crates/apollo_rpc/src/v0_8/api/api_impl.rs`)

### Summary

`JsonRpcServerImpl::get_storage_at` performs a contract-existence check against **accepted storage only**, ignoring `pending_data.state_update.state_diff.deployed_contracts`. When a contract is deployed exclusively in the pending block and a caller queries a storage key whose committed value is `Felt::default()`, the RPC returns `CONTRACT_NOT_FOUND` (error code 20) instead of the correct `0x0`.

### Finding Description

In `get_storage_at` (lines 340–384 of `api_impl.rs`), when `block_id = Tag::Pending`:

1. **Pending storage diffs are read correctly** — only `storage_diffs` are extracted from `pending_data`: [1](#0-0) 

2. **`execution_utils::get_storage_at` is called** with those diffs. If the key has no pending override and no accepted value, it returns `Felt::default()`: [2](#0-1) 

3. **The existence check fires** — when `res == Felt::default()`, the code checks whether the contract exists, but it calls `txn.get_state_reader().get_class_hash_at(state_number, &contract_address)`, which reads **accepted storage only**: [3](#0-2) 

A contract deployed only in `pending_data.state_update.state_diff.deployed_contracts` is invisible to this check, so `ok_or_else(|| ErrorObjectOwned::from(CONTRACT_NOT_FOUND))?` fires and the call returns error code 20.

**Contrast with `maybe_get_class_hash_at`**, which correctly reads `pending_state_diff.deployed_contracts` and passes them to `execution_utils::get_class_hash_at` (which checks pending contracts first): [4](#0-3) [5](#0-4) 

The existence check in `get_storage_at` does not use this pattern.

### Impact Explanation

The RPC pending view returns an authoritative-looking wrong value: `CONTRACT_NOT_FOUND` (error 20) instead of `0x0` for a legitimately pending-deployed contract. This corrupts the observable pending state for any client (wallet, dApp, sequencer tooling) that queries storage on a contract deployed in the pending block before it is accepted. This matches the allowed impact: **High — RPC pending view returns an authoritative-looking wrong value**.

### Likelihood Explanation

Any unprivileged caller can trigger this by:
- Knowing (or guessing) a contract address that appears in the current pending block's `deployed_contracts` diff but has not yet been accepted.
- Calling `starknet_getStorageAt(contract_address, key=0x0, block_id="pending")` where the key has no explicit pending storage entry.

No special privileges are required. The pending block is a normal, publicly observable RPC state.

### Recommendation

In `get_storage_at`, when `block_id = Tag::Pending`, the existence check must also consult `pending_data.state_update.state_diff.deployed_contracts` (and `replaced_classes`), exactly as `maybe_get_class_hash_at` does. Concretely, replace the raw `txn.get_state_reader().get_class_hash_at(...)` call with a call to `execution_utils::get_class_hash_at(...)` that receives the pending deployed contracts, mirroring the pattern at lines 1656–1673.

### Proof of Concept

Logical trace (no privileges required):

1. Pending data contains `deployed_contracts = [{ address: 0xDEAD, class_hash: 0xBEEF }]` and `storage_diffs = {}`.
2. Accepted storage has no entry for `0xDEAD`.
3. Caller sends: `starknet_getStorageAt("0xDEAD", "0x0", "pending")`.
4. `execution_utils::get_storage_at` finds no pending storage diff for `0xDEAD` → falls through to accepted storage → returns `Felt::default()`.
5. Line 375: `res == Felt::default()` → existence check triggered.
6. `txn.get_state_reader().get_class_hash_at(state_number, 0xDEAD)` → `None` (contract not in accepted storage).
7. `ok_or_else(|| CONTRACT_NOT_FOUND)?` → RPC returns error code 20.
8. **Expected**: `0x0` (the Starknet spec states "0 if no value is found" for a deployed contract).

### Citations

**File:** crates/apollo_rpc/src/v0_8/api/api_impl.rs (L347-357)
```rust
        let maybe_pending_storage_diffs = if let BlockId::Tag(Tag::Pending) = block_id {
            Some(
                read_pending_data(&self.pending_data, &txn)
                    .await?
                    .state_update
                    .state_diff
                    .storage_diffs,
            )
        } else {
            None
        };
```

**File:** crates/apollo_rpc/src/v0_8/api/api_impl.rs (L375-382)
```rust
        if res == Felt::default() && contract_address != BLOCK_HASH_TABLE_ADDRESS {
            // check if the contract exists
            txn.get_state_reader()
                .map_err(internal_server_error)?
                .get_class_hash_at(state_number, &contract_address)
                .map_err(internal_server_error)?
                .ok_or_else(|| ErrorObjectOwned::from(CONTRACT_NOT_FOUND))?;
        }
```

**File:** crates/apollo_rpc/src/v0_8/api/api_impl.rs (L1656-1673)
```rust
        let maybe_pending_deployed_contracts_and_replaced_classes =
            if let BlockId::Tag(Tag::Pending) = block_id {
                let pending_state_diff =
                    read_pending_data(&self.pending_data, &txn).await?.state_update.state_diff;
                Some((pending_state_diff.deployed_contracts, pending_state_diff.replaced_classes))
            } else {
                None
            };

        let block_number = get_accepted_block_number(&txn, block_id)?;
        let state_number = StateNumber::unchecked_right_after_block(block_number);
        execution_utils::get_class_hash_at(
            &txn,
            state_number,
            // This map converts &(T, S) to (&T, &S).
            maybe_pending_deployed_contracts_and_replaced_classes.as_ref().map(|t| (&t.0, &t.1)),
            contract_address,
        )
```

**File:** crates/apollo_rpc_execution/src/execution_utils.rs (L151-169)
```rust
pub fn get_storage_at<Mode: TransactionKind>(
    txn: &StorageTxn<'_, Mode>,
    state_number: StateNumber,
    pending_storage_diffs: Option<&IndexMap<ContractAddress, Vec<StorageEntry>>>,
    contract_address: ContractAddress,
    key: StorageKey,
) -> StorageResult<Felt> {
    if let Some(pending_storage_diffs) = pending_storage_diffs {
        if let Some(storage_entries) = pending_storage_diffs.get(&contract_address) {
            if let Some(StorageEntry { key: _, value }) = storage_entries
                .iter()
                .find(|StorageEntry { key: other_key, value: _ }| key == *other_key)
            {
                return Ok(*value);
            }
        }
    }
    txn.get_state_reader()?.get_storage_at(state_number, &contract_address, &key)
}
```

**File:** crates/apollo_rpc_execution/src/execution_utils.rs (L190-215)
```rust
pub fn get_class_hash_at<Mode: TransactionKind>(
    txn: &StorageTxn<'_, Mode>,
    state_number: StateNumber,
    pending_deployed_contracts_and_replaced_classes: Option<(
        &Vec<DeployedContract>,
        &Vec<ReplacedClass>,
    )>,
    contract_address: ContractAddress,
) -> StorageResult<Option<ClassHash>> {
    if let Some((pending_deployed_contracts, pending_replaced_classes)) =
        pending_deployed_contracts_and_replaced_classes
    {
        // Searching first in the replaced classes because if the contract was deployed and
        // replaced, the replaced class is the contract's class.
        for ReplacedClass { address, class_hash } in pending_replaced_classes {
            if *address == contract_address {
                return Ok(Some(*class_hash));
            }
        }
        for DeployedContract { address, class_hash } in pending_deployed_contracts {
            if *address == contract_address {
                return Ok(Some(*class_hash));
            }
        }
    }
    txn.get_state_reader()?.get_class_hash_at(state_number, &contract_address)
```
