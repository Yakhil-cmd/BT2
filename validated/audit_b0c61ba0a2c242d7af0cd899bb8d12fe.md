[1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** crates/sui-core/src/jsonrpc_index.rs (L189-193)
```rust
pub struct IndexStoreCaches {
    per_coin_type_balance: ShardedLruCache<(SuiAddress, TypeTag), SuiResult<TotalBalance>>,
    all_balances: ShardedLruCache<SuiAddress, SuiResult<Arc<HashMap<TypeTag, TotalBalance>>>>,
    pub locks: MutexTable<SuiAddress>,
}
```

**File:** crates/sui-core/src/jsonrpc_index.rs (L197-210)
```rust
/// Cache updates with optional locks held. Returned from `index_tx`.
/// In sync mode, locks are acquired and held until the batch is committed.
/// In async mode, locks are None and this is converted to `IndexStoreCacheUpdates`
/// via `into_inner()` before sending across threads.
pub struct IndexStoreCacheUpdatesWithLocks {
    pub(crate) _locks: Option<Vec<OwnedMutexGuard<()>>>,
    pub(crate) inner: IndexStoreCacheUpdates,
}

impl IndexStoreCacheUpdatesWithLocks {
    pub fn into_inner(self) -> IndexStoreCacheUpdates {
        self.inner
    }
}
```

**File:** crates/sui-core/src/jsonrpc_index.rs (L900-936)
```rust
    #[instrument(skip_all)]
    pub fn index_coin(
        &self,
        digest: &TransactionDigest,
        batch: &mut StagedBatch,
        object_index_changes: &ObjectIndexChanges,
        tx_coins: Option<TxCoins>,
        acquire_locks: bool,
    ) -> SuiResult<IndexStoreCacheUpdatesWithLocks> {
        // In production if this code path is hit, we should expect `tx_coins` to not be None.
        // However, in many tests today we do not distinguish validator and/or fullnode, so
        // we gracefully exist here.
        if tx_coins.is_none() {
            return Ok(IndexStoreCacheUpdatesWithLocks {
                _locks: None,
                inner: IndexStoreCacheUpdates::default(),
            });
        }

        let _locks = if acquire_locks {
            let mut addresses: HashSet<SuiAddress> = HashSet::new();
            addresses.extend(
                object_index_changes
                    .deleted_owners
                    .iter()
                    .map(|(owner, _)| *owner),
            );
            addresses.extend(
                object_index_changes
                    .new_owners
                    .iter()
                    .map(|((owner, _), _)| *owner),
            );
            Some(self.caches.locks.acquire_locks(addresses.into_iter()))
        } else {
            None
        };
```
