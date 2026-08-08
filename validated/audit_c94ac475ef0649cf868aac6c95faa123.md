### No vulnerability found for this question.

The `secondary.rs` module implements `AccountSecondaryIndexes` used purely for local RPC lookup acceleration (e.g., `getProgramAccounts` filtering by `ProgramId`, `SplTokenMint`, `SplTokenOwner`), not for consensus or bank-hash computation. `insert_if_not_exists` simply inserts a `Pubkey` into an in-memory `HashSet` and bumps a metrics counter; it does not touch lamports, capitalization, or any hash contribution. [1](#0-0) [2](#0-1) 

There is no `Ord`/hash-relevant summing of lamports in this file, and this indexing structure is explicitly the "secondary indexes" mechanism the audit rules call out as out-of-scope (`"unfiltered getProgramAccounts without secondary indexes"` scope note refers to this exact feature). Since the code path never contributes to the bank hash or capitalization calculation, the premise that a repeated call here could make "lamports summed into capitalization disagree with lamports stored across account entries" or break "hash contribution is a pure function of committed account state" does not hold — this data structure is not part of the consensus-relevant account hashing/capitalization pipeline at all. [3](#0-2)

### Citations

**File:** accounts-db/src/accounts_index/secondary.rs (L16-35)
```rust
#[derive(Debug, Default, Clone, PartialEq)]
pub struct AccountSecondaryIndexes {
    pub keys: Option<AccountSecondaryIndexesIncludeExclude>,
    pub indexes: HashSet<AccountIndex>,
}

impl AccountSecondaryIndexes {
    pub fn is_empty(&self) -> bool {
        self.indexes.is_empty()
    }
    pub fn contains(&self, index: &AccountIndex) -> bool {
        self.indexes.contains(index)
    }
    pub fn include_key(&self, key: &Pubkey) -> bool {
        match &self.keys {
            Some(options) => options.exclude ^ options.keys.contains(key),
            None => true, // include all keys
        }
    }
}
```

**File:** accounts-db/src/accounts_index/secondary.rs (L83-94)
```rust
impl SecondaryIndexEntry for RwLockSecondaryIndexEntry {
    fn insert_if_not_exists(&self, key: &Pubkey, inner_keys_count: &AtomicU64) {
        if self.account_keys.read().unwrap().contains(key) {
            // the key already exists, so nothing to do here
            return;
        }

        let was_newly_inserted = self.account_keys.write().unwrap().insert(*key);
        if was_newly_inserted {
            inner_keys_count.fetch_add(1, Ordering::Relaxed);
        }
    }
```

**File:** accounts-db/src/accounts_index/secondary.rs (L132-171)
```rust
    /// Inserts `inner_key` into `key`'s map.
    pub fn insert(&self, key: &Pubkey, inner_key: &Pubkey) {
        // Note: Always lock the reverse index first, so we synchronize with remove().
        // Pre-size to 1 to avoid push() over-allocating an empty Vec to capacity 4.
        let reverse_index_entry = self
            .reverse_index
            .entry(*inner_key)
            .or_insert_with(|| RwLock::new(Vec::with_capacity(1)));
        let mut outer_keys = reverse_index_entry.write().unwrap();

        // Now insert into the index.
        // Note, we do this get()-then-unwrap instead of calling entry() directly, because
        // get() is a read lock whereas entry() is a write lock.  We assume `key` already has
        // a map created, so optimize for the common case and only take a read lock.
        self.index
            .get(key)
            .unwrap_or_else(|| self.index.entry(*key).or_default().downgrade())
            .insert_if_not_exists(inner_key, &self.stats.num_inner_keys);

        if !outer_keys.contains(key) {
            outer_keys.push(*key);
        }

        // explicitly drop the locks so we don't hold them while reporting metrics
        drop(outer_keys);
        drop(reverse_index_entry);

        if self.stats.last_report.should_update(1000) {
            datapoint_info!(
                self.metrics_name,
                ("num_secondary_keys", self.index.len(), i64),
                (
                    "num_inner_keys",
                    self.stats.num_inner_keys.load(Ordering::Relaxed),
                    i64
                ),
                ("num_reverse_index_keys", self.reverse_index.len(), i64),
            );
        }
    }
```
