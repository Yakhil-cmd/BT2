Looking at `finalize_updates` and the `AliasUpdater` logic carefully:

The bug is real. Let me trace through the exact execution path to confirm.

**State machine trace for the described scenario:**

**Step 1 — `AliasUpdater::new`** (fresh alias contract, counter = 0): [1](#0-0) 

`stored_counter == Felt::ZERO` → `next_free_alias = None`, `is_alias_inserted = false`.

**Step 2 — `insert_alias` for every key in the state diff** (all keys 0x01..0x7f, all contract addresses < 0x80): [2](#0-1) 

The guard `alias_key.0 >= MIN_VALUE_FOR_ALIAS_ALLOC` is false for every key and every contract address in the described scenario. `insert_alias` body never executes. `is_alias_inserted` stays `false`, `next_free_alias` stays `None`.

**Step 3 — `finalize_updates`:** [3](#0-2) 

The `None` arm has **no guard on `is_alias_inserted`**. It unconditionally calls `set_alias_in_storage(ALIAS_COUNTER_STORAGE_KEY, INITIAL_AVAILABLE_ALIAS)`. Compare with the `Some` arm, which correctly gates on `self.is_alias_inserted`. The asymmetry is the bug.

---

### Title
Spurious alias-counter write in `AliasUpdater::finalize_updates` when no alias is earned — (`crates/blockifier/src/state/stateful_compression.rs`)

### Summary
`finalize_updates` unconditionally writes `INITIAL_AVAILABLE_ALIAS` (0x80) to `ALIAS_COUNTER_STORAGE_KEY` whenever `next_free_alias` is `None` (i.e., the alias contract counter was zero at block start), regardless of whether any alias was actually allocated. A block whose state diff touches only keys and contract addresses below 0x80 — with a fresh alias contract — triggers this path, injecting a spurious storage entry into the alias contract's state diff that was never earned by any user transaction.

### Finding Description
`AliasUpdater::new` sets `next_free_alias = None` when the stored counter is `Felt::ZERO`. [4](#0-3) 

`insert_alias` only sets `is_alias_inserted = true` and advances `next_free_alias` when `alias_key.0 >= MIN_VALUE_FOR_ALIAS_ALLOC`. [5](#0-4) 

When all keys and all contract addresses in the state diff are below 0x80, neither field is ever updated. `finalize_updates` then matches on `next_free_alias`:

```
None  =>  self.set_alias_in_storage(ALIAS_COUNTER_STORAGE_KEY, INITIAL_AVAILABLE_ALIAS)?;
``` [6](#0-5) 

There is no `if self.is_alias_inserted` guard here, unlike the `Some` arm: [7](#0-6) 

The result is a `set_storage_at` call on the alias contract that writes `0x80` to key `0x0` even though zero aliases were allocated.

### Impact Explanation
The alias contract's storage is mutated with a value it did not earn. This spurious entry appears in the block's `CommitmentStateDiff`, which feeds the Patricia trie update and the on-chain state root commitment. The state root for that block is therefore wrong — it encodes a storage write that no user transaction caused. Any independent verifier (OS, prover, full node) that recomputes the state root from the actual transaction set will disagree with the sequencer's committed root.

### Likelihood Explanation
The preconditions are:
1. The alias contract counter is still zero (first use of stateful compression on a fresh network or fresh alias contract deployment).
2. At least one user transaction touches a contract at address in `(0x0f, 0x80)` with storage keys all below `0x80`.

Condition 1 is a one-time window at network launch. Condition 2 is trivially achievable by any unprivileged user who can submit a `INVOKE` writing to a low storage slot of a contract whose address falls in the range `0x10..0x7f`. No special privileges are required.

### Recommendation
Add the same `is_alias_inserted` guard to the `None` arm:

```rust
fn finalize_updates(mut self) -> StateResult<()> {
    if !self.is_alias_inserted {
        return Ok(());
    }
    let alias = self.next_free_alias.unwrap_or(INITIAL_AVAILABLE_ALIAS);
    self.set_alias_in_storage(ALIAS_COUNTER_STORAGE_KEY, alias)
}
```

This mirrors the intent of the `Some` arm and ensures the counter is only written when at least one alias was actually allocated.

### Proof of Concept
```rust
#[test]
fn test_no_spurious_counter_write_when_all_keys_below_threshold() {
    // Fresh alias contract (counter == 0), contract at 0x20 (> 0x0f, < 0x80),
    // storage keys 0x01..0x7f — all below MIN_VALUE_FOR_ALIAS_ALLOC.
    let mut state = CachedState::from(DictStateReader::default());
    let alias_addr = *ALIAS_CONTRACT_ADDRESS;

    for key in 1u16..0x80 {
        state
            .set_storage_at(
                ContractAddress::from(0x20_u16),
                StorageKey::from(key),
                Felt::ONE,
            )
            .unwrap();
    }

    allocate_aliases_in_storage(&mut state, alias_addr).unwrap();

    let storage_diff = state.to_state_diff().unwrap().state_maps.storage;
    // The alias contract must have NO entries — no alias was earned.
    let alias_entries: Vec<_> = storage_diff
        .keys()
        .filter(|(addr, _)| addr == &alias_addr)
        .collect();
    assert!(
        alias_entries.is_empty(),
        "spurious alias contract write: {:?}",
        alias_entries
    );
}
```

With the current code this test **fails**: `alias_entries` contains `(alias_contract, 0x0) → 0x80`. The fix makes it pass.

### Citations

**File:** crates/blockifier/src/state/stateful_compression.rs (L117-123)
```rust
        let stored_counter =
            state.get_storage_at(alias_contract_address, ALIAS_COUNTER_STORAGE_KEY)?;
        Ok(Self {
            state,
            is_alias_inserted: false,
            next_free_alias: if stored_counter == Felt::ZERO { None } else { Some(stored_counter) },
            alias_contract_address,
```

**File:** crates/blockifier/src/state/stateful_compression.rs (L132-141)
```rust
    fn insert_alias(&mut self, alias_key: &AliasKey) -> StateResult<()> {
        if alias_key.0 >= MIN_VALUE_FOR_ALIAS_ALLOC
            && self.state.get_storage_at(self.alias_contract_address, *alias_key)? == Felt::ZERO
        {
            let alias_to_allocate = self.next_free_alias.unwrap_or(INITIAL_AVAILABLE_ALIAS);
            self.set_alias_in_storage(*alias_key, alias_to_allocate)?;
            self.is_alias_inserted = true;
            self.next_free_alias = Some(alias_to_allocate + Felt::ONE);
        }
        Ok(())
```

**File:** crates/blockifier/src/state/stateful_compression.rs (L145-157)
```rust
    fn finalize_updates(mut self) -> StateResult<()> {
        match self.next_free_alias {
            None => {
                self.set_alias_in_storage(ALIAS_COUNTER_STORAGE_KEY, INITIAL_AVAILABLE_ALIAS)?;
            }
            Some(alias) => {
                if self.is_alias_inserted {
                    self.set_alias_in_storage(ALIAS_COUNTER_STORAGE_KEY, alias)?;
                }
            }
        }
        Ok(())
    }
```
