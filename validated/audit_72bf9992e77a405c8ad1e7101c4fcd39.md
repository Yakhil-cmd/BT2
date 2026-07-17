### Title
`descendant_of_tracked_shard_cache` Keyed Only by `ShardId`, Ignoring `EpochId`, Causes Wrong Shard-Tracking Decision After Resharding — (`File: chain/epoch-manager/src/shard_tracker.rs`)

---

### Summary

`ShardTracker::check_if_descendant_of_tracked_shard` caches its result in a `HashMap<ShardId, bool>` that uses only the numeric `ShardId` as the key. The function is called with different `epoch_id` values for the same `shard_id` (current epoch, next epoch, previous epoch). After a resharding event, the stale cached boolean from the pre-resharding epoch is returned for the post-resharding epoch, causing `should_apply_chunk` to return the wrong value and the node to silently skip applying chunks for shards it is configured to track.

---

### Finding Description

`ShardTracker` holds:

```rust
descendant_of_tracked_shard_cache: Arc<Mutex<HashMap<ShardId, bool>>>,
``` [1](#0-0) 

The cache is populated and read in `check_if_descendant_of_tracked_shard`:

```rust
if let Some(is_tracked) = self.descendant_of_tracked_shard_cache.lock().get(&shard_id) {
    return Ok(*is_tracked);   // epoch_id is ignored
}
// ...
self.descendant_of_tracked_shard_cache.lock().insert(shard_id, is_tracked);
``` [2](#0-1) 

The function signature accepts `epoch_id` and passes it to `check_if_descendant_of_tracked_shard_impl`, which uses it to look up the shard layout and trace ancestry across resharding boundaries: [3](#0-2) 

The result is epoch-dependent: before resharding, shard `X` may not be a descendant of any tracked shard; after resharding, the same numeric `ShardId` `X` (now with a different `ShardUId` version) is a child of a tracked parent and should return `true`.

`tracks_shard_at_epoch` calls `check_if_descendant_of_tracked_shard` for `TrackedShardsConfig::Shards`: [4](#0-3) 

`tracks_shard_at_epoch` is invoked with three distinct epoch IDs for the same `shard_id` within a single `should_apply_chunk` call: [5](#0-4) 

- `cares_about_shard` → `tracks_shard` → `tracks_shard_at_epoch(shard_id, current_epoch_id)`
- `will_care_about_shard` → `tracks_shard_next_epoch_from_prev_block` → `tracks_shard_at_epoch(shard_id, next_epoch_id)`
- `cared_about_shard_in_prev_epoch_from_prev_hash` → `tracks_shard_prev_epoch_from_prev_block` → `tracks_shard_at_epoch(shard_id, prev_epoch_id)`

The first call that populates the cache wins for all subsequent calls with the same `ShardId`, regardless of which epoch is being queried.

---

### Impact Explanation

When a resharding event occurs and a node is configured with `TrackedShardsConfig::Shards`:

1. **Pre-resharding**: `check_if_descendant_of_tracked_shard(shard_id=X, epoch=N)` computes `false` (shard X is not yet a descendant of any tracked shard). Result is cached as `(X → false)`.
2. **Post-resharding**: `check_if_descendant_of_tracked_shard(shard_id=X, epoch=N+1)` hits the cache and returns `false` — **wrong**. The correct answer is `true` because shard X is now a child of a tracked parent shard.
3. `should_apply_chunk` returns `false` for the new shard, so the node silently skips applying chunks for a shard it is supposed to track.
4. The node's state for that shard becomes stale. It cannot produce valid endorsements and effectively stops tracking the shard without any error.

The corrupted value is the `should_apply_chunk` boolean, which gates all chunk application for the affected shard.

**Scope**: Authorization / configuration selection. **Impact: High** for nodes using `TrackedShardsConfig::Shards` (archival nodes, partial-shard-tracking nodes). The node silently diverges from the correct state for the newly tracked shard.

---

### Likelihood Explanation

- Resharding is a planned, recurring protocol event on mainnet.
- `TrackedShardsConfig::Shards` is a supported production configuration for archival and partial-tracking nodes.
- The cache has no TTL, no epoch-based invalidation, and no size limit — once poisoned, the wrong value persists for the lifetime of the process.
- The bug is triggered automatically by the normal sequence of `should_apply_chunk` calls across an epoch boundary, requiring no special attacker input.

**Likelihood: Medium** — requires resharding + `Shards` config, both of which are normal production conditions.

---

### Recommendation

Change the cache key from `ShardId` to `(ShardId, EpochId)`:

```rust
descendant_of_tracked_shard_cache: Arc<Mutex<HashMap<(ShardId, EpochId), bool>>>,
```

And update the lookup and insert accordingly:

```rust
let cache_key = (shard_id, *epoch_id);
if let Some(is_tracked) = self.descendant_of_tracked_shard_cache.lock().get(&cache_key) {
    return Ok(*is_tracked);
}
// ...
self.descendant_of_tracked_shard_cache.lock().insert(cache_key, is_tracked);
```

Alternatively, bound the cache size with an LRU eviction policy (similar to `tracked_accounts_shard_cache`) to prevent unbounded growth while also fixing the key.

---

### Proof of Concept

**Setup**: Node configured with `TrackedShardsConfig::Shards(vec![parent_shard_uid])` where `parent_shard_uid` is a shard that will be split in the next resharding.

**Step 1** — Pre-resharding epoch N, block B1:
- `should_apply_chunk(IsCaughtUp, prev_hash_B1, child_shard_id)` is called.
- `cares_about_shard` → `tracks_shard_at_epoch(child_shard_id, epoch_N)` → `check_if_descendant_of_tracked_shard(child_shard_id, tracked_shards, epoch_N)`.
- `child_shard_id` does not exist in epoch N's layout → returns `false`. Cache: `{child_shard_id → false}`.

**Step 2** — Post-resharding epoch N+1, block B2:
- `should_apply_chunk(IsCaughtUp, prev_hash_B2, child_shard_id)` is called.
- `will_care_about_shard` → `tracks_shard_next_epoch_from_prev_block(child_shard_id, prev_hash_B2)` → `tracks_shard_at_epoch(child_shard_id, epoch_N+1)` → `check_if_descendant_of_tracked_shard(child_shard_id, tracked_shards, epoch_N+1)`.
- Cache hit: returns `false`. **Correct answer is `true`** — `child_shard_id` is a child of `parent_shard_uid` in epoch N+1.
- `should_apply_chunk` returns `false`. Node skips applying the chunk for `child_shard_id`.

**Result**: The node never applies chunks for the new child shard, its state for that shard is never updated, and it silently falls out of sync for the shard it was configured to track.

### Citations

**File:** chain/epoch-manager/src/shard_tracker.rs (L46-46)
```rust
    descendant_of_tracked_shard_cache: Arc<Mutex<HashMap<ShardId, bool>>>,
```

**File:** chain/epoch-manager/src/shard_tracker.rs (L92-100)
```rust
            TrackedShardsConfig::Shards(tracked_shards) => {
                // TODO(#13445): Turn the check below into a debug assert and call it earlier,
                // for all `tracked_shards_config` variants.
                let shard_layout = self.epoch_manager.get_shard_layout(epoch_id)?;
                if !shard_layout.shard_ids().contains(&shard_id) {
                    return Ok(false);
                }
                self.check_if_descendant_of_tracked_shard(shard_id, tracked_shards, epoch_id)
            }
```

**File:** chain/epoch-manager/src/shard_tracker.rs (L396-426)
```rust
    pub fn should_apply_chunk(
        &self,
        mode: ApplyChunksMode,
        prev_hash: &CryptoHash,
        shard_id: ShardId,
    ) -> bool {
        let cares_about_shard_this_epoch = self.cares_about_shard(prev_hash, shard_id);
        let cares_about_shard_next_epoch = self.will_care_about_shard(prev_hash, shard_id);
        let cared_about_shard_prev_epoch =
            self.cared_about_shard_in_prev_epoch_from_prev_hash(prev_hash, shard_id);
        match mode {
            // next epoch's shard states are not ready, only update this epoch's shards plus shards we will care about in the future
            // and already have state for
            ApplyChunksMode::NotCaughtUp => {
                cares_about_shard_this_epoch
                    || (cares_about_shard_next_epoch && cared_about_shard_prev_epoch)
            }
            // update both this epoch and next epoch
            ApplyChunksMode::IsCaughtUp => {
                cares_about_shard_this_epoch || cares_about_shard_next_epoch
            }
            // catching up next epoch's shard states, do not update this epoch's shard state
            // since it has already been updated through ApplyChunksMode::NotCaughtUp
            ApplyChunksMode::CatchingUp => {
                let syncing_shard = !cares_about_shard_this_epoch
                    && cares_about_shard_next_epoch
                    && !cared_about_shard_prev_epoch;
                syncing_shard
            }
        }
    }
```

**File:** chain/epoch-manager/src/shard_tracker.rs (L539-551)
```rust
        if let Some(is_tracked) = self.descendant_of_tracked_shard_cache.lock().get(&shard_id) {
            return Ok(*is_tracked);
        }

        let is_tracked = check_if_descendant_of_tracked_shard_impl(
            shard_id,
            &tracked_shards,
            &epoch_id,
            &self.epoch_manager,
        )?;

        self.descendant_of_tracked_shard_cache.lock().insert(shard_id, is_tracked);
        Ok(is_tracked)
```

**File:** chain/epoch-manager/src/shard_tracker.rs (L571-615)
```rust
fn check_if_descendant_of_tracked_shard_impl(
    shard_id: ShardId,
    tracked_shards: &Vec<ShardUId>,
    epoch_id: &EpochId,
    epoch_manager: &Arc<dyn EpochManagerAdapter>,
) -> Result<bool, EpochError> {
    let tracked_shards: HashSet<ShardUId> = tracked_shards.into_iter().cloned().collect();
    let protocol_version = epoch_manager.get_epoch_protocol_version(epoch_id)?;
    let shard_layout = epoch_manager.get_shard_layout(&epoch_id)?;

    // `ShardLayoutV3` stores all ancestor shards, no need to iterate through protocol versions
    if let Some(ancestors) = shard_layout.ancestor_uids(shard_id) {
        let ancestors = HashSet::from_iter(ancestors);
        return Ok(!ancestors.is_disjoint(&tracked_shards));
    }

    let mut shard_uid = ShardUId::from_shard_id_and_layout(shard_id, &shard_layout);
    if tracked_shards.contains(&shard_uid) {
        // We explicitly track `shard_id` (the shard is a descendant of itself).
        return Ok(true);
    }

    // `shard_uid` does not belong to `tracked_shards`, but it might be a descendant of one.
    // Iterate through consecutive pairs of historical shard layouts (newest to oldest) to trace
    // the ancestry. Each pair represents a resharding transition.
    let layout_history = epoch_manager.get_shard_layout_history(protocol_version, None);
    for window in layout_history.windows(2) {
        let current_layout = &window[0];
        let prev_layout = &window[1];
        let Some(parent_shard_id) = current_layout.try_get_parent_shard_id(shard_uid.shard_id())?
        else {
            debug_assert!(
                false,
                "Parent shard is missing for shard {} in shard layout {:?}",
                shard_uid, current_layout,
            );
            return Ok(false);
        };
        shard_uid = ShardUId::from_shard_id_and_layout(parent_shard_id, &prev_layout);
        if tracked_shards.contains(&shard_uid) {
            return Ok(true);
        }
    }
    Ok(false)
}
```
