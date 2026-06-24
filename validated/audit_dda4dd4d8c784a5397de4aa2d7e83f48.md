Audit Report

## Title
Unbounded DKG Unvalidated Pool Growth via Byzantine Peer Flooding with Phantom Remote DKG Dealings — (File: rs/consensus/dkg/src/lib.rs)

## Summary

A single Byzantine subnet node can flood the DKG unvalidated pool with dealings referencing fabricated remote `NiDkgId` values. Because `validate_dealings_for_dealer` intentionally defers rather than rejects such dealings, the DKG pool has no size limit, and the P2P slot table for DKG is configured with `SLOT_TABLE_NO_LIMIT = usize::MAX`, phantom dealings accumulate unbounded in memory until the next DKG interval purge (~500 blocks). Every consensus round, `on_state_change` iterates the entire unvalidated pool, creating O(N) per-round overhead that degrades throughput and can exhaust replica memory, threatening subnet availability.

## Finding Description

**Root cause 1 — Defer instead of reject for phantom remote DKG IDs:**

In `validate_dealings_for_dealer`, when a dealing's `NiDkgId` has `target_subnet.is_remote() == true` but no matching config exists, the function silently returns `Mutations::new()` (defer): [1](#0-0) 

This is intentional for legitimately early remote DKG dealings, but creates no distinction between a legitimately early dealing and a fabricated dealing with a random `NiDkgTargetId` that will never have a matching config. The dealing is neither rejected nor removed from the pool.

**Root cause 2 — No size limit on the DKG unvalidated pool:**

`DkgPoolImpl::insert` performs no bounds check whatsoever: [2](#0-1) 

There is no per-peer quota, no total message count limit, and no byte-size limit on the unvalidated section.

**Root cause 3 — DKG P2P channel uses `SLOT_TABLE_NO_LIMIT`:**

The P2P consensus manager's per-peer slot table, the first line of defense against artifact flooding, is configured with `usize::MAX` for DKG: [3](#0-2) [4](#0-3) 

The slot table enforces a per-peer limit only when `peer_slot_table_len < self.slot_limit`: [5](#0-4) 

With `slot_limit = usize::MAX`, this check never triggers for DKG, so a Byzantine peer can advertise an unlimited number of distinct slot entries.

**Root cause 4 — Purging is epoch-gated, not size-gated:**

Purging only fires when the consensus summary block advances past the pool's current start height: [6](#0-5) 

The purge removes only messages whose `id.height < new_height`: [7](#0-6) 

Deferred remote dealings at the current start height are not purged until the next DKG interval (~500 blocks, ~8 minutes on mainnet).

**Root cause 5 — O(N) processing overhead per round:**

Every call to `on_state_change` iterates the entire unvalidated pool and groups all dealings by `(dealer, DKG ID)`: [8](#0-7) 

With N deferred phantom dealings, this is O(N) work per consensus round.

**Root cause 6 — DkgBouncer admits dealings at current start height unconditionally:**

The bouncer returns `Wants` for any dealing whose `id.height == current_start_height`, regardless of the `NiDkgId` content: [9](#0-8) 

A Byzantine node sets `start_block_height = current_start_height` in all phantom dealings, ensuring they pass the bouncer and are inserted into the pool.

**Existing test confirms the defer behavior is production-active:** [10](#0-9) 

## Impact Explanation

A single Byzantine subnet node can exhaust replica memory and degrade consensus round processing speed by flooding the DKG unvalidated pool with phantom remote dealings. If multiple replicas are affected simultaneously, the subnet can halt. This matches the allowed ICP bounty impact: **High ($2,000–$10,000) — Application/platform-level DoS, consensus blocking, or subnet availability impact not based on raw volumetric DDoS.** The attack is authenticated (valid TLS peer, valid node signature) and exploits a structural gap in pool admission controls, not a raw bandwidth flood.

## Likelihood Explanation

- **Attacker model**: A single Byzantine subnet node, within the standard BFT fault assumption (f < n/3). No threshold corruption required.
- **Entry point**: Standard P2P artifact gossip, authenticated only by TLS node identity.
- **Effort**: Low. The attacker generates many `NiDkgId` values with distinct random `NiDkgTargetId` bytes, signs them with its own node key, and advertises them via P2P using distinct slot numbers. No cryptographic breaking required.
- **Window**: One full DKG interval (~500 blocks) per attack cycle. The attack can be repeated continuously across intervals.
- **Detectability**: The `on_state_change_processed` metric would spike, but no alert is wired to DKG pool size.

## Recommendation

1. **Reject phantom remote DKG dealings at admission**: In `validate_dealings_for_dealer`, check whether the `dealer_subnet` field of the `NiDkgId` matches the local subnet ID. Dealings from the local subnet for a remote target that has no matching config should be rejected (not deferred), since the local node would know if it initiated such a request. Dealings from a foreign `dealer_subnet` can still be deferred, but their count should be bounded.

2. **Apply a slot table limit to DKG**: Change `SLOT_TABLE_NO_LIMIT` to a bounded constant for DKG (e.g., matching the expected maximum number of concurrent DKG dealings per subnet node per interval, which is at most a handful of configs × 1 dealing per dealer).

3. **Add a pool size cap**: Enforce a maximum unvalidated pool size in `DkgPoolImpl::insert`, evicting oldest entries or dropping new ones when the cap is reached.

4. **Rate-limit deferred remote dealings per peer**: Track how many deferred remote dealings have been received from each peer and drop new ones beyond a threshold.

## Proof of Concept

The existing test `test_remote_dealing_validation_is_deferred_until_context_exists` already confirms the defer behavior is production-active.

A minimal reproduction:

```rust
// Byzantine node generates N phantom remote DKG dealings at current start height
let start_height = dkg_pool.get_current_start_height();
for i in 0..1_000_000u64 {
    let phantom_id = NiDkgId {
        start_block_height: start_height,
        dealer_subnet: local_subnet_id,
        dkg_tag: NiDkgTag::LowThreshold,
        target_subnet: NiDkgTargetSubnet::Remote(
            NiDkgTargetId::new(i.to_le_bytes().try_into().unwrap())
        ),
    };
    let dealing = create_and_sign_dealing(phantom_id, byzantine_node_key);
    // Each dealing:
    // 1. Passes DkgBouncer (height == current_start_height → Wants)
    // 2. Is inserted into unvalidated pool (no size check in DkgPoolImpl::insert)
    // 3. Is deferred by validate_dealings_for_dealer (is_remote() && no config → Mutations::new())
    // 4. Is never purged until next DKG interval (purge only removes id.height < new_height)
    // 5. Is iterated every consensus round in on_state_change (O(N) per round)
    p2p_send(dealing);
}
// Victim replica: pool grows to GBs; on_state_change takes O(10^6) per round.
```

A deterministic integration test can be written using `DkgPoolImpl` directly: insert N phantom remote dealings with distinct `NiDkgTargetId` values at the current start height, call `on_state_change`, assert the pool size is unchanged (all deferred), and measure iteration time scaling with N.

### Citations

**File:** rs/consensus/dkg/src/lib.rs (L204-211)
```rust
        // If the dealing refers a config which is not among the ongoing DKGs,
        // we reject it, unless it is a remote DKG, in which case we defer it
        // until the request appears in the state, or the dealing is purged.
        let config = match configs.get(message_dkg_id) {
            Some(config) => config,
            None if message_dkg_id.target_subnet.is_remote() => {
                return Mutations::new();
            }
```

**File:** rs/consensus/dkg/src/lib.rs (L302-304)
```rust
        if start_height > dkg_pool.get_current_start_height() {
            return ChangeAction::Purge(start_height).into();
        }
```

**File:** rs/consensus/dkg/src/lib.rs (L339-362)
```rust
        let mut processed = 0;
        let dealings: Vec<Vec<&Message>> = dkg_pool
            .get_unvalidated()
            // Group all unvalidated dealings by (dealer, DKG ID).
            .fold(BTreeMap::new(), |mut map, dealing| {
                let key = (dealing.signature.signer, dealing.content.dkg_id.clone());
                let dealings: &mut Vec<_> = map.entry(key).or_default();
                dealings.push(dealing);
                processed += 1;
                map
            })
            // Get the dealings sorted by (dealer, DKG ID)
            .into_values()
            .collect();

        let changeset = dealings
            .par_iter()
            .map(|dealings| {
                self.validate_dealings_for_dealer(dkg_pool, &configs, start_height, dealings)
            })
            .collect::<Vec<Mutations>>()
            .into_iter()
            .flatten()
            .collect::<Mutations>();
```

**File:** rs/consensus/dkg/src/lib.rs (L396-403)
```rust
        Box::new(move |id| {
            use std::cmp::Ordering;
            match id.height.cmp(&start_height) {
                Ordering::Equal => BouncerValue::Wants,
                Ordering::Greater => BouncerValue::MaybeWantsLater,
                Ordering::Less => BouncerValue::Unwanted,
            }
        })
```

**File:** rs/consensus/dkg/src/lib.rs (L2168-2172)
```rust
                assert!(
                    receiver_dkg.on_state_change(&dkg_pool).is_empty(),
                    "dealing should be deferred while context is missing",
                );
                assert_eq!(dkg_pool.get_unvalidated().count(), 2);
```

**File:** rs/artifact_pool/src/dkg_pool.rs (L62-70)
```rust
        let unvalidated_keys: Vec<_> = self
            .unvalidated
            .keys()
            .filter(|id| id.height < height)
            .cloned()
            .collect();
        for id in unvalidated_keys {
            self.unvalidated.remove(&id);
        }
```

**File:** rs/artifact_pool/src/dkg_pool.rs (L89-92)
```rust
    fn insert(&mut self, artifact: UnvalidatedArtifact<consensus::dkg::Message>) {
        self.unvalidated
            .insert(DkgMessageId::from(&artifact.message), artifact);
    }
```

**File:** rs/replica/setup_ic_network/src/lib.rs (L74-75)
```rust
const SLOT_TABLE_LIMIT_INGRESS: usize = 50_000;
const SLOT_TABLE_NO_LIMIT: usize = usize::MAX;
```

**File:** rs/replica/setup_ic_network/src/lib.rs (L271-280)
```rust
        let dkg = {
            let assembler = ic_artifact_downloader::FetchArtifact::new(
                log.clone(),
                rt_handle.clone(),
                artifact_pools.dkg_pool.clone(),
                bouncers.dkg,
                metrics_registry.clone(),
            );
            new_p2p_consensus.abortable_broadcast_channel(assembler, SLOT_TABLE_NO_LIMIT)
        };
```

**File:** rs/p2p/consensus_manager/src/receiver.rs (L372-390)
```rust
            // Only insert slot update if we are below peer slot table limit.
            Entry::Vacant(empty_slot) if peer_slot_table_len < self.slot_limit => {
                empty_slot.insert(new_slot_entry);
                self.metrics
                    .slot_table_new_entry_total
                    .with_label_values(&[peer_id.to_string().as_str()])
                    .inc();
                (true, None)
            }
            Entry::Vacant(_) => {
                self.metrics.slot_table_limit_exceeded_total.inc();
                warn!(
                    self.log,
                    "Peer {} tries to exceed slot limit {}. Dropping slot update",
                    peer_id,
                    self.slot_limit
                );
                (false, None)
            }
```
