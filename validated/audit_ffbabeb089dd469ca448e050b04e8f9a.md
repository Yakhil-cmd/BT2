Audit Report

## Title
Unbounded Per-Peer Slot Table Growth via `SLOT_TABLE_NO_LIMIT` Enables OOM DoS on Honest Replicas — (`rs/replica/setup_ic_network/src/lib.rs`, `rs/p2p/consensus_manager/src/receiver.rs`)

## Summary
Five of six artifact channels (consensus, certifier, dkg, idkg, https_outcalls) are wired with `SLOT_TABLE_NO_LIMIT = usize::MAX`, rendering the per-peer slot table guard in `ConsensusManagerReceiver::handle_slot_update_receive` effectively inoperative. A single TLS-authenticated Byzantine subnet peer below the fault threshold can flood any of these channels with distinct slot IDs, causing unbounded growth of `slot_table`, `active_assembles`, and `artifact_processor_tasks` until the replica process is OOM-killed and drops out of consensus.

## Finding Description
**Constant definitions** (`rs/replica/setup_ic_network/src/lib.rs`, lines 74–75): `SLOT_TABLE_LIMIT_INGRESS = 50_000` and `SLOT_TABLE_NO_LIMIT = usize::MAX` are defined. The comment at lines 72–73 explicitly acknowledges the ingress limit exists to protect against malicious peers, yet the same protection is absent for the other five channels.

**Channel wiring** (lines 246–303): `consensus`, `certifier`, `dkg`, `idkg`, and `https_outcalls` all call `abortable_broadcast_channel(assembler, SLOT_TABLE_NO_LIMIT)`; only `ingress` uses `SLOT_TABLE_LIMIT_INGRESS`.

**Guard failure** (`rs/p2p/consensus_manager/src/receiver.rs`, line 373): The guard `Entry::Vacant(empty_slot) if peer_slot_table_len < self.slot_limit` is always satisfied when `self.slot_limit = usize::MAX`, because the process is OOM-killed long before `peer_slot_table_len` reaches `usize::MAX`. Every new vacant slot is unconditionally inserted.

**Unbounded task spawning** (lines 405–419): For each new slot with a previously-unseen artifact ID, the code inserts into `active_assembles` and spawns a new Tokio task via `artifact_processor_tasks.spawn_on(...)`. All three data structures (`slot_table`, `active_assembles`, `artifact_processor_tasks`) grow proportionally to the number of distinct `(slot_number, artifact_id)` pairs sent by the attacker.

The existing `Entry::Vacant(_)` drop path (lines 381–390) is never reached in production for these channels because the `usize::MAX` limit is never exceeded before OOM.

## Impact Explanation
A single Byzantine subnet node can OOM-crash any honest replica it is connected to by sending an unbounded stream of `Update::Id(unique_id)` messages on the certification, DKG, IDKG, or HTTPS-outcalls channel. The replica process is killed by the OS, causing it to drop out of consensus participation until it restarts and re-syncs state. This constitutes a concrete application/platform-level DoS and consensus availability impact, matching the **High ($2,000–$10,000)** bounty tier: "Application/platform-level DoS, crash, consensus blocking, certified-state disruption, or subnet availability impact not based on raw volumetric DDoS."

## Likelihood Explanation
The attacker requires only subnet membership (a TLS certificate issued by the IC registry). A single compromised or malicious node operator suffices — no threshold corruption, no majority, no leaked keys. The attack is asymmetric: each message is cheap to produce (no valid artifact content required) and the only observable signal before OOM is a metric counter increment with no log warning (the warning at lines 383–388 is never triggered with `usize::MAX`). The attack is repeatable after each replica restart.

## Recommendation
Replace `SLOT_TABLE_NO_LIMIT` with per-channel bounded constants derived from protocol-level bounds on the maximum number of simultaneously active artifacts per peer for each artifact type (e.g., number of active DKG transcripts, IDKG dealings, certification shares, HTTPS outcall requests). The ingress precedent (`SLOT_TABLE_LIMIT_INGRESS = 50_000`) demonstrates the pattern is already understood and implemented. For channels with tighter protocol bounds (e.g., DKG typically has O(1) active transcripts per epoch), much smaller limits are appropriate.

## Proof of Concept
The existing test `slot_table_limit_exceeded` (`rs/p2p/consensus_manager/src/receiver.rs`, lines 846–887) confirms the limit mechanism works correctly when set to a finite value. The differential PoC is:

```rust
// Reproduces unbounded growth (matches production for cert/dkg/idkg/https):
let (mut mgr, _) = ReceiverManagerBuilder::new()
    .with_slot_limit(usize::MAX)
    .build();
let cancel = CancellationToken::new();
for i in 0u64..1_000_000 {
    mgr.handle_slot_update_receive(
        SlotUpdate {
            slot_number: SlotNumber::from(i),
            commit_id: CommitId::from(i),
            update: Update::Id(i), // distinct ID each time
        },
        NODE_1,
        ConnId::from(1),
        cancel.clone(),
    );
}
// active_assembles.len() == 1_000_000
// artifact_processor_tasks.len() == 1_000_000

// Differential: with slot_limit = 50_000, loop terminates with exactly 50_000 entries.
```

This is a safe, local, unit-level reproduction requiring no network access or mainnet interaction. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** rs/replica/setup_ic_network/src/lib.rs (L72-75)
```rust
/// This limit is used to protect against a malicious peer advertising many ingress messages.
/// If no malicious peers are present the ingress pools are bounded by a separate limit.
const SLOT_TABLE_LIMIT_INGRESS: usize = 50_000;
const SLOT_TABLE_NO_LIMIT: usize = usize::MAX;
```

**File:** rs/replica/setup_ic_network/src/lib.rs (L246-303)
```rust
            new_p2p_consensus.abortable_broadcast_channel(assembler, SLOT_TABLE_NO_LIMIT)
        };

        let ingress = {
            let assembler = ic_artifact_downloader::FetchArtifact::new(
                log.clone(),
                rt_handle.clone(),
                artifact_pools.ingress_pool.clone(),
                bouncers.ingress,
                metrics_registry.clone(),
            );
            new_p2p_consensus.abortable_broadcast_channel(assembler, SLOT_TABLE_LIMIT_INGRESS)
        };

        let certifier = {
            let assembler = ic_artifact_downloader::FetchArtifact::new(
                log.clone(),
                rt_handle.clone(),
                artifact_pools.certification_pool.clone(),
                bouncers.certifier,
                metrics_registry.clone(),
            );
            new_p2p_consensus.abortable_broadcast_channel(assembler, SLOT_TABLE_NO_LIMIT)
        };

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

        let idkg = {
            let assembler = ic_artifact_downloader::FetchArtifact::new(
                log.clone(),
                rt_handle.clone(),
                artifact_pools.idkg_pool.clone(),
                bouncers.idkg,
                metrics_registry.clone(),
            );

            new_p2p_consensus.abortable_broadcast_channel(assembler, SLOT_TABLE_NO_LIMIT)
        };

        let https_outcalls = {
            let assembler = ic_artifact_downloader::FetchArtifact::new(
                log.clone(),
                rt_handle.clone(),
                artifact_pools.https_outcalls_pool.clone(),
                bouncers.https_outcalls,
                metrics_registry.clone(),
            );

            new_p2p_consensus.abortable_broadcast_channel(assembler, SLOT_TABLE_NO_LIMIT)
```

**File:** rs/p2p/consensus_manager/src/receiver.rs (L187-195)
```rust
    slot_table: HashMap<NodeId, HashMap<SlotNumber, SlotEntry<WireArtifact::Id>>>,
    active_assembles: HashMap<WireArtifact::Id, watch::Sender<PeerCounter>>,

    #[allow(clippy::type_complexity)]
    artifact_processor_tasks: JoinSet<(watch::Receiver<PeerCounter>, WireArtifact::Id)>,

    topology_watcher: watch::Receiver<SubnetTopology>,

    slot_limit: usize,
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

**File:** rs/p2p/consensus_manager/src/receiver.rs (L405-419)
```rust
                    self.active_assembles.insert(id.clone(), tx);

                    self.artifact_processor_tasks.spawn_on(
                        Self::process_slot_update(
                            self.log.clone(),
                            id.clone(),
                            artifact.map(|a| (a, peer_id)),
                            rx,
                            self.sender.clone(),
                            self.artifact_assembler.clone(),
                            self.metrics.clone(),
                            cancellation_token.clone(),
                        ),
                        &self.rt_handle,
                    );
```

**File:** rs/p2p/consensus_manager/src/receiver.rs (L846-887)
```rust
    #[tokio::test]
    async fn slot_table_limit_exceeded() {
        let (mut mgr, _channels) = ReceiverManagerBuilder::new().with_slot_limit(2).build();
        let cancellation = CancellationToken::new();

        mgr.handle_slot_update_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(1),
                update: Update::Id(0),
            },
            NODE_1,
            ConnId::from(1),
            cancellation.clone(),
        );
        mgr.handle_slot_update_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(2),
                commit_id: CommitId::from(2),
                update: Update::Id(1),
            },
            NODE_1,
            ConnId::from(1),
            cancellation.clone(),
        );
        assert_eq!(mgr.slot_table.len(), 1);
        assert_eq!(mgr.slot_table.get(&NODE_1).unwrap().len(), 2);
        assert_eq!(mgr.active_assembles.len(), 2);
        // Send slot update that exceeds limit
        mgr.handle_slot_update_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(3),
                commit_id: CommitId::from(3),
                update: Update::Id(2),
            },
            NODE_1,
            ConnId::from(1),
            cancellation.clone(),
        );
        assert_eq!(mgr.slot_table.get(&NODE_1).unwrap().len(), 2);
        assert_eq!(mgr.active_assembles.len(), 2);
    }
```
