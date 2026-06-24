The code matches the claims precisely. The vulnerability is confirmed.

Audit Report

## Title
Missing Cancellation Guard on `peer_rx.wait_for` After Assembler Completion Allows Byzantine Peer to Permanently Leak Assemble Tasks — (`rs/p2p/consensus_manager/src/receiver.rs`)

## Summary

In `process_slot_update`, once the `assemble_result` arm of the outer `select!` wins, execution proceeds inside the arm body where two bare `.await` calls on `peer_rx.wait_for(|p| p.is_empty())` exist at lines 500 and 521. These awaits have no cancellation guard. A single Byzantine subnet peer that advertises an artifact and never sends a slot-deletion will hold these awaits indefinitely, permanently leaking the Tokio task, preventing `UnvalidatedArtifactMutation::Remove` from being sent (for the `Done` path), and keeping the `active_assembles` entry alive forever. The developers have explicitly flagged this with `// TODO: NET-1774`.

## Finding Description

`process_slot_update` races three futures in a `select!` at line 480:

```rust
select! {
    _ = cancellation_token.cancelled() => {}          // branch A
    assemble_result = assemble_artifact => { ... }    // branch B
    _ = all_peers_deleted_artifact => { ... }         // branch C
}
```

Once branch B wins, Tokio executes the arm body to completion. Branch A (cancellation) is no longer polled. Inside that arm body:

- **Line 500** (`Done` path): `let _ = peer_rx.wait_for(|p| p.is_empty()).await;`
- **Line 521** (`Unwanted` path): `let _ = peer_rx.wait_for(|p| p.is_empty()).await;`

The `PeerCounter` for an artifact is only decremented when the event loop receives a slot-deletion from the advertising peer via `sender.send_if_modified(|h| h.remove(peer_id))` in `handle_slot_update_receive` (line 427). A Byzantine peer that never sends a slot-deletion never triggers this decrement.

The `watch::Sender` (`tx`) is stored in `active_assembles` at line 405 and is only dropped when `active_assembles.remove(&id)` is called in `handle_artifact_processor_joined` at line 318. That function is only reached when the task joins. Since the task is stuck at `wait_for`, the sender is never dropped, so `wait_for` never receives a `RecvError` to break out.

`handle_topology_update` (line 542) removes peers from `PeerCounter`s only if they leave the subnet topology. A Byzantine peer that remains a valid subnet member is never removed this way.

With `SLOT_TABLE_NO_LIMIT = usize::MAX` used for consensus artifacts (confirmed at `rs/replica/setup_ic_network/src/lib.rs` lines 74–75 and 237–246), there is no per-peer cap on how many distinct artifact IDs a Byzantine peer can advertise, so the number of permanently stuck tasks is unbounded.

## Impact Explanation

This is a **High** severity issue matching: *"Application/platform-level DoS, crash, consensus blocking, certified-state disruption, or subnet availability impact not based on raw volumetric DDoS."*

Concrete impacts:
1. **Unbounded task/memory leak**: Each artifact ID advertised by the Byzantine peer and assembled before deletion results in one permanently stuck Tokio task. With no slot limit, this can exhaust replica memory and thread resources.
2. **Unvalidated pool pollution**: For the `Done` path, `UnvalidatedArtifactMutation::Remove` is never sent, so assembled artifacts remain in the unvalidated pool indefinitely, polluting consensus processing.
3. **`active_assembles` map exhaustion**: The entry for the artifact ID is never removed, so no new assemble task for the same ID can ever be started; new slot updates from honest peers merely call `send_if_modified` on the existing stuck sender.
4. **Shutdown hang**: When the cancellation token fires during node shutdown, stuck tasks do not terminate, potentially blocking the `JoinSet` drain in `start_event_loop`.

## Likelihood Explanation

The attacker is a single Byzantine subnet peer, within the standard BFT fault tolerance of `f < n/3`. The attack requires only: (1) being a valid subnet member, (2) sending one or more slot-update HTTP requests to the victim node's P2P endpoint, (3) waiting for the assembler to return `Done` or `Unwanted`, and (4) never sending a slot-deletion. No threshold corruption, no key material, and no privileged access beyond subnet membership is required. The `// TODO: NET-1774` comment at lines 499 and 520 confirms the developers are aware the `wait_for` calls lack cancellation protection. The attack is trivially repeatable for as many artifact IDs as desired.

## Recommendation

Wrap both `wait_for` calls in a `select!` that also polls `cancellation_token.cancelled()`, and handle the `Remove` send (or skip it) on cancellation:

```rust
select! {
    _ = cancellation_token.cancelled() => {
        // optionally send Remove to clean up unvalidated pool
    }
    _ = peer_rx.wait_for(|p| p.is_empty()) => {
        // proceed to send Remove as normal
    }
}
```

This is exactly what NET-1774 tracks. Apply the same fix to both the `Done` path (line 500) and the `Unwanted` path (line 521).

## Proof of Concept

State-machine test (no network required):

1. Build a `ConsensusManagerReceiver` with a mock assembler that immediately returns `AssembleResult::Done`.
2. Call `handle_slot_update_receive` from `NODE_1` for artifact ID `X` — this spawns the assemble task.
3. Await `Insert` on the unvalidated channel (confirms assembler returned `Done` and task reached line 500).
4. Fire the cancellation token.
5. With a short timeout, attempt to join the assemble task from `artifact_processor_tasks` — the join never completes because the task is stuck at `wait_for`.
6. Assert that `Remove` is never received on the unvalidated channel.

The existing test `overwrite_slot_send_remove` (line 976) already demonstrates the normal path where a slot-overwrite triggers peer removal and unblocks `wait_for`. The Byzantine scenario is the same setup but without the overwrite/deletion step, confirming the stuck-task behavior.