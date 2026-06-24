Audit Report

## Title
Byzantine Peer Permanent State Sync Stall via Persistent HTTP 429 — (`rs/p2p/state_sync_manager/src/ongoing.rs`)

## Summary
A Byzantine subnet peer that persistently returns `HTTP 429 TOO_MANY_REQUESTS` for every chunk request is never evicted from `active_downloads` in `OngoingStateSync`. Because `DownloadChunkError::Overloaded` has no eviction path and no retry-count ceiling, the downloading replica loops indefinitely re-queuing and re-dispatching the same chunks to the same peer, permanently preventing state sync completion with no self-healing mechanism.

## Finding Description
`parse_chunk_handler_response` in `rs/p2p/state_sync_manager/src/routes/chunk.rs` maps `StatusCode::TOO_MANY_REQUESTS` to `DownloadChunkError::Overloaded` at line 129. This status code requires no cryptographic material and can be returned unconditionally by any peer.

In `handle_downloaded_chunk_result` (`rs/p2p/state_sync_manager/src/ongoing.rs`, lines 211–222), the `Overloaded` arm only calls `self.chunks_to_download.download_failed(chunk_id)`, re-queuing the chunk, but does **not** call `self.active_downloads.remove(&peer_id)` and does **not** decrement `self.allowed_downloads`. By contrast, `NoContent` (lines 194–199) and `RequestError` (lines 201–209) both remove the peer and decrement the budget.

The `run` loop (lines 173–176) exits only when `self.active_downloads.is_empty()`. Because `Overloaded` never removes the peer, `active_downloads` is never emptied by the Byzantine peer's responses. `spawn_chunk_downloads` is called after every result, re-dispatching the same chunk to the same peer, which again returns 429, which re-queues the chunk — an unbounded cycle.

`StateSyncManager::run` in `lib.rs` (lines 107–139) has no wall-clock deadline for an ongoing state sync; it runs until the `CancellationToken` is triggered externally or the sync completes. The per-chunk `CHUNK_DOWNLOAD_TIMEOUT` of 10 s (ongoing.rs line 46) is irrelevant because a 429 response is received immediately, before the timeout fires.

The existing test `test_cancel_if_running` (ongoing.rs lines 429–461) already uses `StatusCode::TOO_MANY_REQUESTS` as its mock transport response and relies on an external `shutdown()` call to terminate the loop, confirming that without external cancellation the loop does not self-terminate.

## Impact Explanation
A replica that cannot complete state sync cannot catch up to the current chain height and cannot participate in consensus. This constitutes a targeted, sustained denial of a single replica's recovery mechanism — a limited subnet availability impact. This matches the **High ($2,000–$10,000)** impact class: "Application/platform-level DoS, crash, consensus blocking, certified-state disruption, or subnet availability impact not based on raw volumetric DDoS." The attack is sustained (not one-time) and requires no majority corruption, placing it above the Medium threshold.

## Likelihood Explanation
- Requires a Byzantine node that is a subnet member, below the consensus fault threshold — no majority corruption needed.
- The Byzantine node must advertise the target state (normal protocol behavior) and be the only or dominant advertiser when the victim starts state sync.
- Returning `HTTP 429` requires zero cryptographic material; any node can do it unconditionally.
- The attack is trivially repeatable: the Byzantine peer simply never changes its response.
- The scenario is already encoded in the existing test suite, confirming it is a known reachable code path.

## Recommendation
1. **Add a per-peer `Overloaded` counter.** After N consecutive `Overloaded` responses from the same peer within a state sync session, treat it identically to `RequestError` and evict the peer via `active_downloads.remove(&peer_id)` with the corresponding `allowed_downloads` decrement.
2. **Exponential backoff with a ceiling.** Re-queue the chunk with a delay and cap total retries per peer before eviction.
3. **Overall state sync deadline.** Introduce a wall-clock timeout for the entire `OngoingStateSync::run` loop so that a permanently stalled sync is eventually abandoned and restarted, potentially with a different peer set.

## Proof of Concept
The existing `test_cancel_if_running` test (ongoing.rs lines 429–461) already demonstrates the scenario: the mock transport always returns `StatusCode::TOO_MANY_REQUESTS`, the mock chunkable always reports chunks remaining, and the test must call `ongoing.shutdown.shutdown().await` externally to terminate the loop. Without that external shutdown call, the loop runs indefinitely. A minimal regression test asserting self-termination after N retry cycles would fail against the current code, confirming the bug.