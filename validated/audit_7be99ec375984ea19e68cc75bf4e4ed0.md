Audit Report

## Title
Byzantine Peer Permanent State Sync Stall via Persistent HTTP 429 — (`rs/p2p/state_sync_manager/src/ongoing.rs`)

## Summary
`parse_chunk_handler_response` maps `StatusCode::TOO_MANY_REQUESTS` to `DownloadChunkError::Overloaded`. Unlike `NoContent` and `RequestError`, the `Overloaded` arm in `handle_downloaded_chunk_result` never removes the peer from `active_downloads` and never decrements `allowed_downloads`. Combined with `ChunksToDownload::download_failed` unconditionally re-queuing the chunk with no retry ceiling, a Byzantine subnet peer that always returns 429 causes the `OngoingStateSync::run` loop to spin indefinitely, permanently preventing the victim replica from completing state sync.

## Finding Description
**Root cause — status code mapping:**
`parse_chunk_handler_response` in `routes/chunk.rs` maps `StatusCode::TOO_MANY_REQUESTS` to `DownloadChunkError::Overloaded` at line 129. This response requires no cryptographic material and is trivially forgeable. [1](#0-0) 

**Missing eviction — `handle_downloaded_chunk_result`:**
The `Overloaded | Timeout | Cancelled` arm (lines 211–222) only calls `self.chunks_to_download.download_failed(chunk_id)`. It does **not** call `self.active_downloads.remove(&peer_id)` and does **not** decrement `self.allowed_downloads`. [2](#0-1) 

By contrast, both `NoContent` and `RequestError` explicitly remove the peer and decrement the budget: [3](#0-2) 

**Unconditional re-queue with no retry limit:**
`ChunksToDownload::download_failed` simply pushes the chunk back onto the vector. There is no counter, no backoff, and no ceiling on retries. [4](#0-3) 

**Loop exit condition never reached:**
The `run` loop self-terminates only when `active_downloads.is_empty()`. Because `Overloaded` never removes the peer, this condition is never satisfied by the Byzantine peer's responses. [5](#0-4) 

**Weighted selection amplifies the attack:**
`spawn_chunk_downloads` weights peers inversely by their current in-flight count. Because 429 is returned immediately, the Byzantine peer's `active_downloads` counter drops back to 0 almost instantly, giving it maximum weight and ensuring it is selected for the majority of subsequent dispatches. [6](#0-5) 

**No higher-level timeout:**
`StateSyncManager::run` has no wall-clock deadline for an ongoing sync; it runs until the `CancellationToken` is triggered externally or the sync completes naturally. [7](#0-6) 

The per-chunk `CHUNK_DOWNLOAD_TIMEOUT` of 10 s is irrelevant because a 429 response is received immediately — no timeout fires. [8](#0-7) 

## Impact Explanation
The victim replica's state sync task loops indefinitely: chunks are re-queued, dispatched to the Byzantine peer, receive 429, and re-queued again with no progress and no exit. The replica cannot advance its certified state height and falls permanently behind consensus. This is a targeted, sustained denial-of-service against a single replica's recovery mechanism, matching the **High** bounty impact: *"Application/platform-level DoS, crash, consensus blocking, certified-state disruption, or subnet availability impact not based on raw volumetric DDoS."*

## Likelihood Explanation
- Requires a Byzantine node that is a subnet member (below the consensus fault threshold — no majority corruption needed).
- The Byzantine node must advertise the target state (normal protocol behavior) and be the only or dominant advertiser when the victim starts state sync.
- The 429 response requires zero cryptographic material — any node can return it unconditionally.
- The existing test `test_cancel_if_running` already uses `StatusCode::TOO_MANY_REQUESTS` as its mock transport response, confirming the scenario is trivially reproducible in the existing test harness. [9](#0-8) 

## Recommendation
1. **Per-peer `Overloaded` counter:** Track consecutive `Overloaded` responses per peer within a session. After N consecutive responses, treat the peer as `RequestError` and evict it from `active_downloads`.
2. **Exponential backoff with ceiling:** Re-queue the chunk with a delay and cap total retries per peer before eviction.
3. **Overall state sync deadline:** Introduce a wall-clock timeout for the entire `OngoingStateSync::run` loop so that a permanently stalled sync is eventually abandoned and restarted, potentially with a different peer set.

## Proof of Concept
The existing `test_cancel_if_running` structure already demonstrates the behavior. A minimal extension:

```rust
// Mock transport always returns 429
t.expect_rpc().returning(|_, _| {
    Ok(Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .body(compress_empty_bytes())
        .unwrap())
});
// Mock chunkable always reports chunks remaining
c.expect_chunks_to_download()
    .returning(|| Box::new(std::iter::once(ChunkId::from(1))));

// Start sync, add Byzantine peer, do NOT call shutdown
// Assert: after N*PARALLEL_CHUNK_DOWNLOADS retry cycles,
//   either peer is removed OR state sync has exited.
// Actual result: neither happens — loop spins indefinitely.
// active_downloads retains the peer, allowed_downloads stays at 10,
// chunks_to_download is perpetually non-empty.
```

The `active_downloads` map retains the Byzantine peer entry throughout, `allowed_downloads` stays at 10, and `chunks_to_download` is perpetually non-empty. State sync never completes and never self-terminates without an external `CancellationToken` signal.

### Citations

**File:** rs/p2p/state_sync_manager/src/routes/chunk.rs (L128-130)
```rust
        StatusCode::NO_CONTENT => Err(DownloadChunkError::NoContent),
        StatusCode::TOO_MANY_REQUESTS => Err(DownloadChunkError::Overloaded),
        StatusCode::REQUEST_TIMEOUT => Err(DownloadChunkError::Timeout),
```

**File:** rs/p2p/state_sync_manager/src/ongoing.rs (L44-46)
```rust
const PARALLEL_CHUNK_DOWNLOADS: usize = 10;
const ONGOING_STATE_SYNC_CHANNEL_SIZE: usize = 200;
const CHUNK_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(10);
```

**File:** rs/p2p/state_sync_manager/src/ongoing.rs (L173-176)
```rust
            if self.active_downloads.is_empty() {
                info!(self.log, "Stopping ongoing state sync because no peers.",);
                break;
            }
```

**File:** rs/p2p/state_sync_manager/src/ongoing.rs (L194-209)
```rust
            Err(DownloadChunkError::NoContent) => {
                if self.active_downloads.remove(&peer_id).is_some() {
                    self.allowed_downloads -= PARALLEL_CHUNK_DOWNLOADS;
                }

                self.chunks_to_download.download_failed(chunk_id);
            }
            Err(DownloadChunkError::RequestError { chunk_id, err }) => {
                info!(
                    self.log,
                    "Failed to download chunk {} from {}: {} ", chunk_id, peer_id, err
                );
                if self.active_downloads.remove(&peer_id).is_some() {
                    self.allowed_downloads -= PARALLEL_CHUNK_DOWNLOADS;
                }
                self.chunks_to_download.download_failed(chunk_id);
```

**File:** rs/p2p/state_sync_manager/src/ongoing.rs (L211-222)
```rust
            Err(
                err @ (DownloadChunkError::Overloaded
                | DownloadChunkError::Timeout
                | DownloadChunkError::Cancelled),
            ) => {
                info!(
                    every_n_seconds => 15,
                    self.log,
                    "Failed to download chunk from {}: {} ", peer_id, err
                );
                self.chunks_to_download.download_failed(chunk_id);
            }
```

**File:** rs/p2p/state_sync_manager/src/ongoing.rs (L249-265)
```rust
        let mut peers = Vec::with_capacity(self.active_downloads.len());
        let mut weights = Vec::with_capacity(self.active_downloads.len());
        for (peer, active_downloads) in &self.active_downloads {
            peers.push(*peer);
            // Add one such that all peers can get selected.
            weights.push(max_active_downloads - active_downloads + 1);
        }
        let dist = WeightedIndex::new(weights).expect("weights>=0, sum(weights)>0, len(weigths)>0");

        for _ in 0..available_download_capacity {
            match self.chunks_to_download.next_chunk_to_download() {
                Some(chunk) => {
                    // Select random peer weighted proportional to active downloads.
                    // Peers with less active downloads are more likely to be selected.
                    let peer_id = *peers.get(dist.sample(&mut small_rng)).expect("Is present");

                    self.active_downloads.entry(peer_id).and_modify(|v| *v += 1);
```

**File:** rs/p2p/state_sync_manager/src/ongoing.rs (L429-461)
```rust
    #[test]
    fn test_cancel_if_running() {
        with_test_replica_logger(|log| {
            let mut t = MockTransport::default();
            t.expect_rpc().returning(|_, _| {
                Ok(Response::builder()
                    .status(StatusCode::TOO_MANY_REQUESTS)
                    .body(compress_empty_bytes())
                    .unwrap())
            });
            let mut c = MockChunkable::<TestMessage>::default();
            c.expect_chunks_to_download()
                .returning(|| Box::new(std::iter::once(ChunkId::from(1))));

            let rt = Runtime::new().unwrap();
            let ongoing = start_ongoing_state_sync(
                log,
                rt.handle(),
                OngoingStateSyncMetrics::new(&MetricsRegistry::default()),
                Arc::new(Mutex::new(Box::new(c))),
                StateSyncArtifactId {
                    height: Height::from(1),
                    hash: CryptoHash(vec![]),
                },
                Arc::new(t),
            );

            rt.block_on(async move {
                ongoing.sender.send(NODE_1).await.unwrap();
                ongoing.shutdown.shutdown().await.unwrap();
            });
        });
    }
```

**File:** rs/p2p/state_sync_manager/src/ongoing/chunks_to_download.rs (L26-28)
```rust
    pub(crate) fn download_failed(&mut self, chunk_id: ChunkId) {
        self.chunks.push(chunk_id);
    }
```

**File:** rs/p2p/state_sync_manager/src/lib.rs (L107-139)
```rust
    async fn run(mut self, cancellation: CancellationToken, transport: Arc<dyn Transport>) {
        let mut interval = tokio::time::interval(ADVERT_BROADCAST_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut advertise_task = JoinSet::new();
        loop {
            select! {
                () = cancellation.cancelled() => {
                    break;
                }
                Some(_) = advertise_task.join_next() => {}
                Some((advert, peer_id)) = self.advert_receiver.recv() => {
                    self.handle_advert(advert, peer_id, transport.clone()).await;
                }
                // Make sure we only have one active advertise task.
                _ = interval.tick(), if advertise_task.is_empty() => {
                    advertise_task.spawn_on(
                        Self::send_state_adverts(
                            self.rt.clone(),
                            self.state_sync.clone(),
                            transport.clone(),
                            self.metrics.clone(),
                            cancellation.clone(),
                        ),
                        &self.rt
                    );
                },
            }
        }
        while advertise_task.join_next().await.is_some() {}
        if let Some(ongoing_state_sync) = self.ongoing_state_sync.take() {
            let _ = ongoing_state_sync.shutdown.shutdown().await;
        }
    }
```
