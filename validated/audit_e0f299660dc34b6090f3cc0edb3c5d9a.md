The code evidence confirms all key claims. Let me verify the findings:

1. `encode_manifest` is called unconditionally on every `ManifestChunk` request at [1](#0-0)  with no caching.

2. `StateSyncMessage` holds only the raw `Manifest`, no pre-encoded bytes. [2](#0-1) 

3. The chunk handler dispatches directly to `spawn_blocking` with no rate limiting, no per-peer concurrency cap, no deduplication. [3](#0-2) 

4. The router setup in `lib.rs` adds no middleware-level rate limiting or concurrency guards. [4](#0-3) 

5. Grep across all of `rs/p2p/**` confirms zero matches for `rate_limit`, `throttle`, `semaphore`, or `concurrency_limit`.

---

Audit Report

## Title
Uncached `encode_manifest` Per `ManifestChunk` Request Enables Protocol-Level CPU Exhaustion by Byzantine Peer — (`rs/state_manager/src/state_sync/types.rs`)

## Summary
Every `ManifestChunk` request served by `StateSyncMessage::get_chunk` unconditionally invokes `encode_manifest(&self.manifest)`, performing a full protobuf serialization of the manifest with no result caching. The P2P chunk handler (`state_sync_chunk_handler`) dispatches each incoming request directly to a Tokio `spawn_blocking` task with no per-peer rate limiting, no concurrency cap, and no deduplication. A single Byzantine subnet peer can flood the serving replica with repeated manifest-chunk requests, causing O(manifest_size) CPU work per request and sustained blocking-thread-pool exhaustion.

## Finding Description
In `StateSyncMessage::get_chunk` (`rs/state_manager/src/state_sync/types.rs`, lines 498–510), the `ManifestChunk(index)` branch calls `encode_manifest(&self.manifest)` on every invocation:

```rust
StateSyncChunk::ManifestChunk(index) => {
    let index = index as usize;
    if index < self.meta_manifest.sub_manifest_hashes.len() {
        let encoded_manifest = encode_manifest(&self.manifest);
        ...
    }
}
```

`encode_manifest` performs a full protobuf serialization (`pb::Manifest::proxy_encode(manifest.clone())`) and returns a freshly allocated `Vec<u8>` each time. The result is never stored; `StateSyncMessage` holds only the raw `Manifest` field with no `OnceCell`, `Arc<Vec<u8>>`, or any other cache.

The serving path in `state_sync_chunk_handler` (`rs/p2p/state_sync_manager/src/routes/chunk.rs`, lines 41–74) parses the incoming request and immediately calls `tokio::task::spawn_blocking(move || state.state_sync.chunk(...))` with no guards:
- No per-peer request counter or rate limit
- No global concurrency semaphore on the blocking pool
- No deduplication of identical chunk IDs

The router in `lib.rs` (lines 68–75) registers the handler with `any(state_sync_chunk_handler)` and no Tower middleware layers for rate limiting or concurrency control. A search across all of `rs/p2p/**` returns zero matches for `rate_limit`, `throttle`, `semaphore`, or `concurrency_limit`.

A Byzantine peer sends repeated HTTP/QUIC POST requests to `/state-sync/chunk` with `chunk_id = MANIFEST_CHUNK_ID_OFFSET` (a valid `ManifestChunk(0)` ID). Each request spawns a blocking task that re-serializes the entire manifest. For a large checkpoint (e.g., 100 MiB encoded manifest), this is significant CPU work per request. Tokio's blocking thread pool (default cap 512) can be saturated, stalling all other `spawn_blocking` operations on the replica (checkpoint reads, file chunk serving, etc.).

## Impact Explanation
This is a protocol-level CPU amplification DoS: a small request (tens of bytes) triggers O(manifest_size) CPU work on the serving replica. Sustained flooding degrades or halts the replica's ability to serve legitimate state-sync chunks and participate in consensus-adjacent blocking I/O. This matches the allowed High impact: **"Application/platform-level DoS, consensus blocking, or subnet availability impact not based on raw volumetric DDoS."** Severity: **High ($2,000–$10,000)**.

## Likelihood Explanation
The attacker must be a valid subnet peer — a single Byzantine node below the consensus fault threshold suffices. No admin key, governance majority, or threshold corruption is required. The exploit is mechanically trivial: send a tight loop of valid `StateSyncChunkRequest` protobuf messages with `chunk_id = MANIFEST_CHUNK_ID_OFFSET` over QUIC to the target replica's P2P endpoint. The attack is repeatable and requires no victim interaction.

## Recommendation
Pre-compute and cache the encoded manifest bytes inside `StateSyncMessage`, for example using `once_cell::sync::OnceCell<Vec<u8>>` or by storing a pre-computed `Arc<Vec<u8>>` at construction time, so `encode_manifest` is called at most once per checkpoint regardless of how many `ManifestChunk` requests arrive. Additionally, add a per-peer concurrency semaphore or token-bucket rate limiter in `state_sync_chunk_handler` to bound the number of concurrent blocking serialization tasks any single peer can induce.

## Proof of Concept
```rust
// Unit benchmark (safe, no mainnet interaction)
let msg: StateSyncMessage = /* construct with large checkpoint manifest */;
let chunk_id = ChunkId::new(MANIFEST_CHUNK_ID_OFFSET); // valid ManifestChunk(0)

let start = Instant::now();
for _ in 0..1000 {
    let _ = msg.get_chunk(chunk_id); // each call invokes encode_manifest()
}
println!("Total: {:?}", start.elapsed());
// Each iteration re-serializes the full manifest; total ≈ 1000 × T(encode_manifest)
```

Alternatively, an integration test can mock `StateSyncClient::chunk` to record call counts and verify that 1000 identical `ManifestChunk` requests each invoke `encode_manifest` independently, confirming the absence of caching.

### Citations

**File:** rs/state_manager/src/state_sync/types.rs (L430-440)
```rust
pub struct StateSyncMessage {
    pub height: Height,
    pub root_hash: CryptoHashOfState,
    /// Absolute path to the checkpoint root directory.
    pub checkpoint_root: std::path::PathBuf,
    pub meta_manifest: Arc<MetaManifest>,
    /// The manifest containing the summary of the content.
    pub manifest: Manifest,
    pub state_sync_file_group: Arc<FileGroupChunks>,
    pub malicious_flags: MaliciousFlags,
}
```

**File:** rs/state_manager/src/state_sync/types.rs (L498-501)
```rust
                StateSyncChunk::ManifestChunk(index) => {
                    let index = index as usize;
                    if index < self.meta_manifest.sub_manifest_hashes.len() {
                        let encoded_manifest = encode_manifest(&self.manifest);
```

**File:** rs/p2p/state_sync_manager/src/routes/chunk.rs (L41-74)
```rust
pub(crate) async fn state_sync_chunk_handler<T: 'static>(
    State(state): State<Arc<StateSyncChunkHandler<T>>>,
    payload: Bytes,
) -> Result<Bytes, StatusCode> {
    // Parse payload
    let pb::StateSyncChunkRequest { id, chunk_id } =
        pb::StateSyncChunkRequest::decode(payload).map_err(|_| StatusCode::BAD_REQUEST)?;
    let artifact_id: StateSyncArtifactId = id.map(From::from).ok_or(StatusCode::BAD_REQUEST)?;
    let chunk_id = ChunkId::from(chunk_id);

    let jh =
        tokio::task::spawn_blocking(
            move || match state.state_sync.chunk(&artifact_id, chunk_id) {
                Some(data) => {
                    let pb_chunk = pb::StateSyncChunkResponse { data: data.take() };
                    let mut raw = BytesMut::with_capacity(pb_chunk.encoded_len());
                    pb_chunk.encode(&mut raw).expect("Allocated enough memory");
                    let raw = raw.freeze();

                    let compressed = zstd::bulk::compress(&raw, zstd::DEFAULT_COMPRESSION_LEVEL)
                        .expect("Compression failed");
                    state
                        .metrics
                        .compression_ratio
                        .observe(raw.len() as f64 / compressed.len() as f64);
                    Ok(compressed)
                }
                None => Err(StatusCode::NO_CONTENT),
            },
        );
    let data = jh.await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)??;

    Ok(data.into())
}
```

**File:** rs/p2p/state_sync_manager/src/lib.rs (L68-75)
```rust
    let router = Router::new()
        .route(STATE_SYNC_CHUNK_PATH, any(state_sync_chunk_handler))
        .with_state(shared_chunk_state)
        .route(
            STATE_SYNC_ADVERT_PATH,
            axum::routing::any(state_sync_advert_handler),
        )
        .with_state(advert_handler_state);
```
