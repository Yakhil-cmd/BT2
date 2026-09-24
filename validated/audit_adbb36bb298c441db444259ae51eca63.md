No vulnerability found for this question.

The CVE describes a heap out-of-bounds copy in the libjxl JPEG XL image decoder, caused by out-of-order processing of image "groups" (256x256 pixel blocks) during multi-threaded decoding, where boundary/edge groups can be copied incorrectly if not processed in the expected order. This is a C++ image-codec-specific memory-safety bug tied to `libjxl`'s pixel buffer management.

The Polkadot SDK repository has no dependency on or usage of `libjxl`/JPEG XL decoding, and no grep matches for `jxl`/`libjxl`/`jpegxl` were found anywhere in the codebase. [1](#0-0) 

I searched for the closest structural analog — code that processes discrete chunks/segments out-of-order under concurrency and could produce a buffer bounds violation on edge cases (e.g., multi-threaded erasure-coding chunk reconstruction in availability-recovery, parallel approval-voting workers, chain-sync block range handling, and contract sandbox memory bounds checks). None of these exhibit the specific violated invariant from the CVE: an attacker-controlled input causing groups/segments to be copied out of bounds into a heap buffer due to missing order/edge validation.

- `polkadot/node/network/availability-recovery/src/lib.rs` uses a bounded thread pool for erasure-coding reconstruction/re-encoding, but chunk indices and buffer bounds are validated against `n_validators` and root hashes before use, with no analogous edge-group boundary math. [2](#0-1) 
- `substrate/frame/contracts/src/wasm/runtime.rs` performs explicit bounds checks (`memory.get(ptr..ptr+len)`) before any read/copy, which is exactly the kind of check the libjxl bug was missing — and it's present here. [3](#0-2) 
- `substrate/client/network/sync/src/strategy/chain_sync.rs` processes block ranges/gaps from peers but validates blocks (`validate_blocks`) before insertion; this is node-sync logic, not reachable via a signed extrinsic, contract call, or XCM message as required by the scan method's entry-point requirement. [4](#0-3) 

None of these provide a demonstrable analog satisfying the required chain: a real user-facing entry point (signed extrinsic, contract call, or XCM) with attacker-controlled input reaching a missing bounds/order check that causes an out-of-bounds heap copy with measurable impact. No FRAME pallet, XCM executor, or bridge code was found that processes ordered "groups"/segments with edge-boundary copy logic analogous to the libjxl bug.

### Citations

**File:** polkadot/node/network/availability-recovery/src/lib.rs (L884-911)
```rust
			Some(ErasureTask::Reconstruct(n_validators, chunks, sender)) => {
				let _ = sender.send(polkadot_erasure_coding::reconstruct_v1(
					n_validators,
					chunks.iter().map(|(c_index, chunk)| {
						(
							&chunk[..],
							usize::try_from(c_index.0)
								.expect("usize is at least u32 bytes on all modern targets."),
						)
					}),
				));
			},
			Some(ErasureTask::Reencode(n_validators, root, available_data, sender)) => {
				let metrics = metrics.clone();

				let maybe_data = if reconstructed_data_matches_root(
					n_validators,
					&root,
					&available_data,
					&metrics,
				) {
					Some(available_data)
				} else {
					None
				};

				let _ = sender.send(maybe_data);
			},
```

**File:** substrate/frame/contracts/src/wasm/runtime.rs (L614-628)
```rust
	pub fn read_sandbox_memory_as_unbounded<D: Decode>(
		&self,
		memory: &[u8],
		ptr: u32,
		len: u32,
	) -> Result<D, DispatchError> {
		let ptr = ptr as usize;
		let mut bound_checked =
			memory.get(ptr..ptr + len as usize).ok_or_else(|| Error::<E::T>::OutOfBounds)?;

		let decoded = D::decode_all_with_depth_limit(MAX_DECODE_NESTING, &mut bound_checked)
			.map_err(|_| DispatchError::from(Error::<E::T>::DecodingFailed))?;

		Ok(decoded)
	}
```

**File:** substrate/client/network/sync/src/strategy/chain_sync.rs (L1370-1408)
```rust
			if let Some(request) = request {
				match &mut peer.state {
					PeerSyncState::DownloadingNew(_) => {
						self.blocks.clear_peer_download(peer_id);
						peer.state = PeerSyncState::Available;
						if let Some(start_block) =
							validate_blocks::<B>(&blocks, peer_id, Some(request))?
						{
							self.blocks.insert(start_block, blocks, *peer_id);
						}
						self.ready_blocks()
					},
					PeerSyncState::DownloadingGap(_) => {
						peer.state = PeerSyncState::Available;
						if blocks.is_empty() && request.fields.contains(BlockAttributes::BODY) {
							// An empty response means the peer holds no body of the entire
							// range (bodies are pruned oldest-first). Disconnect it to free
							// the slot for a peer that does; the mild penalty lets it retry
							// later.
							debug!(
								target: LOG_TARGET,
								"Peer {peer_id} sent an empty response for gap block request \
								 {request:?} that required bodies; disconnecting it",
							);
							if let Some(metrics) = &self.metrics {
								metrics.gap_body_empty_responses.inc();
							}
							if let Some(gap_sync) = &mut self.gap_sync {
								gap_sync.blocks.clear_peer_download(peer_id);
							}
							return Err(BadPeer(*peer_id, rep::NO_GAP_BODIES));
						}
						if let Some(gap_sync) = &mut self.gap_sync {
							gap_sync.blocks.clear_peer_download(peer_id);
							if let Some(start_block) =
								validate_blocks::<B>(&blocks, peer_id, Some(request))?
							{
								gap_sync.blocks.insert(start_block, blocks, *peer_id);
							}
```
