### Title
Stale relay-chain proxy proof remains replayable within `MaxStorageRootsToKeep` window after revocation - ([File: pallets/remote-proxy/src/lib.rs])

### Summary
`Pallet::do_remote_proxy` validates a `RemoteProxyProof::RelayChain { proof, block }` only against whatever storage root is still retained in `BlockToRoot`, without any check that the proof reflects the *current* proxy state on the relay chain. An attacker who captured a valid proof/`block` pair before `real` called `pallet_proxy::remove_proxy` on the relay chain can still submit `remote_proxy` locally and successfully dispatch as `real`, as long as that historical root has not yet been evicted from `BlockToRoot`.

### Finding Description
In `do_remote_proxy` at [1](#0-0) , for `RemoteProxyProof::RelayChain`, the code performs a `binary_search_by` over `BlockToRoot::<T, I>::get()` to find *any* retained root matching the attacker-supplied `block`, then verifies the merkle proof against that root. There is no requirement that `block` be the most recent root, nor any secondary freshness/liveness check. The only authorization gate afterwards is `ensure!(def.delay.is_zero(), Error::<T, I>::Unannounced)` at [2](#0-1) , which checks proxy *delay*, not revocation recency.

`BlockToRoot` is a bounded ring buffer populated in `on_validation_data`, retaining up to `T::MaxStorageRootsToKeep` roots [3](#0-2) . Any relay-chain block/root pair within that retention window remains a valid anchor for proof verification, regardless of whether the proxy relationship it attests to has since been revoked at a later relay-chain block.

Exploit flow:
1. Attacker is a legitimate delegate proxy for `real` on the relay chain at block `B1`; attacker captures the storage proof for the `Proxy::Proxies` entry and `block = B1`.
2. `real` calls `pallet_proxy::remove_proxy` on the relay chain at block `B2 > B1`, revoking the delegation.
3. As long as `B1` is still present in `BlockToRoot` (i.e., `B2 - B1 <= MaxStorageRootsToKeep` in relay-chain blocks), the attacker calls `RemoteProxy::remote_proxy(real, None, call, RemoteProxyProof::RelayChain { proof, block: B1 })`.
4. `do_remote_proxy` finds root for `B1` still stored, verifies the pre-revocation proof successfully, finds a matching (now-stale) `ProxyDefinition`, passes the `delay.is_zero()` check, and dispatches `call` as `real` via `do_proxy` at [4](#0-3) .

This is explicitly acknowledged as a known tradeoff in the pallet's own documentation: "when deleting a proxy at the remote location at X, it will take MaxStorageRootsToKeep time until the proxy can not be used anymore" [5](#0-4) . This confirms the root cause is real and by design there is no revocation-freshness check beyond the retention window bound.

### Impact Explanation
An account whose relay-chain proxy delegation has been revoked can still forge `real`'s origin on the parachain and dispatch arbitrary calls filtered only by `def.proxy_type`, enabling unauthorized fund movement or other state changes attributable to `real`, for the duration of the retention window (bounded by `MaxStorageRootsToKeep`).

### Likelihood Explanation
Fully reachable by an unprivileged signed account through the public extrinsic `RemoteProxy::remote_proxy` (or `remote_proxy_with_registered_proof`). Preconditions require only that the attacker was once a legitimate proxy and captures the proof before revocation — an ordinary, easily achievable action — and that the exploit is executed before the retention window (`MaxStorageRootsToKeep`, docs state it's calibrated in time/blocks) elapses. This is deterministic and repeatable, not probabilistic, and is explicitly called out as an accepted design tradeoff rather than mitigated.

### Recommendation
This is a documented, intentional design tradeoff of the pallet (bounding proxy revocation propagation delay to `MaxStorageRootsToKeep`), not an unintended missing check — the module doc explicitly warns operators to size `MaxStorageRootsToKeep` conservatively for this reason. If tighter guarantees are desired, consider: (a) reducing `MaxStorageRootsToKeep` to the minimum operationally acceptable value, (b) adding a mandatory "freshness" requirement (e.g., proof's `block` must be within a small delta of the latest retained root) for security-sensitive proxy types, or (c) supporting an explicit remote revocation-proof / nullifier mechanism propagated faster than full root retention windows.

### Proof of Concept
Extend `remote_proxy_works` in `pallets/remote-proxy/src/tests.rs`:
1. Set up `real` with a relay-chain proxy delegation to `attacker`; capture `proof_old` and `block_old` for this state.
2. Call the mock relay chain's `pallet_proxy::remove_proxy` to revoke `attacker`'s delegation, advancing to `block_new`, while keeping `block_old` still within `BlockToRoot`'s window (`block_new - block_old <= MaxStorageRootsToKeep`).
3. Call `RemoteProxy::remote_proxy(real, None, call, RemoteProxyProof::RelayChain{ proof: proof_old, block: block_old })` as `attacker` and assert it succeeds (`Ok`), proving replay of the stale proof dispatches `call` as `real`.
4. Advance further until `block_old` is evicted from `BlockToRoot` (beyond `MaxStorageRootsToKeep`), retry the same call, and assert it now fails with `Error::UnknownProofAnchorBlock`, confirming the window-bounded replay behavior.

### Citations

**File:** pallets/remote-proxy/src/lib.rs (L41-48)
```rust
//! As explained above the security of the proxy depends on the remote location. So, if the remote
//! location is not trusted, it should not be configured as remote location. When configuring
//! [`MaxStorageRootsToKeep`](Config::MaxStorageRootsToKeep) it should be considered that the
//! lifetime of a proxy will be [`MaxStorageRootsToKeep`](Config::MaxStorageRootsToKeep) in the
//! past. This means when deleting a proxy at the remote location at X, it will take
//! [`MaxStorageRootsToKeep`](Config::MaxStorageRootsToKeep) time until the proxy can not be used
//! anymore. The reason for this is that the caller will be able to provide an old `proof` at which
//! the proxy was still available.
```

**File:** pallets/remote-proxy/src/lib.rs (L207-227)
```rust
	impl<T: Config<I>, I: 'static> OnSystemEvent for Pallet<T, I> {
		fn on_validation_data(validation_data: &PersistedValidationData) {
			let Some((block, hash)) = T::RemoteProxy::block_to_storage_root(validation_data) else {
				return;
			};

			// Update the block to root mappings.
			BlockToRoot::<T, I>::mutate(|roots| {
				let delete_up_to =
					block.clone().saturating_sub(T::MaxStorageRootsToKeep::get().into());

				while roots.first().is_some_and(|f| f.0 <= delete_up_to) {
					roots.remove(0);
				}

				// We always remove all the old items before, thus there should always be space in
				// the vector.
				let _res = roots.try_push((block, hash));
				debug_assert!(_res.is_ok());
			});
		}
```

**File:** pallets/remote-proxy/src/lib.rs (L405-429)
```rust
			let def = match proof {
				RemoteProxyProof::RelayChain { proof, block } => {
					let roots = BlockToRoot::<T, I>::get();

					let Ok(storage_root) = roots
						.binary_search_by(|(b, _)| b.cmp(&block))
						.map(|pos| roots[pos].1.clone())
					else {
						return Err(Error::<T, I>::UnknownProofAnchorBlock.into());
					};

					let key = T::RemoteProxy::proxy_definition_storage_key(&real_remote);

					let db =
						sp_trie::StorageProof::new(proof).into_memory_db::<RemoteHasherOf<T, I>>();
					let value = sp_trie::read_trie_value::<sp_trie::LayoutV1<_>, _>(
						&db,
						&storage_root,
						&key,
						None,
						None,
					)
					.ok()
					.flatten()
					.ok_or(Error::<T, I>::InvalidProof)?;
```

**File:** pallets/remote-proxy/src/lib.rs (L458-458)
```rust
			ensure!(def.delay.is_zero(), Error::<T, I>::Unannounced);
```

**File:** pallets/remote-proxy/src/lib.rs (L460-460)
```rust
			Self::do_proxy(def, real, call);
```
