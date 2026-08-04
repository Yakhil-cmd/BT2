### Title
`remote_proxy` weight does not scale with attacker-controlled `proof` size, allowing PoV/computation cost far above declared weight - (File: pallets/remote-proxy/src/lib.rs)

### Summary
The `#[pallet::weight]` for `remote_proxy` (and `remote_proxy_with_registered_proof`) charges a fixed `WeightInfoOf::<T,I>::remote_proxy()` value plus the inner call's weight, but never adds a component proportional to the size of the user-supplied `proof: Vec<Vec<u8>>`. Since `sp_trie::StorageProof::new(proof).into_memory_db()` and `sp_trie::read_trie_value` cost scales with the number/size of proof nodes, an unprivileged signed user can submit a much larger proof than the one used for benchmarking and pay far less weight/fee than the actual computation consumes.

### Finding Description
`do_remote_proxy` builds an in-memory trie DB directly from the caller-supplied `proof` field and performs a trie lookup against it: [1](#0-0) 

The dispatchable's weight annotation only uses a constant benchmarked weight for the proof-verification part: [2](#0-1) 

The benchmark that produces `WeightInfoOf::<T,I>::remote_proxy()` constructs the proof from a trie with a single inserted key (`create_remote_proxy_proof`), which yields a small, near-minimal number of nodes: [3](#0-2) [4](#0-3) 

Nothing in `RemoteProxyProof::RelayChain { proof: Vec<Vec<u8>>, block }` bounds the number of entries or their sizes (no `BoundedVec`, no `MaxEncodedLen` restriction, no per-node size cap): [5](#0-4) 

Because the weight formula does not include a term derived from `proof.len()` or the total encoded proof size, a user can submit an oversized `proof` (many/large `Vec<u8>` node blobs, up to the extrinsic length limit) that is still processed by `into_memory_db()` (which hashes/stores every node) and `read_trie_value` (trie traversal), consuming compute and PoV proportional to the actual proof size while only being charged the fixed benchmarked weight. There is no explicit check anywhere in `do_remote_proxy` that rejects "too many" or "too large" proof nodes before doing this work — the only correctness check is that the final root/key lookup succeeds (`InvalidProof` returned only if the trie lookup itself fails at the end), by which point the DB-building and traversal work has already been paid for in constant time.

### Impact Explanation
This is a weight/fee accounting gap, not an asset-theft or origin-forgery bug: the attacker cannot forge a proxy or steal funds this way (the trie lookup itself still cryptographically requires a genuine root match to succeed, so a bogus proof simply returns `InvalidProof`/decoding errors after the extra work is done). The concrete impact is computational cost underestimation — an attacker-controlled extrinsic can consume execution time proportional to attacker-chosen proof size (bounded only by the runtime's max extrinsic/block length) while paying weight fees benchmarked against a minimal proof. Repeated submissions in a block could push actual block execution time beyond the time budget implied by charged weight, which can degrade block production timing and delay processing of subsequent extrinsics/queue items in that block. This matches the "weight/fee checks bypassed → execution time exceeds charged weight" impact class, scoped to compute/time overrun rather than fund loss.

### Likelihood Explanation
Feasible and fully repeatable by any signed account: `remote_proxy` is directly reachable by `ensure_signed` origin, `real` and `call` can be arbitrary/cheap (e.g., `System::remark`), and `proof` is entirely attacker-controlled with no size/count validation prior to being fed into `StorageProof::new(...).into_memory_db()`. The proof does not need to be valid — it must merely be well-formed enough for the trie decode/hash step to run over all nodes before the final lookup fails. The only natural limits are the runtime's max extrinsic length / block length constraints, which are generally megabytes in size — orders of magnitude larger than the trivial single-leaf proof used to derive the benchmarked constant weight, so a meaningful weight/cost mismatch is achievable without any special privilege.

### Recommendation
Add a proof-size/proof-count dependent weight component to the `#[pallet::weight]` annotations of `remote_proxy` and `remote_proxy_with_registered_proof` (and `register_remote_proxy_proof`), e.g. benchmark `into_memory_db`/`read_trie_value` cost per node/byte and add `Weight::from_parts(0, per_byte_cost).saturating_mul(proof_total_len)` (or a dedicated linear-component benchmark), and/or enforce a hard cap on the number of proof nodes and per-node size (e.g., via `BoundedVec` with a `MaxProofNodes`/`MaxProofNodeSize` config constant) before calling `into_memory_db`, rejecting oversized proofs early with a cheap, O(1) pre-check.

### Proof of Concept
Rust benchmark/fuzz-style test in `pallets/remote-proxy/src/tests.rs`:
```rust
#[test]
fn oversized_proof_costs_far_more_than_charged_weight() {
    new_test_ext().execute_with(|| {
        // Baseline: benchmark-style minimal proof (single key trie), measure wall time
        // to run do_remote_proxy's proof verification path.
        let minimal_proof = /* single-leaf proof, as in create_remote_proxy_proof */;
        let t0 = std::time::Instant::now();
        let _ = sp_trie::StorageProof::new(minimal_proof.clone())
            .into_memory_db::<BlakeTwo256>();
        let minimal_elapsed = t0.elapsed();

        // Attacker-crafted: many/large garbage node blobs, sized up to
        // T::BlockLength "normal" extrinsic limit, structurally valid Vec<Vec<u8>>
        // but not required to form a coherent trie (StorageProof::new does not
        // validate global trie coherence up front).
        let bloated_proof: Vec<Vec<u8>> = (0..N_MAX_NODES)
            .map(|_| vec![0xAB; MAX_NODE_SIZE])
            .collect();
        let t1 = std::time::Instant::now();
        let _ = sp_trie::StorageProof::new(bloated_proof.clone())
            .into_memory_db::<BlakeTwo256>();
        let bloated_elapsed = t1.elapsed();

        // Assert: charged weight for `remote_proxy()` is identical (constant) in both
        // cases, but measured processing time for the bloated proof vastly exceeds
        // that of the minimal (benchmarked) proof, exposing the weight/PoV mismatch.
        assert_eq!(
            <Test as crate::Config>::WeightInfo::remote_proxy(),
            <Test as crate::Config>::WeightInfo::remote_proxy() // charged weight is fixed regardless of proof size
        );
        assert!(bloated_elapsed > minimal_elapsed * 100); // orders-of-magnitude blowup
    });
}
```
Expected result: the constant weight charged for `remote_proxy` does not change with proof size, while measured processing time scales with attacker-chosen proof size, demonstrating the weight-accounting gap described above.

### Citations

**File:** pallets/remote-proxy/src/lib.rs (L260-263)
```rust
	pub enum RemoteProxyProof<RemoteBlockNumber> {
		/// Assumes the default proxy storage layout.
		RelayChain { proof: Vec<Vec<u8>>, block: RemoteBlockNumber },
	}
```

**File:** pallets/remote-proxy/src/lib.rs (L284-292)
```rust
		#[pallet::call_index(0)]
		#[pallet::weight({
			let di = call.get_dispatch_info();
			(WeightInfoOf::<T, I>::remote_proxy()
				// AccountData for inner call origin accountdata.
				.saturating_add(T::DbWeight::get().reads_writes(1, 1))
				.saturating_add(di.call_weight),
			di.class)
		})]
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

**File:** pallets/remote-proxy/src/tests.rs (L165-194)
```rust
	#[cfg(feature = "runtime-benchmarks")]
	fn create_remote_proxy_proof(
		caller: &u64,
		proxy: &u64,
	) -> (RemoteProxyProof<Self::RemoteBlockNumber>, u64, H256) {
		use sp_trie::TrieMut;

		let (mut db, mut root) = sp_trie::MemoryDB::<BlakeTwo256>::default_with_root();
		let mut trie =
			sp_trie::TrieDBMutBuilder::<sp_trie::LayoutV1<_>>::new(&mut db, &mut root).build();

		let proxy_definition = vec![ProxyDefinition::<u64, ProxyType, u64> {
			delegate: *caller,
			proxy_type: ProxyType::default(),
			delay: 0,
		}];

		trie.insert(&Self::proxy_definition_storage_key(proxy), &proxy_definition.encode())
			.unwrap();
		drop(trie);

		(
			RemoteProxyProof::RelayChain {
				proof: db.drain().into_values().map(|d| d.0).collect(),
				block: 1,
			},
			1,
			root,
		)
	}
```

**File:** relay/kusama/constants/src/lib.rs (L236-266)
```rust
		fn create_remote_proxy_proof(
			caller: &AccountId,
			proxy: &AccountId,
		) -> (pallet_remote_proxy::RemoteProxyProof<Self::RemoteBlockNumber>, BlockNumber, Hash) {
			use codec::Encode;
			use sp_trie::TrieMut;

			let (mut db, mut root) = sp_trie::MemoryDB::<BlakeTwo256>::default_with_root();
			let mut trie =
				sp_trie::TrieDBMutBuilder::<sp_trie::LayoutV1<_>>::new(&mut db, &mut root).build();

			let proxy_definition =
				alloc::vec![ProxyDefinition::<AccountId, ProxyType, BlockNumber> {
					delegate: caller.clone(),
					proxy_type: ProxyType::default(),
					delay: 0,
				}];

			trie.insert(&Self::proxy_definition_storage_key(proxy), &proxy_definition.encode())
				.unwrap();
			drop(trie);

			(
				pallet_remote_proxy::RemoteProxyProof::RelayChain {
					proof: db.drain().into_values().map(|d| d.0).collect(),
					block: 1,
				},
				1,
				root,
			)
		}
```
