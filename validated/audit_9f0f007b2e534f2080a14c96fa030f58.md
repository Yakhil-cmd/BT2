### Title
Unbounded-size `RemoteProxyProof::RelayChain.proof` allows fixed-weight `remote_proxy`/`remote_proxy_with_registered_proof` calls to consume execution time far beyond their declared weight - (File: pallets/remote-proxy/src/lib.rs)

### Summary
`do_remote_proxy` builds a `MemoryDB` from the caller-supplied `proof: Vec<Vec<u8>>` via `StorageProof::new(proof).into_memory_db(...)`, which hashes and inserts every supplied blob unconditionally before any trie lookup occurs. The dispatch weight for `remote_proxy`/`remote_proxy_with_registered_proof` is a fixed constant (`WeightInfoOf::remote_proxy()`) benchmarked against a trivial single-node proof and does not scale with the actual size of the attacker-supplied `proof` vector, which is unbounded except by the generic extrinsic length limit.

### Finding Description
In `do_remote_proxy`, the `RelayChain` proof-verification path is: [1](#0-0) 

`sp_trie::StorageProof::new(proof).into_memory_db::<RemoteHasherOf<T, I>>()` iterates over every entry in the attacker-supplied `proof: Vec<Vec<u8>>` and hashes/stores each one in a `MemoryDB` — this cost is `O(total bytes of proof)` and occurs *before* `read_trie_value` ever walks the trie. `read_trie_value` itself only needs to follow nodes on the path from root to `key`, so unrelated/garbage/duplicate blobs padded into `proof` contribute no verification value but still incur full hashing/insertion cost.

The declared dispatch weight for the extrinsic is: [2](#0-1) 

`WeightInfoOf::<T, I>::remote_proxy()` is a flat constant derived from a benchmark that constructs a proof for exactly one stored key (a single trie node), as seen in the benchmark harness: [3](#0-2) 

and reflected in the generated weight file, which reports a small fixed `Measured`/`Estimated` proof size (105/1846 bytes) and a fixed ~18µs execution time: [4](#0-3) 

Nothing in the pallet bounds the size of `proof: Vec<Vec<u8>>` inside `RemoteProxyProof::RelayChain`: [5](#0-4) 

There is no `MaxEncodedLen`/`BoundedVec` constraint on the proof field, no cap on number-of-nodes or total-proof-bytes checked in `do_remote_proxy`, and no weight component that grows with `proof.len()`. The only constraint is the generic extrinsic/PoV length limit enforced by `frame_system`/block-length configuration, which is on the order of several MB for the Normal dispatch class — far larger than the single-node proof the benchmark measured. An attacker (any signed account) can therefore submit `remote_proxy(real, None, remark, garbage_proof)` where `garbage_proof` is padded with a large number of bogus/duplicate byte blobs sized just under the length limit; the call still parses as a valid `StorageProof`, forces `into_memory_db` to hash/insert all of it, ultimately fails to resolve the real key, and returns `Error::InvalidProof` — while being charged only the fixed, tiny benchmarked weight.

### Impact Explanation
Because the charged weight for `remote_proxy` does not reflect the actual proof-processing cost, a signed attacker can pack many such calls into a block, each declared as cheap (fixed weight from a 1-node benchmark) but each actually performing MB-scale hashing/insertion work. This creates a mismatch between metered weight (which gates how many extrinsics/how much declared weight fits in the Normal dispatch-class budget) and real computation time, letting an attacker consume disproportionate CPU time within a block relative to the weight budget it "used." This does not directly corrupt asset accounting or forge origins, but it is a real weight/DoS-adjacent flaw: the pallet under-prices proof-size-dependent computation.

### Likelihood Explanation
Preconditions are minimal: any unprivileged signed account with balance to pay extrinsic fees can construct such a call, since `proof` bytes are entirely attacker-controlled and unchecked for size/validity before the costly `into_memory_db` step. The attack is trivially repeatable across many transactions/blocks, bounded only by the fee cost of large extrinsics and the existing block length limit, both of which permit proofs orders of magnitude larger than the benchmarked case.

### Recommendation
Bound the size of `RemoteProxyProof::RelayChain.proof` (e.g., cap total node count and/or total byte size with a `Config`-configurable limit), and make the extrinsic's declared weight scale with the actual supplied proof size (e.g., add a `Weight::from_parts(proof_len * per_byte_cost, 0)` component derived from a size-parameterized benchmark), similar to how other proof-consuming pallets (e.g., GRANDPA/BEEFY justification verification) charge weight proportional to input size rather than a flat constant.

### Proof of Concept
Rust unit test plan (extend `pallets/remote-proxy/src/tests.rs`):
1. Build a valid single-key trie proof as in `remote_proxy_works`, then pad the `proof: Vec<Vec<u8>>` with `N` additional large random byte vectors (e.g. 10,000 entries of ~200 bytes each, staying under `BlockLength` Normal-class limits) that are not part of the real trie path.
2. Call `RemoteProxy::remote_proxy(...)` with this padded proof and assert it still returns `Error::<Test>::InvalidProof` (or succeeds if the real key happens to still resolve) — confirming padding doesn't break proof parsing.
3. Using `std::time::Instant`, measure wall-clock time of `do_remote_proxy`/`into_memory_db` for the padded proof vs. the single-node benchmark proof, and assert the ratio of `(actual_time_for_large_proof / actual_time_for_benchmark_proof)` is not bounded by `(WeightInfo::remote_proxy() ratio == 1)`, i.e., assert `actual_time_large >> declared_weight_time`, demonstrating the fixed weight does not scale with attacker-supplied proof size.

### Citations

**File:** pallets/remote-proxy/src/lib.rs (L260-263)
```rust
	pub enum RemoteProxyProof<RemoteBlockNumber> {
		/// Assumes the default proxy storage layout.
		RelayChain { proof: Vec<Vec<u8>>, block: RemoteBlockNumber },
	}
```

**File:** pallets/remote-proxy/src/lib.rs (L284-304)
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
		pub fn remote_proxy(
			origin: OriginFor<T>,
			real: AccountIdLookupOf<T>,
			force_proxy_type: Option<T::ProxyType>,
			call: Box<<T as pallet_proxy::Config>::RuntimeCall>,
			proof: RemoteProxyProof<RemoteBlockNumberOf<T, I>>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			let real = T::Lookup::lookup(real)?;

			Self::do_remote_proxy(who, real, force_proxy_type, *call, proof)
		}
```

**File:** pallets/remote-proxy/src/lib.rs (L416-429)
```rust
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

**File:** system-parachains/asset-hubs/asset-hub-kusama/src/weights/pallet_remote_proxy.rs (L53-64)
```rust
impl<T: frame_system::Config> pallet_remote_proxy::WeightInfo for WeightInfo<T> {
	/// Storage: `RemoteProxyRelayChain::BlockToRoot` (r:1 w:0)
	/// Proof: `RemoteProxyRelayChain::BlockToRoot` (`max_values`: Some(1), `max_size`: Some(361), added: 856, mode: `MaxEncodedLen`)
	fn remote_proxy() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `105`
		//  Estimated: `1846`
		// Minimum execution time: 16_009_000 picoseconds.
		Weight::from_parts(18_259_000, 0)
			.saturating_add(Weight::from_parts(0, 1846))
			.saturating_add(T::DbWeight::get().reads(1))
	}
```
