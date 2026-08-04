### Title
Fixed-weight benchmarking of `remote_proxy` doesn't scale with attacker-controlled proof size, allowing block-weight underestimation on the `Unannounced` (and other) error paths - (File: pallets/remote-proxy/src/lib.rs)

### Summary
`Pallet::do_remote_proxy` performs full trie-proof verification and SCALE-decoding of the proxy definition list *before* checking `def.delay.is_zero()` (`Unannounced`), yet the benchmarked weight `WeightInfoOf::remote_proxy()` is a fixed constant derived from a benchmark using a 105-byte proof [1](#0-0) . Because the `proof: Vec<Vec<u8>>` field is not size-bound to the benchmarked case, an attacker can submit a much larger (still transaction-size-limited) proof so that `sp_trie::read_trie_value` and the subsequent `Vec::<ProxyDefinition<..>>::decode` cost materially more than the fixed weight charged, and this cost is fully paid before the cheap `Unannounced` check aborts execution.

### Finding Description
`Pallet::do_remote_proxy` executes, in order: `local_to_remote_account_id`, a `BlockToRoot` storage read/binary search, `sp_trie::StorageProof::new(proof).into_memory_db(...)` + `sp_trie::read_trie_value(...)`, `Vec::<ProxyDefinition<...>>::decode(...)`, a linear `find` over decoded definitions, and only then `ensure!(def.delay.is_zero(), Error::<T, I>::Unannounced)` [2](#0-1) . All of the expensive trie-verification/decoding work happens before the delay check, so a caller who legitimately holds a non-zero-delay proxy on the remote chain (a normal configuration state, not a privileged one) will always reach `Unannounced` only after paying that cost.

The declared weight for the `remote_proxy` extrinsic is:
```
WeightInfoOf::<T, I>::remote_proxy()
    .saturating_add(T::DbWeight::get().reads_writes(1, 1))
    .saturating_add(di.call_weight)
``` [3](#0-2) 
`WeightInfoOf::remote_proxy()` itself is a constant (`Weight::from_parts(18_259_000, 0)` plus one DB read) generated from a benchmark that always uses a fixed, tiny (105-byte measured) proof via `T::RemoteProxy::create_remote_proxy_proof` [4](#0-3) [5](#0-4) . Nothing in the weight annotation scales with `proof.len()`/number of trie nodes supplied by the caller — the `RemoteProxyProof::RelayChain { proof: Vec<Vec<u8>>, block }` variant has no `#[codec(compact)]`/`BoundedVec` size cap tied to the weight formula [6](#0-5) . `di.call_weight` (the inner call's weight) is added on top but is irrelevant to this cost, since the inner call is never dispatched when the delay check fails — that portion is only an over-charge, not an under-charge.

Because the trie-proof verification (`read_trie_value`) and SCALE-decoding scale with the number/size of nodes provided in `proof`, and the caller fully controls this argument (only bounded by the runtime's max-extrinsic-length limit, not by the benchmark's fixed 105-byte case), an attacker can submit a proof containing far more trie nodes than benchmarked while still resolving to the same `Unannounced` outcome, causing measured execution time for that call to exceed the fixed declared weight.

Existing protections that fail to stop this: the `ensure!` check is purely logical and comes after the expensive computation, not before it; there is no upfront cheap check (e.g., verifying `delay == 0` from some cached data) prior to trie verification; and the weight formula has no size-dependent component to bound worst-case proof-processing cost.

### Impact Explanation
Repeatedly submitting `remote_proxy` calls that all resolve to `Unannounced` (or other post-verification errors) with maximally-sized proofs lets an attacker consume disproportionate wall-clock/computation time relative to the weight actually reserved for those extrinsics in a block. Because each call individually passes signature/fee/weight pre-checks (the declared weight is a fixed, "legal" amount), a batch of such calls can be scheduled into a block whose *actual* execution cost is materially higher than its *declared* weight indicates, degrading block-production throughput/timing without directly violating the block's declared weight limit accounting. This is a resource-exhaustion/DoS-adjacent concern rather than an asset-safety issue.

### Likelihood Explanation
Preconditions are realistic and cheap to obtain: an attacker only needs to be granted *any* delayed proxy by a real account on the remote chain (a normal, unprivileged configuration), or — more simply — needs no valid proxy relationship at all, since an oversized/garbage `proof` will also incur the same expensive verification before failing at `InvalidProof`/`ProxyDefinitionDecodingFailed`/`DidNotFindMatchingProxyDefinition`, which are reached via the identical code path [7](#0-6) . This makes the attack trivially repeatable: an attacker can submit many such calls per block (each independently valid per the fee/weight system), each incurring full trie-verification cost while paying only the fixed benchmarked weight.

### Recommendation
- Introduce a weight component in `remote_proxy`'s `#[pallet::weight]` annotation that scales with the size/node-count of the supplied `proof` (similar to how storage-proof-consuming pallets like `pallet-bridge-grandpa`/XCMP proof verification price proof size), or bound `proof: Vec<Vec<u8>>` with a strict `MaxEncodedLen`/`BoundedVec` cap matched to the benchmarked worst case.
- Alternatively, reject proofs whose total encoded size exceeds the size used in benchmarking before attempting `read_trie_value`/decode.
- Consider re-benchmarking with a worst-case-sized proof (matching whatever cap is enforced) so `WeightInfoOf::remote_proxy()` bounds the true worst-case verification+decode cost, independent of which error branch is eventually hit.

### Proof of Concept
Benchmark differential test:
1. Construct two `RemoteProxyProof::RelayChain` proofs against the same `real`/`storage_root`: (a) the pallet's benchmark-generated minimal proof (~105 bytes, as used in `create_remote_proxy_proof`), and (b) a maximal-size proof filled with padding trie nodes up to the runtime's max extrinsic length, for a proxy definition with `delay > 0`.
2. Call `Pallet::do_remote_proxy` (or the public `remote_proxy` extrinsic) with each proof and measure actual execution time/weight via `frame_benchmarking`'s low-level timing harness or a Rust unit test using `std::time::Instant` around the call.
3. Assert: `measured_weight(proof_b) > WeightInfoOf::<T, I>::remote_proxy()`, i.e., the large-proof `Unannounced` failure exceeds the declared weight, while `measured_weight(proof_a)` stays within it — demonstrating that the declared constant weight does not bound the worst case.
4. Optionally extend to an integration test issuing N such `remote_proxy(proof_b)` extrinsics in one block and comparing cumulative measured weight vs. cumulative declared weight to quantify the disproportionate cost.

### Citations

**File:** system-parachains/asset-hubs/asset-hub-kusama/src/weights/pallet_remote_proxy.rs (L54-64)
```rust
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

**File:** pallets/remote-proxy/src/lib.rs (L405-459)
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

					let proxy_definitions = alloc::vec::Vec::<
						ProxyDefinition<
							RemoteAccountIdOf<T, I>,
							RemoteProxyTypeOf<T, I>,
							RemoteBlockNumberOf<T, I>,
						>,
					>::decode(&mut &value[..])
					.map_err(|_| Error::<T, I>::ProxyDefinitionDecodingFailed)?;

					let f = |x: &ProxyDefinition<
						T::AccountId,
						T::ProxyType,
						BlockNumberFor<T>,
					>|
					 -> bool {
						x.delegate == who &&
							force_proxy_type.as_ref().is_none_or(|y| &x.proxy_type == y)
					};

					proxy_definitions
						.into_iter()
						.filter_map(T::RemoteProxy::remote_to_local_proxy_defintion)
						.find(f)
						.ok_or(Error::<T, I>::DidNotFindMatchingProxyDefinition)?
				},
			};

			ensure!(def.delay.is_zero(), Error::<T, I>::Unannounced);

```

**File:** pallets/remote-proxy/src/benchmarking.rs (L48-71)
```rust
	#[benchmark]
	fn remote_proxy() -> Result<(), BenchmarkError> {
		// In this case the caller is the "target" proxy
		let caller: T::AccountId = account("target", 0, SEED);
		<T as pallet_proxy::Config>::Currency::make_free_balance_be(
			&caller,
			BalanceOf::<T>::max_value() / 2u32.into(),
		);
		// ... and "real" is the traditional caller. This is not a typo.
		let real: T::AccountId = whitelisted_caller();
		let real_lookup = T::Lookup::unlookup(real.clone());
		let call: <T as pallet_proxy::Config>::RuntimeCall =
			frame_system::Call::<T>::remark { remark: vec![] }.into();
		let (proof, block_number, storage_root) =
			T::RemoteProxy::create_remote_proxy_proof(&caller, &real);
		BlockToRoot::<T, I>::set(BoundedVec::truncate_from(vec![(block_number, storage_root)]));

		#[extrinsic_call]
		_(RawOrigin::Signed(caller), real_lookup, None, Box::new(call), proof);

		assert_last_event::<T>(pallet_proxy::Event::ProxyExecuted { result: Ok(()) }.into());

		Ok(())
	}
```
