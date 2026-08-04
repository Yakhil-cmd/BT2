### Title
Unbounded `proof: Vec<Vec<u8>>` size in `remote_proxy` allows actual verification cost to exceed the fixed benchmarked weight - ([File: pallets/remote-proxy/src/lib.rs])

### Summary
`Pallet::remote_proxy` and `remote_proxy_with_registered_proof` charge a **fixed** weight (`WeightInfoOf::<T, I>::remote_proxy()`), benchmarked against a minimal single-entry trie proof, but the actual `RemoteProxyProof::RelayChain { proof: Vec<Vec<u8>>, .. }` accepted from a signed extrinsic has no size/node-count bound tied to the weight formula. An attacker can submit a signed `remote_proxy` call with a much larger (but still extrinsic-length-limited) `proof` to make `sp_trie::StorageProof::new(proof).into_memory_db(..)` and `read_trie_value` do disproportionately more hashing/allocation work than what was accounted for, creating a weight-accounting mismatch.

### Finding Description
`do_remote_proxy` in [1](#0-0)  takes the caller-supplied `proof: Vec<Vec<u8>>` unconditionally, builds an in-memory trie DB from it, and performs a `read_trie_value` lookup:
```
let db = sp_trie::StorageProof::new(proof).into_memory_db::<RemoteHasherOf<T, I>>();
let value = sp_trie::read_trie_value::<sp_trie::LayoutV1<_>, _>(&db, &storage_root, &key, None, None)...
```
There is no check on `proof.len()` or total encoded byte size before this call, and `RemoteProxyProof` carries no `MaxEncodedLen`-style bound in `Config` (only `MaxStorageRootsToKeep` bounds the `BlockToRoot` storage, see [2](#0-1)  and [3](#0-2) ).

The dispatched weight for `remote_proxy` is a static value from `WeightInfoOf::<T, I>::remote_proxy()` plus the inner call's weight, with no term scaling with `proof` size:
```
#[pallet::weight({
    let di = call.get_dispatch_info();
    (WeightInfoOf::<T, I>::remote_proxy()
        .saturating_add(T::DbWeight::get().reads_writes(1, 1))
        .saturating_add(di.call_weight),
    di.class)
})]
```
( [4](#0-3) )

The benchmark that produces `WeightInfoOf::<T, I>::remote_proxy()` only ever constructs a trie with a **single** proxy-definition entry via `create_remote_proxy_proof` ( [5](#0-4) , and the interface implementation used on relay chains at [6](#0-5) ), so the benchmark never captures the cost of a large, attacker-supplied `proof` vector.

An unprivileged, signed account can call `remote_proxy` (origin check is only `ensure_signed`, see [7](#0-6) ) using any still-valid anchor block from `BlockToRoot` (bounded by `MaxStorageRootsToKeep`, evicted in `on_validation_data`, [8](#0-7) ) and a crafted, maximally-sized `proof: Vec<Vec<u8>>` — up to the runtime's normal extrinsic/block length limit — that decodes fine via `StorageProof::new` but forces `into_memory_db` to hash/insert far more node bytes than the single-node case the weight was benchmarked on.

### Impact Explanation
Because the declared weight for `remote_proxy` does not scale with `proof` size, actual execution cost (memory allocation + hashing of every supplied trie node in `into_memory_db`, even nodes irrelevant to the traversal) can exceed the accounted weight. Repeated submission of such calls (each failing at the final `find(f)` step with `DidNotFindMatchingProxyDefinition`/`InvalidProof`, which is cheap to trigger while still paying the up-front trie-DB construction cost) lets an attacker consume disproportionate actual computation per unit of accounted block weight, causing weight-accounting drift that can degrade block-building/import time and starve legitimate extrinsics of effective throughput — a temporary DoS as scoped.

### Likelihood Explanation
Feasible and repeatable for any signed account: the attacker only needs (1) a known, currently-retained anchor `block` in `BlockToRoot` (trivially observable on-chain), and (2) an extrinsic-length-limit-bounded `proof` vector filled with arbitrary/garbage byte blobs (does not need to be a real trie fragment tied to the real proxy account — it just needs to decode via `StorageProof::new`, which accepts arbitrary `Vec<Vec<u8>>`). The call can be resubmitted every block since it is a normal signed extrinsic, so the attack is fully repeatable and cheap relative to the imbalance created.

### Recommendation
- Add an explicit bound (e.g. `MaxProofSize`/`MaxProofNodes` in `Config`) enforced before constructing the trie DB, rejecting oversized `proof` vectors early with a cheap error.
- Make the declared weight for `remote_proxy`/`remote_proxy_with_registered_proof` a function of `proof.len()`/total encoded size (component-based benchmarking, similar to how bridge/light-client pallets benchmark proof-size-dependent weight), rather than a single fixed benchmarked constant.
- Alternatively, charge a proof-size-proportional pre-dispatch fee/weight surcharge so cost scales with attacker-supplied input size.

### Proof of Concept
Rust integration test plan (extending `pallets/remote-proxy/src/tests.rs`):
1. Set up `BlockToRoot` with a valid anchor block/root as in `clean_up_works_and_old_blocks_are_rejected` ( [9](#0-8) ).
2. Construct two proofs against the same benchmarked weight: (a) the standard single-entry proof used in existing tests, (b) an artificially inflated `proof: Vec<Vec<u8>>` containing thousands of large filler byte vectors (still under the runtime's max extrinsic length) alongside the legitimate proof nodes.
3. Measure wall-clock/instruction count of `Pallet::do_remote_proxy` (or directly `sp_trie::StorageProof::new(proof).into_memory_db(..)`) for both cases.
4. Assert that execution cost for (b) grows materially with proof size while `WeightInfoOf::<T,I>::remote_proxy()` stays constant, i.e. `actual_cost(b) >> declared_weight` and `actual_cost(b)/actual_cost(a) >> proof_size(b)/proof_size(a)` is not similarly bounded — demonstrating the weight/cost ratio is not preserved as `proof` size grows toward the length limit.

### Citations

**File:** pallets/remote-proxy/src/lib.rs (L177-205)
```rust
	#[pallet::storage]
	pub type BlockToRoot<T: Config<I>, I: 'static = ()> = StorageValue<
		_,
		BoundedVec<(RemoteBlockNumberOf<T, I>, RemoteHashOf<T, I>), T::MaxStorageRootsToKeep>,
		ValueQuery,
	>;

	/// Configuration trait.
	#[pallet::config]
	pub trait Config<I: 'static = ()>: frame_system::Config + pallet_proxy::Config {
		/// The maximum number of storage roots to keep.
		///
		/// The storage roots are used to validate the remote proofs. The more we keep in storage,
		/// the older the proof can be. This is not only seen as a maximum number, but also as the
		/// maximum difference between the latest and the oldest storage root stored. This means
		/// that if the chain for example did not progress for `MaxStorageRootsToKeep` blocks, only
		/// the latest added storage root will be available for validating proofs.
		type MaxStorageRootsToKeep: Get<u32>;

		/// The interface for interacting with the remote proxy.
		type RemoteProxy: RemoteProxyInterface<
			Self::AccountId,
			Self::ProxyType,
			BlockNumberFor<Self>,
		>;

		/// Weight information for extrinsics in this pallet.
		type WeightInfo: WeightInfo;
	}
```

**File:** pallets/remote-proxy/src/lib.rs (L208-227)
```rust
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

**File:** relay/polkadot/constants/src/lib.rs (L235-266)
```rust
		// Skip 4 as it is now removed (was SudoBalances)
		// Skip 5 as it was IdentityJudgement
		CancelProxy = 6,
		Auction = 7,
		NominationPools = 8,
		ParaRegistration = 9,
	}

	/// Remote proxy interface that uses the relay chain as remote location.
	pub struct RemoteProxyInterface<LocalProxyType, ProxyDefinitionConverter>(
		core::marker::PhantomData<(LocalProxyType, ProxyDefinitionConverter)>,
	);

	impl<
			LocalProxyType,
			ProxyDefinitionConverter: Convert<
				ProxyDefinition<AccountId, ProxyType, BlockNumber>,
				Option<ProxyDefinition<AccountId, LocalProxyType, BlockNumber>>,
			>,
		> pallet_remote_proxy::RemoteProxyInterface<AccountId, LocalProxyType, BlockNumber>
		for RemoteProxyInterface<LocalProxyType, ProxyDefinitionConverter>
	{
		type RemoteAccountId = AccountId;

		type RemoteProxyType = ProxyType;

		type RemoteBlockNumber = BlockNumber;

		type RemoteHash = Hash;

		type RemoteHasher = BlakeTwo256;

```

**File:** pallets/remote-proxy/src/tests.rs (L600-632)
```rust
#[test]
fn clean_up_works_and_old_blocks_are_rejected() {
	new_test_ext().execute_with(|| {
		let root = H256::zero();
		let call = Box::new(call_transfer(6, 1));

		BlockToRoot::<Test>::set(BoundedVec::truncate_from(vec![
			(0, root),
			(10, root),
			(20, root),
			(29, root),
		]));

		RemoteProxy::on_validation_data(&PersistedValidationData {
			parent_head: vec![].into(),
			relay_parent_number: 30,
			relay_parent_storage_root: root,
			max_pov_size: 5000000,
		});
		BlockToRoot::<Test>::get()
			.iter()
			.for_each(|(b, _)| assert!(*b == 29 || *b == 30));
		assert_err!(
			RemoteProxy::remote_proxy(
				RuntimeOrigin::signed(1),
				1000,
				None,
				call.clone(),
				RemoteProxyProof::RelayChain { proof: vec![], block: 5 }
			),
			Error::<Test>::UnknownProofAnchorBlock
		);

```
