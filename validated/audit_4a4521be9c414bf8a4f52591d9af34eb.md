### Title
`BlockToRoot` binary-search relies on an unenforced monotonicity assumption, causing spurious `UnknownProofAnchorBlock` for still-retained roots - (File: pallets/remote-proxy/src/lib.rs)

### Summary
`OnSystemEvent::on_validation_data` always appends the new `(block, hash)` pair to the end of `BlockToRoot` via `try_push`, assuming `block` values arrive in strictly ascending order. `do_remote_proxy` then looks up an anchor block with `roots.binary_search_by(|(b, _)| b.cmp(&block))`, which is only correct if `roots` is sorted ascending. Under async backing, relay-parent numbers observed across successive `on_validation_data` calls are not guaranteed to be non-decreasing, so the vector can become unsorted, breaking `binary_search_by` and causing legitimate, still-retained anchors to be reported as `UnknownProofAnchorBlock`.

### Finding Description
`on_validation_data` mutates `BlockToRoot` purely by trimming from the front and pushing the new entry at the back: [1](#0-0) 

This logic implicitly assumes `block` (derived from `T::RemoteProxy::block_to_storage_root(validation_data)`, i.e., the relay-parent block/storage root pair for the current relay-parent) increases monotonically call over call. Nothing in this pallet enforces that assumption — there is no check that the new `block` is greater than the last stored entry before pushing.

`do_remote_proxy` then performs a binary search over this vector, which is only valid on a sorted slice: [2](#0-1) 

Under async backing / elastic scaling, a collator can pick any relay-parent from the "allowed ancestry" window for each parachain block, and that window can include relay-parents from more than one point at once; consecutive `on_validation_data` invocations (one per parachain block built against a relay-parent) are therefore not guaranteed to observe strictly increasing relay-parent numbers. Feeding the sequence `[10, 12, 11, 13]` produces:

- After 10: `[(10,h10)]`
- After 12: `[(10,h10),(12,h12)]`
- After 11: `[(10,h10),(12,h12),(11,h11)]` — now **unsorted**
- After 13: `[(10,h10),(12,h12),(11,h11),(13,h13)]`

A subsequent `remote_proxy` call anchored at `block = 12` performs `binary_search_by` on this unsorted vector. With `len = 4`, the algorithm probes `mid = 2` → `(11, h11)`, compares `11.cmp(&12) = Less`, so it searches the right half `[(13,h13)]`, compares `13.cmp(&12) = Greater`, and returns `Err`, even though `(12, h12)` is present at index 1 and still within the retention window. The call fails with `Error::UnknownProofAnchorBlock` despite the anchor being legitimately retained.

Existing protections do not prevent this: there is no assertion or reordering step in `on_validation_data` (only a `debug_assert!` on push capacity, which does not catch ordering violations and is compiled out in release builds), and `do_remote_proxy` has no fallback linear search or sortedness check before calling `binary_search_by`.

### Impact Explanation
This causes a liveness/griefing issue: a legitimate remote-proxy authorization that anchors its proof to a still-retained root can spuriously fail with `UnknownProofAnchorBlock`, even though the corresponding `(block, hash)` pair remains in `BlockToRoot`. This affects both `remote_proxy` and `remote_proxy_with_registered_proof`, since both funnel through `do_remote_proxy`. The failure is silent from the caller's perspective (a legitimate proof/anchor combination is rejected) and is queue-accounting-adjacent in the sense that it corrupts the pallet's internal "recently retained roots" bookkeeping, making some retained roots effectively unusable until they age out and are evicted.

### Likelihood Explanation
The precondition is that consecutive relay-parent numbers observed by `on_validation_data` are non-strictly-increasing, which is plausible under async backing / elastic scaling where a parachain can select relay-parents from a window of allowed ancestors rather than being forced to strictly advance on every block. No special privilege is required to trigger the corrupted state (it results from ordinary block production timing); a user only needs to know which historical block their proof anchors to and attempt `remote_proxy`/`remote_proxy_with_registered_proof` against it, and can observe legitimate calls failing depending on the exact ordering that occurred.

### Recommendation
Do not assume input ordering in `on_validation_data`. Either:
1. Maintain `BlockToRoot` sorted by inserting at the correct position (e.g., `roots.binary_search_by(...)` to find insertion point, or skip/replace if `block` is not strictly greater than the last element), or
2. Replace `binary_search_by` in `do_remote_proxy` with a linear `iter().find()`/`position()` lookup that does not depend on sortedness, or
3. Explicitly reject (skip) updates in `on_validation_data` where `block` is not strictly greater than the current last entry, only allowing forward progress, and document/enforce this as a genuine protocol invariant on the relay-parent selection.

### Proof of Concept
Rust unit test (in `pallets/remote-proxy/src/tests.rs` style):
```rust
#[test]
fn non_monotonic_block_sequence_breaks_lookup() {
    // Simulate on_validation_data with block sequence [10, 12, 11, 13]
    for (block, hash) in [(10u32, H::from_low_u64_be(10)),
                          (12, H::from_low_u64_be(12)),
                          (11, H::from_low_u64_be(11)),
                          (13, H::from_low_u64_be(13))] {
        BlockToRoot::<Test>::mutate(|roots| {
            let delete_up_to = block.saturating_sub(MaxStorageRootsToKeep::get());
            while roots.first().is_some_and(|f| f.0 <= delete_up_to) {
                roots.remove(0);
            }
            roots.try_push((block, hash)).unwrap();
        });
    }

    let roots = BlockToRoot::<Test>::get();
    // vector is not sorted ascending
    assert_ne!(roots, {
        let mut sorted = roots.clone();
        sorted.sort_by_key(|(b, _)| *b);
        sorted
    });

    // binary_search fails to find a block that is actually present
    assert!(roots.binary_search_by(|(b, _)| b.cmp(&12)).is_err());
    assert!(roots.iter().any(|(b, _)| *b == 12)); // but it IS present

    // -> remote_proxy anchored at block=12 would incorrectly return
    //    Error::UnknownProofAnchorBlock despite a valid, retained root existing.
}
```
Fuzz/invariant extension: generate arbitrary `block` sequences (including duplicates and out-of-order values) fed to the `on_validation_data` mutate logic, and assert that for every `(block, hash)` still present after eviction, `roots.iter().find(|(b,_)| *b == block)` succeeds while `binary_search_by` may fail — proving `binary_search_by` is not a correctness-preserving equivalent of a linear scan on this data structure once monotonicity is violated.

### Citations

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

**File:** pallets/remote-proxy/src/lib.rs (L405-414)
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
```
