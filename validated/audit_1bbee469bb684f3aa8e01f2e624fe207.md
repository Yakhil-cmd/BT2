### Title
Missing G2 subgroup check on attacker-supplied BLS sync-committee signature before pairing in `fast_aggregate_verify` - (File: bridges/snowbridge/primitives/beacon/src/bls.rs)

### Summary
The Snowbridge Ethereum light client verifies sync-committee updates using `fast_aggregate_verify`, which deserializes the raw `sync_committee_signature` bytes from the extrinsic payload directly into a G2 point via `milagro_bls::Signature::from_bytes` and feeds it straight into a pairing check, without any explicit prime-order-subgroup validation of that G2 point in this codebase's wrapper code. This mirrors the reported `zksync-crypto` `pairing_certificate.rs` bug class: a G2 point used in a pairing operation without confirming `[r]P = O`.

### Finding Description
`prepare_aggregate_signature` deserializes the attacker-supplied signature bytes and hands the resulting G2 point to the pairing-based verification routine: [1](#0-0) 

This is reached from the public, signed extrinsic `submit`/`submit_with_sync_committee` -> `verify_update` -> `fast_aggregate_verify`, where `update.sync_aggregate.sync_committee_signature` comes straight from the caller's payload with no merkle-proof or other binding to trusted beacon-chain state: [2](#0-1) [3](#0-2) 

This is materially different from the *public keys*, whose G1-subgroup membership is guaranteed by the honest Ethereum beacon chain and additionally bound to on-chain state through a merkle proof — and which the maintainers explicitly hardened with an extra subgroup check as defense-in-depth: [4](#0-3) 

The signature, however, is never merkle-proof-bound; it is a fresh value chosen by whoever submits the extrinsic every time, and the codebase's own `bls.rs` wrapper performs no `is_in_correct_subgroup_assuming_on_curve()`-style check on the deserialized G2 point before it is used in `fast_aggregate_verify_pre_aggregated`'s pairing computation: [5](#0-4) 

Whether `milagro_bls::Signature::from_bytes` itself performs a subgroup check internally is a property of the external `milagro-bls` crate, which is not vendored/indexed in this repository, so I could not directly confirm from the code available whether the dependency enforces the check. The BLS RFC (draft-irtf-cfrg-bls-signature) requires `signature_subgroup_check` as part of `CoreVerify`/`FastAggregateVerify`, but this repository's own wrapper code shows no explicit enforcement, and the maintainers' hardening effort (PR 11910) covered only the G1 public key path, not the G2 signature path.

### Impact Explanation
If the underlying deserialization does not enforce G2 subgroup membership, an attacker who submits a specially crafted `sync_committee_signature` — an on-curve but non-prime-order-subgroup G2 point — could exploit small-subgroup/invalid-curve style pairing confusion to get `fast_aggregate_verify_pre_aggregated` to return true without possessing the sync committee's private keys. Because `verify_update` gates whether a `Update` (finalized header, next sync committee) is accepted into `FinalizedBeaconState`/`NextSyncCommittee` storage, a successful forgery would let an attacker inject arbitrary finalized Ethereum state into the Snowbridge light client — the root of trust for the entire Ethereum-to-Polkadot bridge, enabling downstream message/asset forgery. This would be a Critical-severity unauthorized-dispatch/integrity break if confirmed.

### Likelihood Explanation
Reachability is clean: `submit` requires only `ensure_signed` (any signed account, no privilege), and the signature bytes are attacker-controlled input with no merkle-proof binding, unlike the public keys. The actual exploitability, however, hinges entirely on an external, non-vendored dependency (`milagro-bls`)'s internal deserialization behavior, which I could not verify from the indexed code. Given that Snowfork/Parity already invested in hardening the analogous G1 pubkey path, and this exact G2/pairing subgroup-check gap is the one this report class targets, this needs confirmation against the actual `milagro-bls` crate source/version pinned in `Cargo.lock` (not present in the index) before treating it as anything beyond a "needs verification" finding.

### Recommendation
Explicitly validate that the deserialized signature G2 point lies in the correct prime-order subgroup (and is on-curve) in `prepare_aggregate_signature` before it is used in any pairing, mirroring the subgroup-check hardening already applied to public keys in PR 11910, rather than relying implicitly on the `milagro-bls` dependency's internal behavior.

### Proof of Concept
Not executed. Confirming exploitability requires inspecting the exact `milagro-bls` crate version pinned for this workspace (not resolvable from this index — `Cargo.lock` entry for `milagro-bls` was not found) to determine whether `Signature::from_bytes` performs a subgroup check, and, if not, constructing a non-subgroup G2 point encoded per that crate's compressed format and submitting it via `EthereumBeaconClient::submit` in the pallet's existing test harness (`bridges/snowbridge/pallets/ethereum-client/src/tests.rs`) to observe whether `fast_aggregate_verify` incorrectly returns `Ok`. This step could not be completed within the scope of static code search; a background engineering session with dependency-source access would be needed to finish the PoC.

### Citations

**File:** bridges/snowbridge/primitives/beacon/src/bls.rs (L71-89)
```rust
/// Prepare for G2 AggregateSignature, normally more expensive than G1 operation.
pub fn prepare_aggregate_signature(signature: &Signature) -> Result<AggregateSignature, BlsError> {
	Ok(AggregateSignature::from_signature(
		&SignaturePrepared::from_bytes(&signature.0).map_err(|_| BlsError::InvalidSignature)?,
	))
}

/// fast_aggregate_verify_pre_aggregated which is the most expensive call in beacon light client.
pub fn fast_aggregate_verify_pre_aggregated(
	agg_sig: AggregateSignature,
	aggregate_key: AggregatePublicKey,
	message: H256,
) -> Result<(), BlsError> {
	ensure!(
		agg_sig.fast_aggregate_verify_pre_aggregated(&message[..], &aggregate_key),
		BlsError::SignatureVerificationFailed
	);
	Ok(())
}
```

**File:** bridges/snowbridge/pallets/ethereum-client/src/lib.rs (L217-224)
```rust
		#[transactional]
		/// Submits a new finalized beacon header update. The update may contain the next
		/// sync committee.
		pub fn submit(origin: OriginFor<T>, update: Box<Update>) -> DispatchResultWithPostInfo {
			ensure_signed(origin)?;
			ensure!(!Self::operating_mode().is_halted(), Error::<T>::Halted);
			Self::process_update(&update)
		}
```

**File:** bridges/snowbridge/pallets/ethereum-client/src/lib.rs (L436-458)
```rust
			// Verify sync committee aggregate signature.
			let sync_committee = if signature_period == store_period {
				<CurrentSyncCommittee<T>>::get()
			} else {
				<NextSyncCommittee<T>>::get()
			};
			let absent_pubkeys =
				Self::find_pubkeys(&participation, (*sync_committee.pubkeys).as_ref(), false);
			let signing_root = Self::signing_root(
				&update.attested_header,
				Self::validators_root(),
				update.signature_slot,
			)?;
			// Improvement here per <https://eth2book.info/capella/part2/building_blocks/signatures/#sync-aggregates>
			// suggested start from the full set aggregate_pubkey then subtracting the absolute
			// minority that did not participate.
			fast_aggregate_verify(
				&sync_committee.aggregate_pubkey,
				&absent_pubkeys,
				signing_root,
				&update.sync_aggregate.sync_committee_signature,
			)
			.map_err(|e| Error::<T>::BLSVerificationFailed(e))?;
```

**File:** prdoc/pr_11910.prdoc (L34-40)
```text
      ### snowbridge: harden BLS public key deserialization
      
      Defense-in-depth: validate all cryptographic inputs.
      
      The Merkle proof binding means the public keys must match exactly what the Ethereum beacon chain committed. Since the beacon chain itself enforces G1 subgroup membership for validator keys, invalid subgroup points cannot appear in honest beacon chain state.
      An attacker would need to compromise the Merkle proof verification (e.g., via a SHA-256 collision or another bug in the verification chain) to inject a public key that is on the BLS12-381 curve but not in the G1 subgroup.
      The performance cost of the subgroup check is a one-time cost during sync committee preparation (512 checks per sync committee period, approximately every 27 hours). This is negligible compared to the BLS signature verification that occurs on every update. So just check it as defense-in-depth.
```
