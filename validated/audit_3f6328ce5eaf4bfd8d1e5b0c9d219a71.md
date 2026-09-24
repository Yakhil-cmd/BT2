[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** substrate/frame/verify-signature/src/extension.rs (L138-154)
```rust
		// Construct the payload that the signature will be validated against. The inherited
		// implication contains the encoded bytes of the call and all of the extension data of the
		// extensions that follow in the `TransactionExtension` pipeline.
		//
		// In other words:
		// - extensions that precede this extension are ignored in terms of signature validation;
		// - extensions that follow this extension are included in the payload to be signed (as if
		//   they were the entire `SignedExtension` pipeline in the traditional signed transaction
		//   model).
		//
		// The encoded bytes of the payload are then hashed using `blake2_256`.
		let msg = inherited_implication.using_encoded(blake2_256);

		// The extension was enabled, so the signature must match.
		if !signature.verify(&msg[..], account) {
			Err(InvalidTransaction::BadProof)?
		}
```

**File:** cumulus/parachains/runtimes/collectives/collectives-westend/src/lib.rs (L705-715)
```rust
pub type MetaTxExtension = (
	pallet_verify_signature::VerifySignature<Runtime>,
	pallet_meta_tx::MetaTxMarker<Runtime>,
	frame_system::CheckNonZeroSender<Runtime>,
	frame_system::CheckSpecVersion<Runtime>,
	frame_system::CheckTxVersion<Runtime>,
	frame_system::CheckGenesis<Runtime>,
	frame_system::CheckEra<Runtime>,
	frame_system::CheckNonce<Runtime>,
	frame_metadata_hash_extension::CheckMetadataHash<Runtime>,
);
```

**File:** substrate/frame/meta-tx/src/tests.rs (L60-68)
```rust
fn create_signature<Call: Encode, Ext: Encode + TransactionExtension<RuntimeCall>>(
	call: Call,
	ext: Ext,
	signer: Sr25519Keyring,
) -> MultiSignature {
	MultiSignature::Sr25519(
		(META_EXTENSION_VERSION, call, ext.clone(), ext.implicit().unwrap())
			.using_encoded(|e| signer.sign(&blake2_256(e))),
	)
```

**File:** substrate/frame/assets/precompiles/src/permit.rs (L148-177)
```rust
		/// Compute the EIP-712 domain separator for a given verifying contract.
		///
		/// DOMAIN_SEPARATOR = keccak256(abi.encode(
		///   keccak256("EIP712Domain(string name,string version,uint256 chainId,address
		/// verifyingContract)"),
		///   keccak256(name),
		///   keccak256("1"),
		///   chainId,
		///   verifyingContract
		/// ))
		///
		/// The `name` parameter should be the token name per EIP-2612 specification.
		pub fn compute_domain_separator(verifying_contract: &H160, name: &[u8]) -> H256 {
			let name_hash = keccak_256(name);
			let version_hash = keccak_256(b"1");
			let chain_id = T::ChainId::get();

			// Encode: typehash || name_hash || version_hash || chainId || verifyingContract
			let mut data = Vec::with_capacity(DOMAIN_SEPARATOR_ENCODED_LEN);
			data.extend_from_slice(&DOMAIN_TYPEHASH);
			data.extend_from_slice(&name_hash);
			data.extend_from_slice(&version_hash);
			// Pad chain_id to 32 bytes (big-endian)
			data.extend_from_slice(&[0u8; 24]);
			data.extend_from_slice(&chain_id.to_be_bytes());
			// Pad address to 32 bytes
			data.extend_from_slice(&[0u8; 12]);
			data.extend_from_slice(verifying_contract.as_bytes());

			H256(keccak_256(&data))
```

**File:** substrate/frame/assets/precompiles/src/permit_precompile_tests.rs (L837-875)
```rust
/// A signature for asset A must NOT be replayable against asset B —
/// pins the `verifyingContract` field of the EIP-712 domain. We register
/// the same underlying asset under both prefixes, sign for one, submit
/// to the other; both directions are tested.
#[test_case(PRECOMPILE_ADDRESS_PREFIX, PRECOMPILE_ADDRESS_PREFIX_FOREIGN)]
#[test_case(PRECOMPILE_ADDRESS_PREFIX_FOREIGN, PRECOMPILE_ADDRESS_PREFIX)]
fn permit_signature_bound_to_verifying_contract(sign_prefix: u16, submit_prefix: u16) {
	new_test_ext().execute_with(|| {
		let setup = permit_setup(sign_prefix);
		if sign_prefix != PRECOMPILE_ADDRESS_PREFIX_FOREIGN &&
			submit_prefix == PRECOMPILE_ADDRESS_PREFIX_FOREIGN
		{
			crate::pallet::Pallet::<Test>::insert_asset_mapping(&setup.asset_id)
				.expect("foreign asset mapping must insert");
		}

		let asset_addr_signed = setup.asset_addr;
		let asset_addr_submitted = H160::from(set_prefix_in_address(submit_prefix));
		assert_ne!(asset_addr_signed, asset_addr_submitted);

		let (v, r, s) = sign_permit(
			asset_addr_signed,
			setup.spender_addr,
			AlloyU256::from(100),
			setup.deadline,
		);

		let result = raw_permit(
			setup.submitter,
			asset_addr_submitted,
			HARDHAT_ACCOUNT_0,
			setup.spender_addr,
			AlloyU256::from(100),
			setup.deadline,
			v,
			r,
			s,
		);
		assert_permit_reverted_with(result, "Signer does not match owner");
```

**File:** substrate/client/hop/src/types.rs (L303-320)
```rust
/// Domain-separator prefix for `hop_submit` signatures.
pub const HOP_SUBMIT_CONTEXT: &[u8] = b"hop-submit-v1:";

/// Domain-separator prefix for `hop_claim` signatures.
pub const HOP_CLAIM_CONTEXT: &[u8] = b"hop-claim-v1:";

/// Domain-separator prefix for `hop_ack` signatures.
pub const HOP_ACK_CONTEXT: &[u8] = b"hop-ack-v1:";

/// Compute the 32-byte payload that HOP recipients / submitters sign for a given
/// operation. This is `blake2_256(context || hash)` and ensures signatures from
/// one operation cannot be replayed in another.
pub fn signing_payload(context: &[u8], hash: &HopHash) -> [u8; 32] {
	let mut buf = Vec::with_capacity(context.len() + 32);
	buf.extend_from_slice(context);
	buf.extend_from_slice(hash.as_bytes());
	blake2_256(&buf)
}
```

**File:** substrate/client/hop/src/pool.rs (L862-881)
```rust
	/// Decode `signature` and return the index of the matching recipient in
	/// `meta.recipients`. `context` is the operation's domain separator (claim
	/// / ack). Returning an index keeps a single implementation for both
	/// shared- and exclusive-borrow callers (`meta.recipients[idx]` works in
	/// either case).
	fn find_recipient_idx(
		meta: &HopEntryMeta,
		hash: &HopHash,
		signature: &[u8],
		context: &[u8],
	) -> Result<usize, HopError> {
		let multi_sig =
			MultiSignature::decode(&mut &signature[..]).map_err(|_| HopError::InvalidSignature)?;
		let payload = signing_payload(context, hash);

		meta.recipients
			.iter()
			.position(|r| multi_sig.verify(&payload[..], &r.signer.clone().into_account()))
			.ok_or(HopError::NotRecipient)
	}
```
