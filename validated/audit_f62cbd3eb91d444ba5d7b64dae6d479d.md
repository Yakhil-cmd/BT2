No vulnerability found for this question.

The reported issue is a Solidity-specific typo: a missing closing parenthesis in a hand-written EIP-712 type string (`"OrderRequest(bytes32 salt,...uint256 quantityIn"`) that silently produces a different `keccak256` hash than intended, corrupting order IDs.

I searched the Polkadot SDK codebase for any analogous manually-constructed type/domain hash strings used to derive an EIP-712-style digest, since that's the only place this class of bug could recur. The one place in this codebase that implements EIP-712 hashing is the new `pallet-assets-precompiles` permit module: [1](#0-0) 

Both `DOMAIN_TYPEHASH` (`"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"`) and `PERMIT_TYPEHASH` (`"Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"`) have correctly balanced parentheses matching the canonical EIP-712/EIP-2612 specifications, and are computed at compile time via `const_crypto::sha3::Keccak256`, with an explicit comment noting this approach "eliminat[es] any risk of a copy-paste error in a hand-written byte array" [2](#0-1) . The domain separator and struct hash computation correctly consume these typehash constants [3](#0-2) , and there is test coverage validating determinism and differentiation of the resulting separators [4](#0-3) .

I found no other hand-written type-hash or ABI-encoding string constant anywhere else in the codebase (bridges lane hashing, HOP signing contexts, storage hashers, etc. all use structured `Encode`/`SCALE` derivation rather than manually-typed strings) that would be susceptible to the same "missing bracket" class of bug [5](#0-4) [6](#0-5) . Since no reachable, attacker-triggerable analog of this specific bug class exists, there is nothing to report.

### Citations

**File:** substrate/frame/assets/precompiles/src/permit.rs (L40-53)
```rust
/// EIP-712 type hash for the domain separator.
/// keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
pub(crate) const DOMAIN_TYPEHASH: [u8; 32] = const_crypto::sha3::Keccak256::new()
	.update(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
	.finalize();

/// EIP-712 type hash for Permit.
/// keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)")
///
/// Computed at compile time from the canonical string, eliminating any risk of a
/// copy-paste error in a hand-written byte array.
pub(crate) const PERMIT_TYPEHASH: [u8; 32] = const_crypto::sha3::Keccak256::new()
	.update(b"Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)")
	.finalize();
```

**File:** substrate/frame/assets/precompiles/src/permit.rs (L160-213)
```rust
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
		}

		/// Compute the EIP-712 struct hash for a permit.
		///
		/// structHash = keccak256(abi.encode(
		///   PERMIT_TYPEHASH,
		///   owner,
		///   spender,
		///   value,
		///   nonce,
		///   deadline
		/// ))
		pub fn permit_struct_hash(
			owner: &H160,
			spender: &H160,
			value: &[u8; 32], // U256 as bytes (big-endian)
			nonce: &U256,
			deadline: &[u8; 32], // U256 as bytes (big-endian)
		) -> H256 {
			let mut data = Vec::with_capacity(PERMIT_STRUCT_ENCODED_LEN);
			data.extend_from_slice(&PERMIT_TYPEHASH);
			// owner (padded to 32 bytes)
			data.extend_from_slice(&[0u8; 12]);
			data.extend_from_slice(owner.as_bytes());
			// spender (padded to 32 bytes)
			data.extend_from_slice(&[0u8; 12]);
			data.extend_from_slice(spender.as_bytes());
			// value (already 32 bytes)
			data.extend_from_slice(value);
			// nonce (convert U256 to 32 bytes big-endian)
			data.extend_from_slice(&nonce.to_big_endian());
			// deadline (already 32 bytes)
			data.extend_from_slice(deadline);

			H256(keccak_256(&data))
		}
```

**File:** substrate/frame/assets/precompiles/src/permit_tests.rs (L182-209)
```rust
#[test]
fn domain_separator_is_deterministic() {
	new_test_ext().execute_with(|| {
		let verifying_contract = test_verifying_contract();
		let name = test_token_name();
		let separator1 =
			permit::Pallet::<Test>::compute_domain_separator(&verifying_contract, name);
		let separator2 =
			permit::Pallet::<Test>::compute_domain_separator(&verifying_contract, name);
		// Should return the same value for same inputs
		assert_eq!(separator1, separator2);
	});
}

#[test]
fn domain_separators_differ_per_verifying_contract() {
	new_test_ext().execute_with(|| {
		let contract_1 = H160::from_low_u64_be(0x1111);
		let contract_2 = H160::from_low_u64_be(0x2222);
		let name = test_token_name();

		let separator1 = permit::Pallet::<Test>::compute_domain_separator(&contract_1, name);
		let separator2 = permit::Pallet::<Test>::compute_domain_separator(&contract_2, name);

		// Domain separators should be different for different verifying contracts
		assert_ne!(separator1, separator2);
	});
}
```

**File:** bridges/primitives/messages/src/lane.rs (L172-187)
```rust
impl LaneIdType for HashedLaneId {
	/// Create lane identifier from two locations.
	fn try_new<T: Ord + Encode>(endpoint1: T, endpoint2: T) -> Result<Self, ()> {
		const VALUES_SEPARATOR: [u8; 31] = *b"bridges-lane-id-value-separator";

		Ok(Self(
			if endpoint1 < endpoint2 {
				(endpoint1, VALUES_SEPARATOR, endpoint2)
			} else {
				(endpoint2, VALUES_SEPARATOR, endpoint1)
			}
			.using_encoded(blake2_256)
			.into(),
		))
	}
}
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
