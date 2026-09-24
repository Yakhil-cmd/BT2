No vulnerability found for this question.

The reported bug class is a Solana/Anchor-specific pattern: raw account buffers are deserialized via a generic `unpack_from_slice` function without checking a leading discriminator byte, allowing one account type to be substituted for another type with a similar in-memory layout.

Polkadot SDK's FRAME architecture does not have an analogous attack surface for this specific pattern:
- FRAME storage items are declared with strong Rust types via `#[pallet::storage]` macros (e.g., `StorageMap<_, _, AccountId, BalanceOf<T>>`), and the SCALE codec decodes directly into the declared concrete type rather than through a generic "unpack raw bytes into one of several possible account layouts" function [1](#0-0) .
- There is no mechanism in FRAME extrinsic dispatch where a caller supplies an arbitrary storage-account blob (as in Solana's account model) that then gets deserialized speculatively as one of several possible structs; storage keys and value types are fixed at compile time and enforced by the type system, not by a runtime discriminator check on user-supplied bytes.
- Searches across the codebase for discriminator-less deserialization patterns (`unpack_from_slice`-style generic account decoding) found no equivalent construct; the closest related code (`AccountIdConversion`, opaque keys, `AccountInfo`/`AccountType` in `pallet_revive`) all rely on strongly-typed enums/structs decoded via SCALE `Decode`, which fails deserialization if the encoded discriminant/variant tag doesn't match the expected enum variant, rather than blindly parsing raw bytes into an arbitrary struct shape [2](#0-1) .

Because FRAME's runtime storage and extrinsic argument decoding are strongly typed and validated by SCALE codec's own type-tagged decoding (Rust enums encode a variant discriminant and decoding fails on mismatch), there is no reachable, attacker-controlled analog where account-type confusion via a missing discriminator check could occur through a real extrinsic, contract call, or XCM entry point.

### Citations

**File:** substrate/frame/revive/src/storage.rs (L59-71)
```rust
/// Represents the account information for a contract or an externally owned account (EOA).
#[derive(
	DefaultNoBound, Encode, Decode, CloneNoBound, PartialEq, Eq, Debug, TypeInfo, MaxEncodedLen,
)]
#[scale_info(skip_type_params(T))]
pub struct AccountInfo<T: Config> {
	/// The type of the account.
	pub account_type: AccountType<T>,

	// The  amount that was transferred to this account that is less than the
	// NativeToEthRatio, and can be represented in the native currency
	pub dust: u32,
}
```

**File:** substrate/primitives/runtime/src/traits/mod.rs (L2125-2138)
```rust
	fn try_from_sub_account<S: Decode>(x: &T) -> Option<(Self, S)> {
		x.using_encoded(|d| {
			if d[0..4] != Id::TYPE_ID {
				return None;
			}
			let mut cursor = &d[4..];
			let result = Decode::decode(&mut cursor).ok()?;
			if cursor.iter().all(|x| *x == 0) {
				Some(result)
			} else {
				None
			}
		})
	}
```
