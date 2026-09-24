No vulnerability found for this question.

The reported CVE (phpfm 1.7.9) is rooted in PHP's loose (`==`) comparison semantics, where strings like `"0e123456"` are coerced to floating-point `0` and compared equal to other magic-hash strings, allowing authentication bypass. This is a language-specific weak-typing defect with no structural analog in polkadot-sdk's Rust codebase, since Rust has no implicit type coercion between strings/numbers and all authentication-relevant comparisons in this repo are either:

- Strict, statically-typed equality on fixed-size byte arrays/hashes (e.g. `CheckEqual` for `H256` at [1](#0-0) ), which cannot be influenced by string-to-number coercion tricks.
- Real cryptographic signature verification through `sp_io::crypto::*` (`ed25519_verify`, `sr25519_verify`, `ecdsa_verify`) as seen in `Verify` impls for `ed25519::Signature`, `sr25519::Signature`, and `ecdsa::Signature` at [2](#0-1) , which perform actual elliptic-curve verification rather than any loosely-typed value comparison.
- Explicit byte-level `try_from`/decode steps (e.g. `ed25519::Pair::verify` at [3](#0-2) ) that fail closed on malformed input instead of coercing it.

I searched for any authentication-adjacent code using loose/coerced equality (hash comparisons, signature checks, username/proof validation in `pallet-identity`, `pallet-recovery`, `frame-verify-signature`, BABE equivocation proofs, statement-store proofs) and found only strongly-typed, fixed-width comparisons or genuine cryptographic verification — none exhibit a PHP-style type-juggling class of bypass. Given Rust's static typing and the absence of any dynamic/loose comparison primitive in the authentication paths inspected, there is no demonstrable analog to the reported CVE in this codebase.

### Citations

**File:** substrate/primitives/runtime/src/traits/mod.rs (L135-164)
```rust
impl Verify for sp_core::ed25519::Signature {
	type Signer = sp_core::ed25519::Public;

	fn verify<L: Lazy<[u8]>>(&self, mut msg: L, signer: &sp_core::ed25519::Public) -> bool {
		sp_io::crypto::ed25519_verify(self, msg.get(), signer)
	}
}

impl Verify for sp_core::sr25519::Signature {
	type Signer = sp_core::sr25519::Public;

	fn verify<L: Lazy<[u8]>>(&self, mut msg: L, signer: &sp_core::sr25519::Public) -> bool {
		sp_io::crypto::sr25519_verify(self, msg.get(), signer)
	}
}

impl Verify for sp_core::ecdsa::Signature {
	type Signer = sp_core::ecdsa::Public;
	fn verify<L: Lazy<[u8]>>(&self, mut msg: L, signer: &sp_core::ecdsa::Public) -> bool {
		if !sp_core::ecdsa::is_signature_normalized(self.as_ref()) {
			return false;
		}
		match sp_io::crypto::secp256k1_ecdsa_recover_compressed(
			self.as_ref(),
			&sp_io::hashing::blake2_256(msg.get()),
		) {
			Ok(pubkey) => signer.0 == pubkey,
			_ => false,
		}
	}
```

**File:** substrate/primitives/runtime/src/traits/mod.rs (L1126-1137)
```rust
impl CheckEqual for sp_core::H256 {
	#[cfg(feature = "std")]
	fn check_equal(&self, other: &Self) {
		use sp_core::hexdisplay::HexDisplay;
		if self != other {
			println!(
				"Hash: given={}, expected={}",
				HexDisplay::from(self.as_fixed_bytes()),
				HexDisplay::from(other.as_fixed_bytes()),
			);
		}
	}
```

**File:** substrate/primitives/core/src/ed25519.rs (L115-124)
```rust
	/// Verify a signature on a message.
	///
	/// Returns true if the signature is good.
	fn verify<M: AsRef<[u8]>>(sig: &Signature, message: M, public: &Public) -> bool {
		let Ok(public) = VerificationKey::try_from(public.as_slice()) else { return false };
		let Ok(signature) = ed25519_zebra::Signature::try_from(sig.as_slice()) else {
			return false;
		};
		public.verify(&signature, message.as_ref()).is_ok()
	}
```
