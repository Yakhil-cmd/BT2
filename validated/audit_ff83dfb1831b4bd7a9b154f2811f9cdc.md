No vulnerability found for this question.

The CVE describes a panic in Go's `ParsePKCS1PrivateKey` when validating RSA key well-formedness with missing CRT (Chinese Remainder Theorem) values — a cryptographic key-parsing defect specific to RSA's PKCS#1 key structure.

Polkadot SDK does not use RSA anywhere in its cryptographic primitives or key handling. A search for `rsa::`, `ParsePKCS1PrivateKey`, and related RSA key structures across the codebase returned no matches. The SDK's supported signature schemes are `ed25519`, `sr25519`, `ecdsa` (secp256k1), and `bls12-381`, none of which share RSA's CRT-based key structure or its associated well-formedness pitfalls.

Examining the actual signature/key parsing paths that are reachable from untrusted input:
- `ed25519_verify` in [1](#0-0)  returns `false` on malformed keys/signatures via `Result`/`Option`, never panicking.
- `ecdsa_verify` and `secp256k1_ecdsa_recover*` in [2](#0-1)  propagate `EcdsaVerifyError` on bad `V`/`R`/`S` components rather than panicking.
- CLI-level key/signature parsing in [3](#0-2)  and [4](#0-3)  uses `TryFrom`/`from_slice` with `Result` error handling, not panic-prone parsing.

Additionally, even if a host function were to panic on malformed input, the runtime-interface machinery wraps host function calls in `catch_unwind`, converting panics into `anyhow::Error` rather than crashing the node: [5](#0-4) .

There is no RSA key-parsing code path in the codebase to serve as an analog for this CVE, and the closest analogous cryptographic parsing functions (ed25519/ecdsa/secp256k1 verify and recover) already handle malformed attacker-controlled input via `Result`/`Option` without panicking. No demonstrable Polkadot SDK analog exists for this vulnerability class.

### Citations

**File:** substrate/primitives/io/src/lib.rs (L927-950)
```rust
	fn ed25519_verify(
		sig: PassPointerAndRead<&ed25519::Signature, 64>,
		msg: PassFatPointerAndRead<&[u8]>,
		pub_key: PassPointerAndRead<&ed25519::Public, 32>,
	) -> bool {
		// We don't want to force everyone needing to call the function in an externalities context.
		// So, we assume that we should not use dalek when we are not in externalities context.
		// Otherwise, we check if the extension is present.
		if sp_externalities::with_externalities(|mut e| e.extension::<UseDalekExt>().is_some())
			.unwrap_or_default()
		{
			use ed25519_dalek::Verifier;

			let Ok(public_key) = ed25519_dalek::VerifyingKey::from_bytes(&pub_key.0) else {
				return false;
			};

			let sig = ed25519_dalek::Signature::from_bytes(&sig.0);

			public_key.verify(msg, &sig).is_ok()
		} else {
			ed25519::Pair::verify(sig, msg, pub_key)
		}
	}
```

**File:** substrate/primitives/io/src/lib.rs (L1266-1282)
```rust
	fn secp256k1_ecdsa_recover(
		sig: PassPointerAndRead<&[u8; 65], 65>,
		msg: PassPointerAndRead<&[u8; 32], 32>,
	) -> AllocateAndReturnByCodec<Result<[u8; 64], EcdsaVerifyError>> {
		let rid = libsecp256k1::RecoveryId::parse(
			if sig[64] > 26 { sig[64] - 27 } else { sig[64] } as u8,
		)
		.map_err(|_| EcdsaVerifyError::BadV)?;
		let sig = libsecp256k1::Signature::parse_overflowing_slice(&sig[..64])
			.map_err(|_| EcdsaVerifyError::BadRS)?;
		let msg = libsecp256k1::Message::parse(msg);
		let pubkey =
			libsecp256k1::recover(&msg, &sig, &rid).map_err(|_| EcdsaVerifyError::BadSignature)?;
		let mut res = [0u8; 64];
		res.copy_from_slice(&pubkey.serialize()[1..65]);
		Ok(res)
	}
```

**File:** substrate/client/cli/src/commands/verify.rs (L75-97)
```rust
fn verify<Pair>(sig_data: Vec<u8>, message: Vec<u8>, uri: &str) -> error::Result<()>
where
	Pair: sp_core::Pair,
	Pair::Signature: for<'a> TryFrom<&'a [u8]>,
{
	let signature =
		Pair::Signature::try_from(&sig_data).map_err(|_| error::Error::SignatureFormatInvalid)?;

	let pubkey = if let Ok(pubkey_vec) = array_bytes::hex2bytes(uri) {
		Pair::Public::from_slice(pubkey_vec.as_slice())
			.map_err(|_| error::Error::KeyFormatInvalid)?
	} else {
		Pair::Public::from_string(uri)?
	};

	if Pair::verify(&signature, &message, &pubkey) {
		println!("Signature verifies correctly.");
	} else {
		return Err(error::Error::SignatureInvalid);
	}

	Ok(())
}
```

**File:** substrate/client/cli/src/commands/utils.rs (L196-211)
```rust
/// Try to parse given `public` as hex encoded public key and print relevant information.
pub fn print_from_public<Pair>(
	public_str: &str,
	network_override: Option<Ss58AddressFormat>,
	output: OutputType,
) -> Result<(), Error>
where
	Pair: sp_core::Pair,
	Pair::Public: Into<MultiSigner>,
{
	let public = array_bytes::hex2bytes(public_str)?;

	let public_key = Pair::Public::try_from(&public)
		.map_err(|_| "Failed to construct public key from given hex")?;

	let network_override = unwrap_or_default_ss58_version(network_override);
```

**File:** substrate/primitives/runtime-interface/proc-macro/src/runtime_interface/host_function_interface.rs (L411-430)
```rust
				T::with_function_context(caller, move |__function_context__| {
					let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
						#struct_name::call(
							__function_context__,
							#(#ffi_names,)*
						).map_err(#crate_::sp_wasm_interface::anyhow::Error::msg)
					}));
					match result {
						Ok(result) => result,
						Err(panic) => {
							let message =
								if let Some(message) = panic.downcast_ref::<#crate_::alloc::string::String>() {
									#crate_::alloc::format!("host code panicked while being called by the runtime: {}", message)
								} else if let Some(message) = panic.downcast_ref::<&'static str>() {
									#crate_::alloc::format!("host code panicked while being called by the runtime: {}", message)
								} else {
									#crate_::alloc::borrow::ToOwned::to_owned("host code panicked while being called by the runtime")
								};
							return Err(#crate_::sp_wasm_interface::anyhow::Error::msg(message));
						}
```
