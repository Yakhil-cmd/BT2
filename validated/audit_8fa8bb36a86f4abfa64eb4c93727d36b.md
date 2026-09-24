No vulnerability found for this question.

Investigation notes: the external report's bug class is "sensitive credential (access token) unintentionally included in a JSON API response due to a struct field lacking `json:"-"`, letting a privileged-but-lower-tier user impersonate root." Searching for an analog in `polkadot-sdk` means looking for a case where a secret (session key seed, keystore private key, signing material) is exposed through a response object that should have redacted it, and reachable by a normal, unprivileged actor through a signed extrinsic, contract call, or XCM message — not through node-operator RPC configuration.

The closest surface area is the `author` RPC namespace, where `GeneratedSessionKeys` is the serializable response struct returned by `author_rotateKeys`/`author_rotateKeysWithOwner`, containing only `keys: Bytes` and `proof: Option<Bytes>` — both intentionally public material, not private key bytes. [1](#0-0) 
All methods that could touch keystore secrets (`insert_key`, `rotate_keys`, `rotate_keys_with_owner`, `has_session_keys`, `has_key`) are gated by `check_if_safe(ext)` before executing, which is the node's "unsafe RPC method" policy enforced at the transport layer, not something an on-chain extrinsic sender can influence. [2](#0-1) 
Private key material itself (e.g., `ed25519::SecretKey`) implements a custom `Debug` that never prints the bytes, and is zeroized on parse. [3](#0-2) 

This does not satisfy the required threat model: the report requires a genuine user-entry point (signed extrinsic, enabled contract call, or permitted XCM message) reachable by an attacker with no privileged role, and a demonstrable serialization/authorization defect causing credential leakage and privilege escalation. The RPC keystore/session-key surface is gated by node-operator RPC-safety configuration (an operational/deployment control, not an extrinsic-level authorization check), and the actual secret material is never serialized into any API/extrinsic response in the reviewed code paths. No FRAME pallet, XCM executor, or bridge code path was found where a secret credential analogous to an "access token" (e.g., raw private/session keys, keystore secrets) is serialized into a response reachable by an ordinary signed extrinsic, contract call, or XCM message. Without such a concrete, extrinsic-reachable path, there is no demonstrable analog per the required methodology.

### Citations

**File:** substrate/client/rpc-api/src/author/mod.rs (L29-41)
```rust
/// Output of [`AuthorApiServer::rotate_keys_with_owner`].
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct GeneratedSessionKeys {
	/// The public session keys for registering them on chain.
	pub keys: Bytes,

	/// The `proof` for verifying ownership of the generated session keys.
	///
	/// This will be `None` iff the chain doesn't support generating the `proof`.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[serde(default)]
	pub proof: Option<Bytes>,
}
```

**File:** substrate/client/rpc/src/author/mod.rs (L138-168)
```rust
	fn insert_key(
		&self,
		ext: &Extensions,
		key_type: String,
		suri: String,
		public: Bytes,
	) -> Result<()> {
		check_if_safe(ext)?;

		let key_type = key_type.as_str().try_into().map_err(|_| Error::BadKeyType)?;
		self.keystore
			.insert(key_type, &suri, &public[..])
			.map_err(|_| Error::KeystoreUnavailable)?;
		Ok(())
	}

	fn rotate_keys(&self, ext: &Extensions) -> Result<Bytes> {
		check_if_safe(ext)?;

		self.rotate_keys_impl(Vec::new()).map(|k| k.keys)
	}

	fn rotate_keys_with_owner(
		&self,
		ext: &Extensions,
		owner: Bytes,
	) -> Result<GeneratedSessionKeys> {
		check_if_safe(ext)?;

		self.rotate_keys_impl(owner.0)
	}
```

**File:** substrate/client/network/types/src/ed25519.rs (L231-253)
```rust
impl fmt::Debug for SecretKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "SecretKey")
	}
}

impl SecretKey {
	/// Generate a new Ed25519 secret key.
	pub fn generate() -> SecretKey {
		let signing = ed25519::SigningKey::generate(&mut rand::rngs::OsRng);
		SecretKey(signing.to_bytes())
	}

	/// Try to parse an Ed25519 secret key from a byte slice
	/// containing the actual key, zeroing the input on success.
	/// If the bytes do not constitute a valid Ed25519 secret key, an error is
	/// returned.
	pub fn try_from_bytes(mut sk_bytes: impl AsMut<[u8]>) -> Result<SecretKey, DecodingError> {
		let sk_bytes = sk_bytes.as_mut();
		let secret = <[u8; 32]>::try_from(&*sk_bytes)
			.map_err(|e| DecodingError::SecretKeyParseError(Box::new(e)))?;
		sk_bytes.zeroize();
		Ok(SecretKey(secret))
```
