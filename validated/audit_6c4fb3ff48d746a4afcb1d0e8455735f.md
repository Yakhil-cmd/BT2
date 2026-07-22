### Title
Production Sequencer Signs Consensus Precommit Votes and Peer Identity Challenges with a Publicly Known Hardcoded Private Key - (File: crates/apollo_signature_manager/src/lib.rs)

---

### Summary

The production Apollo sequencer node unconditionally instantiates its `SignatureManager` using `LocalKeyStore::new_for_testing()`, which embeds a hardcoded ECDSA private key (`0x608bf2cdb1ad4138e72d2f82b8c5db9fa182d1883868ae582ed373429b7a133`) directly in the source code. This key is used to sign consensus precommit votes and peer-identity challenges. Because the key is publicly visible in the repository, any party can forge valid signatures for any block hash or peer-identity challenge, impersonating the sequencer node in consensus and on the P2P network.

---

### Finding Description

**Hardcoded key in `LocalKeyStore::new_for_testing()`**

`LocalKeyStore::new_for_testing()` is defined in `crates/apollo_signature_manager/src/signature_manager.rs` and embeds a fixed private key:

```rust
pub(crate) const fn new_for_testing() -> Self {
    // Created using `cairo-lang`.
    const PRIVATE_KEY: PrivateKey = PrivateKey(Felt::from_hex_unchecked(
        "0x608bf2cdb1ad4138e72d2f82b8c5db9fa182d1883868ae582ed373429b7a133",
    ));
    const PUBLIC_KEY: PublicKey = PublicKey(Felt::from_hex_unchecked(
        "0x125d56b1fbba593f1dd215b7c55e384acd838cad549c4a2b9c6d32d264f4e2a",
    ));
    Self { private_key: PRIVATE_KEY, public_key: PUBLIC_KEY }
}
``` [1](#0-0) 

**Production factory function calls the testing constructor unconditionally**

`crates/apollo_signature_manager/src/lib.rs` defines `LocalKeyStoreSignatureManager::new()` — the production constructor — by calling `LocalKeyStore::new_for_testing()`. This call is **not** gated by `#[cfg(test)]` or any feature flag. The public alias `SignatureManager` and the exported `create_signature_manager()` both resolve to this path:

```rust
impl LocalKeyStoreSignatureManager {
    pub fn new() -> Self {
        Self(GenericSignatureManager::new(LocalKeyStore::new_for_testing()))
    }
}
// ...
pub use LocalKeyStoreSignatureManager as SignatureManager;

// TODO(Elin): understand how key store would look in production and better define the way the
// signature manager is created.
pub fn create_signature_manager() -> SignatureManager {
    SignatureManager::new()
}
``` [2](#0-1) 

The TODO comment on line 39 explicitly acknowledges that the production key-management story is unresolved.

**Node startup wires the hardcoded key into the live consensus path**

`crates/apollo_node/src/components.rs` calls `create_signature_manager()` during production node startup for any local execution mode:

```rust
let signature_manager = match config.components.signature_manager.execution_mode {
    ReactiveComponentExecutionMode::LocalExecutionWithRemoteDisabled
    | ReactiveComponentExecutionMode::LocalExecutionWithRemoteEnabled => {
        Some(create_signature_manager())
    }
    ...
};
``` [3](#0-2) 

**What the key signs**

The `SignatureManager` exposes two signing operations, both of which use the hardcoded key:

- `sign_precommit_vote(block_hash)` — produces the ECDSA signature attached to every consensus precommit vote broadcast over the P2P network.
- `sign_identification(peer_id, challenge)` — produces the ECDSA signature used to authenticate the node's identity during peer handshakes. [4](#0-3) 

The `_new(private_key: PrivateKey)` constructor that would accept a caller-supplied key exists but is dead code (prefixed with `_` and never called outside the file). [5](#0-4) 

---

### Impact Explanation

Because the private key is embedded in a public repository, any observer can:

1. **Forge consensus precommit vote signatures** for arbitrary block hashes. A forged precommit bearing the sequencer's known public key (`0x125d56b1fbba593f1dd215b7c55e384acd838cad549c4a2b9c6d32d264f4e2a`) is indistinguishable from a legitimate one. If the sequencer's vote weight is sufficient to influence quorum, an attacker can cast fraudulent votes for any block, directly affecting which block gets finalized.

2. **Forge peer-identity signatures**, allowing an attacker to impersonate the sequencer node during P2P handshakes, disrupting network topology and potentially enabling man-in-the-middle attacks on consensus messages.

This matches the allowed impact: **High — Transaction conversion or signature/hash logic binds the wrong signer, hash, type, or executable payload.**

---

### Likelihood Explanation

- The private key is in plain text in a public source file, requiring zero privilege to obtain.
- The production code path is unconditional — no configuration flag disables the hardcoded key.
- The `sign_precommit_vote` and `sign_identification` operations are exercised on every consensus round and every peer connection, so the key is actively used in production.

---

### Recommendation

1. **Remove the hardcoded key from production code.** The `LocalKeyStore::new_for_testing()` constructor must be gated with `#[cfg(any(feature = "testing", test))]` and must never be reachable from `create_signature_manager()`.

2. **Implement a proper production `KeyStore`.** The `_new(private_key)` constructor already exists; wire it to a key loaded from a secrets manager, an HSM, or an environment-injected secret at startup — consistent with the project's existing `SecretsConfigOverride` infrastructure.

3. **Rotate the exposed key.** Treat `0x608bf2cdb1ad4138e72d2f82b8c5db9fa182d1883868ae582ed373429b7a133` as compromised and replace it with a freshly generated key in any environment where it has been used.

---

### Proof of Concept

```
# 1. Read the private key from the public repository:
PRIVATE_KEY=0x608bf2cdb1ad4138e72d2f82b8c5db9fa182d1883868ae582ed373429b7a133

# 2. Compute the precommit-vote message digest for any target block hash
#    using the same blake2s domain-separation scheme as build_precommit_vote_message_digest():
#    message = b"PRECOMMIT_VOTE" || block_hash_bytes_be
#    digest  = blake2s_to_felt(message)

# 3. Sign the digest with the known private key using starknet ECDSA:
#    signature = ecdsa_sign(PRIVATE_KEY, digest)

# 4. The resulting (r, s) pair is a valid precommit vote signature for the
#    chosen block hash, verifiable against the sequencer's public key
#    0x125d56b1fbba593f1dd215b7c55e384acd838cad549c4a2b9c6d32d264f4e2a,
#    which is the key every peer uses to verify the sequencer's votes.
```

The same procedure applies to `sign_identification` using the `b"INIT_PEER_ID"` domain separator. [6](#0-5)

### Citations

**File:** crates/apollo_signature_manager/src/signature_manager.rs (L59-82)
```rust
    pub async fn sign_identification(
        &self,
        peer_id: PeerId,
        challenge: Challenge,
    ) -> SignatureManagerResult<RawSignature> {
        let message_digest = build_peer_identity_message_digest(peer_id, challenge);
        self.sign(message_digest).await
    }

    pub async fn sign_precommit_vote(
        &self,
        block_hash: BlockHash,
    ) -> SignatureManagerResult<RawSignature> {
        let message_digest = build_precommit_vote_message_digest(block_hash);
        self.sign(message_digest).await
    }

    async fn sign(&self, message_digest: MessageDigest) -> SignatureManagerResult<RawSignature> {
        let private_key = self.keystore.get_key().await?;
        let signature = ecdsa_sign(&private_key, &message_digest)
            .map_err(|e| SignatureManagerError::Sign(e.to_string()))?;

        Ok(signature.into())
    }
```

**File:** crates/apollo_signature_manager/src/signature_manager.rs (L96-99)
```rust
    fn _new(private_key: PrivateKey) -> Self {
        let public_key = PublicKey(get_public_key(&private_key));
        Self { private_key, public_key }
    }
```

**File:** crates/apollo_signature_manager/src/signature_manager.rs (L101-111)
```rust
    pub(crate) const fn new_for_testing() -> Self {
        // Created using `cairo-lang`.
        const PRIVATE_KEY: PrivateKey = PrivateKey(Felt::from_hex_unchecked(
            "0x608bf2cdb1ad4138e72d2f82b8c5db9fa182d1883868ae582ed373429b7a133",
        ));
        const PUBLIC_KEY: PublicKey = PublicKey(Felt::from_hex_unchecked(
            "0x125d56b1fbba593f1dd215b7c55e384acd838cad549c4a2b9c6d32d264f4e2a",
        ));

        Self { private_key: PRIVATE_KEY, public_key: PUBLIC_KEY }
    }
```

**File:** crates/apollo_signature_manager/src/signature_manager.rs (L127-145)
```rust
fn build_peer_identity_message_digest(peer_id: PeerId, challenge: Challenge) -> MessageDigest {
    let challenge = &challenge.0;
    let peer_id = peer_id.to_bytes();
    let mut message = Vec::with_capacity(INIT_PEER_ID.len() + peer_id.len() + challenge.len());
    message.extend_from_slice(INIT_PEER_ID);
    message.extend_from_slice(&peer_id);
    message.extend_from_slice(challenge);

    MessageDigest(blake2s_to_felt(&message))
}

fn build_precommit_vote_message_digest(block_hash: BlockHash) -> MessageDigest {
    let block_hash = block_hash.to_bytes_be();
    let mut message = Vec::with_capacity(PRECOMMIT_VOTE.len() + block_hash.len());
    message.extend_from_slice(PRECOMMIT_VOTE);
    message.extend_from_slice(&block_hash);

    MessageDigest(blake2s_to_felt(&message))
}
```

**File:** crates/apollo_signature_manager/src/lib.rs (L17-43)
```rust
impl LocalKeyStoreSignatureManager {
    pub fn new() -> Self {
        Self(GenericSignatureManager::new(LocalKeyStore::new_for_testing()))
    }
}

impl Default for LocalKeyStoreSignatureManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for LocalKeyStoreSignatureManager {
    type Target = GenericSignatureManager<LocalKeyStore>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub use LocalKeyStoreSignatureManager as SignatureManager;

// TODO(Elin): understand how key store would look in production and better define the way the
// signature manager is created.
pub fn create_signature_manager() -> SignatureManager {
    SignatureManager::new()
}
```

**File:** crates/apollo_node/src/components.rs (L555-561)
```rust
    let signature_manager = match config.components.signature_manager.execution_mode {
        ReactiveComponentExecutionMode::LocalExecutionWithRemoteDisabled
        | ReactiveComponentExecutionMode::LocalExecutionWithRemoteEnabled => {
            Some(create_signature_manager())
        }
        ReactiveComponentExecutionMode::Disabled | ReactiveComponentExecutionMode::Remote => None,
    };
```
