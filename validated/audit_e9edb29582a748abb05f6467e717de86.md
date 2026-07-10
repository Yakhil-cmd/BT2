### Title
`KeygenOutput` Derives `Serialize` and `Debug` Exposing Private Signing Shares in Plaintext — (File: `src/lib.rs`)

---

### Summary
`KeygenOutput<C>`, the primary output of every DKG, reshare, and refresh protocol in this library, unconditionally derives `Serialize`, `Deserialize`, and `Debug` with its `private_share` field fully exposed. There is no API-level warning, no documentation note, and no protective wrapper preventing a caller from trivially serializing a private signing share to a plaintext file, log stream, or database record. The `ZeroizeOnDrop` guard on the struct is directly undermined by the `Serialize` derive, which extracts the raw scalar before any zeroization can occur.

---

### Finding Description

`KeygenOutput<C>` is defined in `src/lib.rs` as:

```rust
#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq, ZeroizeOnDrop)]
#[serde(bound = "C: Ciphersuite")]
pub struct KeygenOutput<C: Ciphersuite> {
    pub private_share: SigningShare<C>,
    #[zeroize[skip]]
    pub public_key: VerifyingKey<C>,
}
``` [1](#0-0) 

Two independent exposure paths exist:

**Path 1 — `Serialize`/`Deserialize`:** The derived `Serialize` implementation serializes `private_share` as a raw hex-encoded scalar with no encryption, MAC, or access-control wrapper. The library's own snapshot tests confirm this output format:

```json
{ "private_share": "add8bea105e6085a3f9d4ee613834280ae277e9516a6d08ba8a1fa88d7ce6225",
  "public_key":    "03aa034760c5846f61bd047a4edd088a2b32bee7473a1163926fcc4b27ebc916f0" }
``` [2](#0-1) 

The serialization test in `src/ecdsa/mod.rs` explicitly asserts that `serde_json::to_string(&keygen_output)` succeeds and produces the private scalar in plaintext: [3](#0-2) 

The same pattern is confirmed for EdDSA and RedJubjub: [4](#0-3) [5](#0-4) 

**Path 2 — `Debug`:** The derived `Debug` implementation will print `private_share` (and its underlying scalar) whenever `{:?}` formatting is applied — for example, in panic messages, test output, or application-level logging. No `#[debug(skip)]` or custom `Debug` suppression is applied to `private_share`. The library itself notes elsewhere that `Debug` cannot be derived on `RerandomizationArguments` due to external type constraints, demonstrating awareness of the issue in adjacent code, but no analogous protection is applied to `KeygenOutput`. [6](#0-5) 

**No documentation warning exists.** Neither the `KeygenOutput` doc comment ("Generic type of key pairs"), the `keygen`, `reshare`, or `refresh` function signatures, nor the README mention any risk associated with serializing or logging `KeygenOutput`. The `ZeroizeOnDrop` annotation signals security awareness but provides no protection against the `Serialize` path, which copies the scalar out of memory before any drop occurs. [7](#0-6) 

---

### Impact Explanation

**Critical — Extraction or disclosure of private signing shares.**

A caller who follows the natural API pattern of persisting `KeygenOutput` between signing sessions (which is required for any real deployment, since the DKG output must survive process restarts) will serialize the struct using the provided `Serialize` impl. If the resulting file, database row, or log entry has overly broad permissions — or is included in a backup, crash dump, or observability pipeline — the raw private signing share scalar is exposed in plaintext. An attacker who reads that scalar can:

1. Reconstruct a valid `KeygenOutput` by deserializing it (the `Deserialize` impl is symmetric).
2. Inject it into any signing protocol as the compromised participant, producing valid signature shares indistinguishable from honest ones.
3. If the attacker collects shares from `threshold` participants (including the stolen one), produce a complete, valid threshold signature over an attacker-chosen message.

This directly satisfies the Critical impact class: *Extraction, reconstruction, or disclosure of private signing shares.*

---

### Likelihood Explanation

**High.** Persisting `KeygenOutput` to disk between sessions is not optional — it is the only way to reuse a DKG output across process restarts, which every production deployment must do. The library provides `Serialize`/`Deserialize` as the only built-in persistence mechanism and provides no alternative (e.g., an encrypted envelope type). There is no warning in the API, the README, or the doc comments. A developer following standard Rust patterns (`serde_json::to_writer(file, &keygen_output)`) will produce a plaintext file containing the private share without any indication that this is dangerous. The snapshot files committed to the repository itself demonstrate that this is the expected and tested serialization format. [8](#0-7) 

---

### Recommendation

1. **Remove `Debug` from `KeygenOutput` or implement a redacting custom `Debug`** that prints `"[REDACTED]"` for `private_share`. This prevents accidental exposure through logging and panic output.

2. **Remove `Serialize`/`Deserialize` from `KeygenOutput` directly**, or gate them behind a clearly named feature flag (e.g., `plaintext-key-export`) that is disabled by default, forcing callers to make an explicit opt-in decision.

3. **Provide an encrypted persistence wrapper** (e.g., a `ProtectedKeygenOutput` type that requires a passphrase or key-encryption-key to serialize/deserialize) as the recommended storage path, analogous to how the Cosmos SDK keyring recommends non-`test` backends.

4. **Add prominent documentation warnings** to `KeygenOutput`, `keygen`, `reshare`, and `refresh` stating that `private_share` is secret key material, that plaintext serialization to disk is dangerous, and that callers are responsible for encrypting the output at rest.

5. **Add a `#[must_use]` or similar lint** to draw attention to the fact that the output of `keygen` contains secret material requiring secure handling.

---

### Proof of Concept

The following is a minimal, valid Rust snippet using only the public API as documented:

```rust
use std::fs::OpenOptions;
use threshold_signatures::{keygen, KeygenOutput};
use threshold_signatures::ecdsa::Secp256K1Sha256;
use threshold_signatures::participants::Participant;
use rand_core::OsRng;

// After running DKG, persist the output — the natural thing to do.
let output: KeygenOutput<Secp256K1Sha256> = /* result of keygen protocol */;

// Writes private_share as plaintext hex to disk. No warning from the API.
let file = OpenOptions::new().write(true).create(true).open("keygen.json").unwrap();
serde_json::to_writer(file, &output).unwrap();

// Attacker reads the file and reconstructs the signing share:
let stolen: KeygenOutput<Secp256K1Sha256> =
    serde_json::from_str(r#"{"private_share":"add8bea1...","public_key":"03aa03..."}"#).unwrap();
// stolen.private_share is now a fully valid signing share usable in any signing protocol.
```

The snapshot file `src/ecdsa/snapshots/threshold_signatures__ecdsa__test__keygen_determinism.snap` is a committed, repository-level demonstration that this serialization produces real private share scalars in plaintext JSON, confirming the exposure path is not theoretical. [1](#0-0) [2](#0-1)

### Citations

**File:** src/lib.rs (L48-55)
```rust
#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq, ZeroizeOnDrop)]
#[serde(bound = "C: Ciphersuite")]
/// Generic type of key pairs
pub struct KeygenOutput<C: Ciphersuite> {
    pub private_share: SigningShare<C>,
    #[zeroize[skip]]
    pub public_key: VerifyingKey<C>,
}
```

**File:** src/lib.rs (L87-102)
```rust
/// Generic key generation function agnostic of the curve
pub fn keygen<C: Ciphersuite>(
    participants: &[Participant],
    me: Participant,
    threshold: impl Into<ReconstructionLowerBound> + Send + Copy + 'static,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = KeygenOutput<C>>, InitializationError>
where
    Element<C>: Send,
    Scalar<C>: Send,
{
    let comms = Comms::new();
    let participants = assert_key_invariants(participants, me, threshold)?;
    let fut = do_keygen::<C>(comms.shared_channel(), participants, me, threshold, rng);
    Ok(make_protocol(comms, fut))
}
```

**File:** src/ecdsa/snapshots/threshold_signatures__ecdsa__test__keygen_determinism.snap (L1-27)
```text
---
source: src/ecdsa/mod.rs
expression: result
---
[
  [
    0,
    {
      "private_share": "add8bea105e6085a3f9d4ee613834280ae277e9516a6d08ba8a1fa88d7ce6225",
      "public_key": "03aa034760c5846f61bd047a4edd088a2b32bee7473a1163926fcc4b27ebc916f0"
    }
  ],
  [
    1,
    {
      "private_share": "5e0b14b3b6dbffdd205091178e73efca89630b645d9d9cf66d190c0ebe35fcb0",
      "public_key": "03aa034760c5846f61bd047a4edd088a2b32bee7473a1163926fcc4b27ebc916f0"
    }
  ],
  [
    2,
    {
      "private_share": "0e3d6ac667d1f7600103d34909649d14649e9833a494696131901d94a49d973b",
      "public_key": "03aa034760c5846f61bd047a4edd088a2b32bee7473a1163926fcc4b27ebc916f0"
    }
  ]
]
```

**File:** src/ecdsa/mod.rs (L92-93)
```rust
// Cannot derive Debug here because an external type inside Tweak does not implement it
#[derive(Clone)]
```

**File:** src/ecdsa/mod.rs (L251-270)
```rust
    fn keygen_output_should_be_serializable() {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let signing_key = FrostSigningKey::<C>::new(&mut rng);

        let keygen_output = KeygenOutput {
            private_share: SigningShare::<C>::new(Scalar::ONE),
            public_key: frost_core::VerifyingKey::<C>::from(signing_key),
        };

        // When
        let serialized_keygen_output =
            serde_json::to_string(&keygen_output).expect("should be able to serialize output");

        // Then
        assert_eq!(
            serialized_keygen_output,
            "{\"private_share\":\"0000000000000000000000000000000000000000000000000000000000000001\",\"public_key\":\"0351177dde89242d9121d787a681bd2a0bd6013428a6b83e684a253815db96d8b3\"}"
        );
    }
```

**File:** src/frost/eddsa/test.rs (L158-179)
```rust
#[test]
#[allow(non_snake_case)]
fn keygen_output__should_be_serializable() {
    // Given
    let mut rng = MockCryptoRng::seed_from_u64(42u64);
    let signing_key = SigningKey::new(&mut rng);

    let keygen_output = KeygenOutput {
        private_share: SigningShare::new(Scalar::<C>::from(7_u32)),
        public_key: VerifyingKey::from(signing_key),
    };

    // When
    let serialized_keygen_output =
        serde_json::to_string(&keygen_output).expect("should be able to serialize output");

    // Then
    assert_eq!(
        serialized_keygen_output,
        "{\"private_share\":\"0700000000000000000000000000000000000000000000000000000000000000\",\"public_key\":\"a80ed62da91a8c6f266d82c4b2017cc0be13e6acba26af04494635b15ac86b57\"}"
    );
}
```

**File:** src/frost/redjubjub/test.rs (L129-150)
```rust
#[test]
#[allow(non_snake_case)]
fn keygen_output__should_be_serializable() {
    // Given
    let mut rng = MockCryptoRng::seed_from_u64(42u64);
    let signing_key = SigningKey::new(&mut rng);

    let keygen_output = KeygenOutput {
        private_share: SigningShare::new(Scalar::<C>::from(7_u64)),
        public_key: VerifyingKey::from(signing_key),
    };

    // When
    let serialized_keygen_output =
        serde_json::to_string(&keygen_output).expect("should be able to serialize output");

    // Then
    assert_eq!(
        serialized_keygen_output,
        "{\"private_share\":\"0700000000000000000000000000000000000000000000000000000000000000\",\"public_key\":\"cee9f1be0b483c2760c22acdf87b79e3a6b89ff755d697a3ba3933d6e6807499\"}"
    );
}
```

**File:** src/ecdsa/snapshots/threshold_signatures__ecdsa__test__reshare_determinism.snap (L1-34)
```text
---
source: src/ecdsa/mod.rs
expression: result
---
[
  [
    0,
    {
      "private_share": "b64c417fea3da809c6c1facf233a0d1fdf8e98c7fc415255eed91451b805dfdc",
      "public_key": "03aa034760c5846f61bd047a4edd088a2b32bee7473a1163926fcc4b27ebc916f0"
    }
  ],
  [
    1,
    {
      "private_share": "efb5a2363284439e32c42cb24ead5b78b31b4420fc22c6a38efd937dbb5b08fe",
      "public_key": "03aa034760c5846f61bd047a4edd088a2b32bee7473a1163926fcc4b27ebc916f0"
    }
  ],
  [
    2,
    {
      "private_share": "a9e28ab12dc3e394a2f0a25e1aec804292e316ea200bc0ce04c607fa2b3001bf",
      "public_key": "03aa034760c5846f61bd047a4edd088a2b32bee7473a1163926fcc4b27ebc916f0"
    }
  ],
  [
    31,
    {
      "private_share": "8d3893dbc11b750c6bcb24bd78710c1c0e0b4519c9c4c2243a27ccf162f713a9",
      "public_key": "03aa034760c5846f61bd047a4edd088a2b32bee7473a1163926fcc4b27ebc916f0"
    }
  ]
]
```
