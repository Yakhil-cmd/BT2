### Title
One-Time-Use Cryptographic Material (`TripleShare` / `PresignOutput`) Derives `Clone`, Enabling Nonce Reuse and Private Key Extraction - (File: `src/ecdsa/ot_based_ecdsa/triples/mod.rs`, `src/ecdsa/ot_based_ecdsa/mod.rs`)

---

### Summary

The OT-based ECDSA pipeline documents that every `TripleShare` and `PresignOutput` is **one-time-use**. However, both types unconditionally derive `Clone` (and `Serialize`/`Deserialize`), and the library provides no runtime or type-system enforcement of the single-use constraint. A caller — including a malicious coordinator or a compromised participant node — can clone either value and feed it into a second protocol invocation. The resulting two signatures share related nonces, enabling classical ECDSA nonce-reuse private-key recovery. This is the direct structural analog of the veNFT double-voting bug: the "transferable" asset is the cloneable one-time-use share, and "double voting" is double signing with the same underlying nonce material.

---

### Finding Description

**Root cause — `TripleShare` is `Clone`:** [1](#0-0) 

The module comment states the scalar values must be kept secret and the triple must not be reused, yet the type freely implements `Clone`.

**Root cause — `PresignOutput` and `RerandomizedPresignOutput` are `Clone`:** [2](#0-1) [3](#0-2) 

**The presign entry point explicitly omits the participant-set consistency check for triples:** [4](#0-3) 

The comment at lines 38-40 acknowledges the omission. Combined with `Clone`, a caller can supply the same `TripleShare` to two concurrent `presign` invocations with different participant sets.

**The README documents the one-time-use requirement but provides no enforcement:** [5](#0-4) 

**The robust ECDSA variant carries the same issue:** [6](#0-5) 

The security documentation for robust ECDSA explicitly names the consequence: [7](#0-6) 

**Attack path (OT-based ECDSA):**

1. Honest parties run triple generation → each party holds a `TripleShare`.
2. A malicious coordinator (or any party that serializes/deserializes its own share) **clones** the `TripleShare` before passing it to `presign`.
3. The coordinator initiates two concurrent presigning sessions using the same cloned triple shares (possibly with overlapping or identical participant sets).
4. Both sessions produce `PresignOutput` values whose `k` shares reconstruct to the **same scalar** `k` (the nonce).
5. The coordinator then drives two signing sessions for two different messages `m1`, `m2` using the two presignatures.
6. The resulting ECDSA signatures `(r, s1)` and `(r, s2)` satisfy `s1 - s2 = k*(h1 - h2)`, from which `k = (s1-s2)/(h1-h2)` and then `x = (s1*k - h1)/r` — the full private key is recovered.

The same path applies to `PresignOutput` reuse directly: clone a completed presignature, rerandomize each copy for a different message, run two signing sessions.

---

### Impact Explanation

Reusing a `TripleShare` across two presigning sessions, or reusing a `PresignOutput` across two signing sessions, produces two ECDSA signatures with multiplicatively related nonces. Standard nonce-reuse algebra recovers the aggregate secret key `x` from the two public signatures alone. This satisfies the **Critical** impact criterion: *Extraction, reconstruction, or disclosure of private signing shares or aggregate secret material*.

---

### Likelihood Explanation

The `Clone` bound is part of the public API surface. Any library consumer that (a) serializes and deserializes shares for storage/transport, (b) implements retry logic after a failed signing session, or (c) is a malicious coordinator deliberately replaying material, will trigger this path without any special privilege. The library's own test utilities clone `PresignOutput` freely. The risk is therefore **High** for any deployment that does not implement an external one-time-use ledger.

---

### Recommendation

1. **Remove `Clone` from `TripleShare`, `PresignOutput`, and `RerandomizedPresignOutput`**. Rust's move semantics then enforce single-use at compile time: passing the value to `presign` or `sign` consumes it.
2. If serialization is required for persistence, gate it behind a separate `#[cfg(feature = "serialize")]` feature flag with prominent documentation that deserialization recreates a reusable value.
3. Add a runtime guard in `presign` that verifies the presigning participant set is a subset of `TriplePub::participants`, closing the explicitly omitted check at lines 38-40 of `src/ecdsa/ot_based_ecdsa/presign.rs`.

---

### Proof of Concept

```rust
// Caller-side reuse — no special privilege required
let (triple_share, triple_pub) = deal(&mut rng, &participants, threshold).unwrap();

// Clone before consuming — library permits this
let triple_share_copy = triple_share.clone();

// Session 1: legitimate presign
let presign1 = presign(&participants, me, PresignArguments {
    triple0: (triple_share,      triple_pub.clone()),
    triple1: (triple1_share,     triple1_pub.clone()),
    keygen_out: keygen.clone(),
    threshold,
}).unwrap();

// Session 2: reuse the same nonce material
let presign2 = presign(&participants, me, PresignArguments {
    triple0: (triple_share_copy, triple_pub.clone()),  // same triple!
    triple1: (triple1_share2,    triple1_pub.clone()),
    keygen_out: keygen.clone(),
    threshold,
}).unwrap();

// Both presignatures reconstruct to the same k.
// Sign two different messages → nonce reuse → private key recovery.
```

The `Clone` derive on `TripleShare` at [1](#0-0)  is the single line that makes this possible. No cryptographic break, no external assumption, and no privileged access is required.

### Citations

**File:** src/ecdsa/ot_based_ecdsa/triples/mod.rs (L72-77)
```rust
#[derive(Clone, Debug, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct TripleShare {
    pub a: Scalar,
    pub b: Scalar,
    pub c: Scalar,
}
```

**File:** src/ecdsa/ot_based_ecdsa/mod.rs (L40-49)
```rust
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, ZeroizeOnDrop)]
pub struct PresignOutput {
    /// The public nonce commitment.
    #[zeroize[skip]]
    pub big_r: AffinePoint,
    /// Our share of the nonce value.
    pub k: Scalar,
    /// Our share of the sigma value.
    pub sigma: Scalar,
}
```

**File:** src/ecdsa/ot_based_ecdsa/mod.rs (L54-63)
```rust
#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct RerandomizedPresignOutput {
    /// The rerandomized public nonce commitment.
    #[zeroize[skip]]
    pub big_r: AffinePoint,
    /// Our rerandomized share of the nonce value.
    pub k: Scalar,
    /// Our rerandomized share of the sigma value.
    pub sigma: Scalar,
}
```

**File:** src/ecdsa/ot_based_ecdsa/README.md (L8-12)
```markdown
Triple Generation (offline)  -->  Presigning (offline)  -->  Signing (online)
   2 triples per presig              1 presignature              1 signature
```

Each output is consumed **exactly once** (one-time use).
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L23-29)
```rust
/// The presignature protocol.
///
/// This is the first phase of performing a signature, in which we perform
/// all the work we can do without yet knowing the message to be signed.
///
/// This work does depend on the private key though, and it's crucial
/// that a presignature is never reused.
```

**File:** docs/ecdsa/robust_ecdsa/signing.md (L151-158)
```markdown
signing parameters are not globally consistent. If different subsets of size at least
$2t + 1$ sign different $(h, \epsilon)$ values using shares derived from the same
presignature, the resulting signatures use multiplicatively related nonces and the
secret key can be recovered using standard ECDSA nonce-reuse attacks.

Moreover, due to protocol modifications relative to [[DJNPO20](https://eprint.iacr.org/2020/501)] (notably signature-share
linearization), **a novel split-view attack exists that can extract the secret key using as
few as $2t + 2$ presigning participants**, with as few as two signing sessions.
```
