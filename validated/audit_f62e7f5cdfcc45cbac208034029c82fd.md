### Title
Secret Cryptographic Material Exposed via `Debug` Trait Derivation on Sensitive Output Types - (File: `src/ecdsa/ot_based_ecdsa/triples/mod.rs`, `src/ecdsa/ot_based_ecdsa/mod.rs`, `src/ecdsa/robust_ecdsa/mod.rs`, `src/lib.rs`, `src/frost/mod.rs`)

---

### Summary

Multiple production types holding secret cryptographic material — including Beaver triple shares, presign nonce shares, and private signing shares — unconditionally derive Rust's `Debug` trait. Because `Debug` prints field values verbatim when formatted with `{:?}`, any logging, panic message, or diagnostic path that touches these types will emit the raw secret scalars in plaintext. The module documentation for `TripleShare` explicitly states that exposure of the underlying scalars allows full private-key recovery.

---

### Finding Description

The following production types derive `Debug` while containing secret scalar material:

**`TripleShare`** (`src/ecdsa/ot_based_ecdsa/triples/mod.rs`, line 72):
```rust
#[derive(Clone, Debug, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct TripleShare {
    pub a: Scalar,
    pub b: Scalar,
    pub c: Scalar,
}
```
The module-level documentation at lines 8–13 explicitly warns: *"It's important that the value of the underlying scalars in the triple is kept secret, otherwise the private key used to create a signature with that triple could be recovered."* Despite this, `Debug` is derived unconditionally, printing `a`, `b`, and `c` verbatim.

**`PresignOutput` (OT-based ECDSA)** (`src/ecdsa/ot_based_ecdsa/mod.rs`, line 40):
```rust
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, ZeroizeOnDrop)]
pub struct PresignOutput {
    pub big_r: AffinePoint,
    pub k: Scalar,      // secret nonce share
    pub sigma: Scalar,  // secret sigma share
}
```

**`RerandomizedPresignOutput` (OT-based ECDSA)** (`src/ecdsa/ot_based_ecdsa/mod.rs`, line 54):
```rust
#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct RerandomizedPresignOutput {
    pub big_r: AffinePoint,
    pub k: Scalar,
    pub sigma: Scalar,
}
```

**`PresignOutput` (Robust ECDSA)** (`src/ecdsa/robust_ecdsa/mod.rs`, line 26):
```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ZeroizeOnDrop)]
pub struct PresignOutput {
    pub big_r: AffinePoint,
    pub c: Scalar,
    pub e: Scalar,
    pub alpha: Scalar,
    pub beta: Scalar,
}
```

**`KeygenOutput<C>`** (`src/lib.rs`, line 48):
```rust
#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq, ZeroizeOnDrop)]
pub struct KeygenOutput<C: Ciphersuite> {
    pub private_share: SigningShare<C>,
    pub public_key: VerifyingKey<C>,
}
```

**`frost::PresignOutput<C>`** (`src/frost/mod.rs`, line 36):
```rust
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct PresignOutput<C: Ciphersuite + Send + 'static> {
    pub nonces: SigningNonces<C>,
    pub commitments_map: BTreeMap<Identifier<C>, SigningCommitments<C>>,
}
```
`SigningNonces<C>` from `frost_core` holds the actual nonce scalars; in Schnorr/FROST, a known nonce combined with a signature allows full private-key recovery.

The underlying scalar types (`k256::Scalar`, `blstrs::Scalar`, `frost_core::keys::SigningShare`) all implement `Debug` by printing their actual byte representation. Deriving `Debug` on the wrapper structs therefore propagates this exposure to every field.

---

### Impact Explanation

**Critical — Extraction or disclosure of private signing shares, presign secrets, and nonce material.**

- **`TripleShare`**: The module documentation is unambiguous — exposing `a`, `b`, or `c` allows an attacker to recover the aggregate private signing key from any signature produced with that triple. A single log line such as `tracing::debug!("{:?}", triple_share)` suffices.
- **`PresignOutput` (OT-based / Robust)**: Exposing the nonce shares `k`/`sigma` or `c`/`e`/`alpha`/`beta` allows an attacker who also observes the resulting signature to solve for the private key share, and with threshold-many such exposures, reconstruct the aggregate secret.
- **`KeygenOutput<C>`**: Direct exposure of `private_share` gives the attacker a signing share outright.
- **`frost::PresignOutput<C>`**: Exposing `SigningNonces` enables nonce-reuse or nonce-recovery attacks against FROST, leading to full private-key extraction.

All of these map to the **Critical** impact class: *Extraction, reconstruction, or disclosure of private signing shares, aggregate secret material, presign secrets, or nonce material.*

---

### Likelihood Explanation

**Medium-to-High.** The `Debug` derive is unconditional and part of the public API surface. In production MPC deployments:

1. Structured logging frameworks (e.g., `tracing`, `log`) routinely format protocol outputs with `{:?}` for observability.
2. Rust's standard `assert_eq!` and `unwrap()` panic messages automatically invoke `Debug` on their operands.
3. The snapshot-testing infrastructure present in this codebase (`src/test_utils/snapshot.rs`) serializes protocol outputs; if `Debug` output is captured there, secrets appear in test artifacts.
4. Error-handling paths that propagate these types through `anyhow` or similar crates will include `Debug` representations in error chains.

No attacker capability beyond reading log output (a realistic assumption for a compromised logging pipeline, insider threat, or misconfigured log aggregator) is required.

---

### Recommendation

1. **Remove `Debug` from all types holding secret scalars**, or implement a custom `Debug` that redacts secret fields:
   ```rust
   impl fmt::Debug for TripleShare {
       fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
           f.debug_struct("TripleShare")
            .field("a", &"[REDACTED]")
            .field("b", &"[REDACTED]")
            .field("c", &"[REDACTED]")
            .finish()
       }
   }
   ```
2. Apply the same pattern to `PresignOutput` (both variants), `RerandomizedPresignOutput` (both variants), `KeygenOutput<C>`, `frost::PresignOutput<C>`, and `ScalarWrapper`.
3. Consider adding a `#[deny(clippy::derive_debug_with_sensitive_fields)]` lint or a custom lint to prevent future regressions.
4. Audit all uses of these types in logging and test infrastructure to ensure no existing log lines already emit secret material.

---

### Proof of Concept

```rust
use threshold_signatures::ecdsa::ot_based_ecdsa::triples::TripleShare;
use k256::Scalar;

// Simulated triple share (values would be real secret scalars in production)
let share = TripleShare { a: Scalar::ONE, b: Scalar::ONE, c: Scalar::ONE };

// Any of the following — all common in production Rust code — leaks a, b, c:
println!("{:?}", share);                          // direct print
tracing::debug!(?share, "triple generated");      // structured logging
log::debug!("{share:?}");                         // log crate
assert_eq!(share, other_share);                   // panic on mismatch prints both
format!("{share:?}")                              // stored in error message
```

The `Debug` output will contain the raw scalar bytes of `a`, `b`, and `c`. Per the module documentation, possession of these values allows recovery of the private signing key from any ECDSA signature produced using this triple. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** src/ecdsa/ot_based_ecdsa/triples/mod.rs (L8-13)
```rust
//! The signing protocols make use of a triple where the scalar values `(a, b, c)`
//! are secret-shared, and the commitments are public. Each signature requires
//! two triples. These triples can be generated in advance without knowledge
//! of the secret key used to sign. It's important that the value of the underlying
//! scalars in the triple is kept secret, otherwise the private key used to create
//! a signature with that triple could be recovered.
```

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

**File:** src/ecdsa/robust_ecdsa/mod.rs (L26-37)
```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ZeroizeOnDrop)]
pub struct PresignOutput {
    /// The public nonce commitment.
    #[zeroize(skip)]
    pub big_r: AffinePoint,

    /// Our secret shares of the nonces.
    pub c: Scalar,
    pub e: Scalar,
    pub alpha: Scalar,
    pub beta: Scalar,
}
```

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

**File:** src/frost/mod.rs (L36-41)
```rust
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct PresignOutput<C: Ciphersuite + Send + 'static> {
    /// The public nonce commitment.
    pub nonces: SigningNonces<C>,
    pub commitments_map: BTreeMap<Identifier<C>, SigningCommitments<C>>,
}
```
