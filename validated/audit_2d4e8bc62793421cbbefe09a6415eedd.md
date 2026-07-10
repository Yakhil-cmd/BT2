### Title
`Debug` Trait on `TripleShare` Exposes Secret Beaver Triple Scalars Enabling Private Key Recovery - (File: `src/ecdsa/ot_based_ecdsa/triples/mod.rs`)

---

### Summary

`TripleShare`, a public library type holding secret Beaver triple scalars `a`, `b`, `c`, derives `Debug`. The module's own documentation explicitly states that disclosure of these scalars allows recovery of the private signing key. Any library caller that formats a `TripleShare` value with `{:?}` — through logging, error propagation, or panic output — leaks all three secret scalars in plaintext.

---

### Finding Description

`TripleShare` is defined in `src/ecdsa/ot_based_ecdsa/triples/mod.rs` with a derived `Debug` implementation:

```rust
#[derive(Clone, Debug, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct TripleShare {
    pub a: Scalar,
    pub b: Scalar,
    pub c: Scalar,
}
```

The module-level documentation at the top of the same file explicitly warns:

> "It's important that the value of the underlying scalars in the triple is kept secret, otherwise the private key used to create a signature with that triple could be recovered."

Despite this warning, the `Debug` derive causes `format!("{:?}", triple_share)` to emit the raw `k256::Scalar` values of `a`, `b`, and `c` in plaintext. `k256::Scalar` does not suppress its `Debug` output.

The same pattern affects additional secret-bearing types in the same protocol family:

- `PresignOutput` (`src/ecdsa/ot_based_ecdsa/mod.rs`, line 40) derives `Debug` and holds secret nonce shares `k` and `sigma`.
- `RerandomizedPresignOutput` (`src/ecdsa/ot_based_ecdsa/mod.rs`, line 54) derives `Debug` and holds `k` and `sigma`.
- `PresignOutput` (`src/ecdsa/robust_ecdsa/mod.rs`, line 26) derives `Debug` and holds secret nonce shares `c`, `e`, `alpha`, `beta`.
- `RerandomizedPresignOutput` (`src/ecdsa/robust_ecdsa/mod.rs`, line 42) derives `Debug` and holds `e`, `alpha`, `beta`.
- `KeygenOutput<C>` (`src/lib.rs`, line 48) derives `Debug` and holds `private_share: SigningShare<C>`.

The root cause is the same in each case: a `#[derive(Debug)]` on a struct whose fields are secret scalars, with no custom `Debug` implementation that redacts or suppresses those fields.

---

### Impact Explanation

**Critical — Extraction, reconstruction, or disclosure of private signing shares, presign secrets, or nonce material.**

The module documentation is unambiguous: knowing `a`, `b`, `c` from a `TripleShare` used in a signing session is sufficient to recover the private signing key. A caller who logs `TripleShare` values (a routine practice in Rust applications using `tracing`, `log`, or `println!("{:?}", ...)`) exposes all three scalars. Combined with the corresponding `TriplePub` (which is public), an observer of the log output can reconstruct the private key without any cryptographic attack.

For `PresignOutput`, exposure of the nonce share `k` combined with a completed signature and the public `big_r` allows the private key share to be derived algebraically.

---

### Likelihood Explanation

**Medium-to-High.** Rust's `Debug` trait is pervasively used in production systems:
- Structured logging frameworks (`tracing`, `log`) routinely format protocol outputs with `{:?}`.
- Error types that wrap these structs (e.g., via `anyhow`, `thiserror`) propagate `Debug` output into error chains.
- Panic messages in assertion failures print `{:?}` of involved values.
- The types are `pub`, so any downstream integrator can trigger this path without modifying library code.

The library already applies `ZeroizeOnDrop` to these types, demonstrating awareness of their sensitivity, but `ZeroizeOnDrop` does not prevent in-memory plaintext exposure through `Debug` formatting before the value is dropped.

---

### Recommendation

Replace `#[derive(Debug)]` on all secret-bearing types with a manual `Debug` implementation that redacts secret fields:

```rust
impl fmt::Debug for TripleShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TripleShare")
            .field("a", &"<redacted>")
            .field("b", &"<redacted>")
            .field("c", &"<redacted>")
            .finish()
    }
}
```

Apply the same pattern to `PresignOutput` (both OT-based and Robust), `RerandomizedPresignOutput` (both variants), `KeygenOutput`, and `ScalarWrapper`. Alternatively, use the `secrecy` crate or a `#[sensitive]`-style wrapper to enforce redaction at the type level across the codebase.

---

### Proof of Concept

```rust
use threshold_signatures::ecdsa::ot_based_ecdsa::triples::TripleShare;
// Obtain a TripleShare from the triple generation protocol (normal library usage).
let share: TripleShare = /* ... result of generate_triple ... */;

// Any of the following — all standard Rust patterns — leak a, b, c in plaintext:
println!("{:?}", share);                          // direct print
tracing::debug!(?share, "triple share obtained"); // structured logging
let msg = format!("share = {:?}", share);         // string formatting
```

The output would be:
```
TripleShare { a: Scalar(0x<secret_a_bytes>), b: Scalar(0x<secret_b_bytes>), c: Scalar(0x<secret_c_bytes>) }
```

Per the module's own documentation, possession of `a`, `b`, `c` is sufficient to recover the private signing key from any signature produced using this triple. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** src/ecdsa/ot_based_ecdsa/triples/mod.rs (L1-13)
```rust
//! This module contains the types and protocols related to triple generation.
//!
//! The cait-sith signing protocol makes use of *committed* Beaver Triples.
//! A triple is a value of the form `(a, b, c), (A, B, C)`, such that
//! `c = a * b`, and `A = a * G`, `B = b * G`, `C = c * G`. This is a beaver
//! triple along with commitments to its values in the form of group elements.
//!
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

**File:** src/ecdsa/robust_ecdsa/mod.rs (L42-52)
```rust
#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct RerandomizedPresignOutput {
    /// The rerandomized public nonce commitment.
    #[zeroize(skip)]
    big_r: AffinePoint,

    /// Our rerandomized secret shares of the nonces.
    e: Scalar,
    alpha: Scalar,
    beta: Scalar,
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
