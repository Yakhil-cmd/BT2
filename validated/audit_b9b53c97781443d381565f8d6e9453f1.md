### Title
Secret Cryptographic Material Exposed via `Debug` Trait on `TripleShare`, `PresignOutput`, and `KeygenOutput` — (File: `src/ecdsa/ot_based_ecdsa/triples/mod.rs`, `src/ecdsa/ot_based_ecdsa/mod.rs`, `src/ecdsa/robust_ecdsa/mod.rs`, `src/lib.rs`)

---

### Summary

Multiple production types holding secret scalar material — Beaver triple shares, presign nonce shares, and private signing shares — unconditionally derive `Debug`. The module documentation for `TripleShare` explicitly states that disclosure of its secret scalars enables private key recovery. Any library caller, logging framework, or error-handling path that formats these types with `{:?}` will emit the raw secret scalars in plaintext, providing a direct path to private key extraction.

---

### Finding Description

The following production types derive `Debug` while containing secret scalar fields:

**1. `TripleShare`** — `src/ecdsa/ot_based_ecdsa/triples/mod.rs`, lines 72–77

```rust
#[derive(Clone, Debug, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct TripleShare {
    pub a: Scalar,
    pub b: Scalar,
    pub c: Scalar,
}
```

The module's own documentation (lines 11–13) states:

> "It's important that the value of the underlying scalars in the triple is kept secret, **otherwise the private key used to create a signature with that triple could be recovered**."

Despite this explicit warning, `Debug` is derived, meaning `format!("{:?}", triple_share)` emits `a`, `b`, `c` in plaintext.

**2. `PresignArguments`** — `src/ecdsa/ot_based_ecdsa/mod.rs`, lines 23–34

```rust
#[derive(Debug, Clone)]
pub struct PresignArguments {
    pub triple0: (TripleShare, TriplePub),
    pub triple1: (TripleShare, TriplePub),
    pub keygen_out: KeygenOutput,
    pub threshold: ReconstructionLowerBound,
}
```

This struct aggregates two `TripleShare` values **and** a `KeygenOutput` (which contains `private_share: SigningShare<C>`). A single `{:?}` format of `PresignArguments` leaks all three secret components simultaneously.

**3. OT-based `PresignOutput`** — `src/ecdsa/ot_based_ecdsa/mod.rs`, lines 40–49

```rust
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, ZeroizeOnDrop)]
pub struct PresignOutput {
    #[zeroize[skip]]
    pub big_r: AffinePoint,
    pub k: Scalar,      // secret nonce share
    pub sigma: Scalar,  // secret sigma share
}
```

**4. OT-based `RerandomizedPresignOutput`** — `src/ecdsa/ot_based_ecdsa/mod.rs`, lines 54–63

```rust
#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct RerandomizedPresignOutput {
    #[zeroize[skip]]
    pub big_r: AffinePoint,
    pub k: Scalar,
    pub sigma: Scalar,
}
```

**5. Robust `PresignOutput`** — `src/ecdsa/robust_ecdsa/mod.rs`, lines 26–37

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ZeroizeOnDrop)]
pub struct PresignOutput {
    #[zeroize(skip)]
    pub big_r: AffinePoint,
    pub c: Scalar,
    pub e: Scalar,
    pub alpha: Scalar,
    pub beta: Scalar,
}
```

**6. `KeygenOutput<C>`** — `src/lib.rs`, lines 48–55

```rust
#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq, ZeroizeOnDrop)]
pub struct KeygenOutput<C: Ciphersuite> {
    pub private_share: SigningShare<C>,
    #[zeroize[skip]]
    pub public_key: VerifyingKey<C>,
}
```

The `private_share` field is the party's secret signing share. `Debug` formatting emits it in plaintext.

---

### Impact Explanation

**Critical — Extraction, reconstruction, or disclosure of private signing shares, aggregate secret material, presign secrets, or nonce material.**

- **`TripleShare` leakage → private key recovery**: The module documentation is unambiguous. An attacker who obtains `a`, `b`, `c` for a triple used in a signing session can reconstruct the signer's private key share from the resulting signature. Two triples are consumed per OT-based ECDSA signature; both are embedded in `PresignArguments` which also derives `Debug`.
- **`PresignOutput` leakage → nonce recovery → private key recovery**: Disclosure of `k` and `sigma` (OT-based) or `c`, `e`, `alpha`, `beta` (Robust) from a presign output, combined with the corresponding signature, allows an attacker to solve for the private key share.
- **`KeygenOutput` leakage → direct private share disclosure**: `private_share` is the party's long-term secret signing share. Its disclosure via `Debug` is a direct, unconditional extraction of secret key material.

---

### Likelihood Explanation

**Medium-to-High.** The `Debug` derive is unconditional and part of the public API. Realistic triggering paths include:

1. **Library caller logging**: Any integrator who logs `PresignArguments`, `PresignOutput`, or `KeygenOutput` for diagnostics (a common practice during development and incident response) will emit secret scalars. The types are `pub`, so callers have full access.
2. **Error propagation**: Rust's `?` operator and `anyhow`/`thiserror` error chains frequently include `{:?}` formatting of context values. If any of these types appear in an error context, the secret is emitted.
3. **Test harnesses leaking into CI logs**: Test failures print `{:?}` of asserted values. If a test asserts on a `PresignOutput` or `KeygenOutput`, the secret scalars appear in CI logs.
4. **Snapshot testing**: `src/test_utils/snapshot.rs` uses `Debug` derives; if snapshot tests capture these types, secrets appear in committed test fixtures.

The `ZeroizeOnDrop` on these types demonstrates the library authors are aware of secret-handling requirements, making the `Debug` derive an inconsistency rather than an intentional design choice.

---

### Recommendation

**Short term**: Remove `Debug` from all types containing secret scalar fields. Replace with a redacting implementation that prints `"[REDACTED]"` for secret fields:

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

Apply the same pattern to `PresignOutput` (both OT and Robust), `RerandomizedPresignOutput`, `KeygenOutput`, and `PresignArguments`.

**Long term**: Adopt a `Secret<T>` wrapper type (e.g., from the `secrecy` crate) for all scalar fields in secret-holding structs. This makes the `Debug` redaction automatic and enforced at the type level, preventing future regressions.

---

### Proof of Concept

```rust
use threshold_signatures::ecdsa::ot_based_ecdsa::triples::TripleShare;
// Assume triple_share is obtained from generate_triple or deal()
// An integrator logs for debugging:
println!("{:?}", triple_share);
// Output: TripleShare { a: Scalar(0x<secret_a>), b: Scalar(0x<secret_b>), c: Scalar(0x<secret_c>) }
// Attacker reads logs, recovers a, b, c.
// Using the ECDSA signing equation and the known triple values,
// the attacker solves for the private key share x_i from any signature
// produced using this triple, as documented in triples/mod.rs lines 11-13.
```

For `PresignArguments`, a single log line leaks both triple shares and the private signing share simultaneously:

```rust
println!("{:?}", presign_args);
// Emits: PresignArguments {
//   triple0: (TripleShare { a: ..., b: ..., c: ... }, ...),
//   triple1: (TripleShare { a: ..., b: ..., c: ... }, ...),
//   keygen_out: KeygenOutput { private_share: SigningShare(...), public_key: ... },
//   threshold: ...
// }
```