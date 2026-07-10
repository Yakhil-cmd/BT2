### Title
Presignature Replay Enabled by `Clone` on `RerandomizedPresignOutput` Despite Documented One-Time-Use Requirement - (File: `src/ecdsa/robust_ecdsa/mod.rs`)

---

### Summary

The `RerandomizedPresignOutput` type in the robust ECDSA scheme derives `Clone` and `Serialize`/`Deserialize`, directly contradicting the library's own documented requirement that each presignature is consumed **exactly once**. Because `sign()` accepts the presignature by value (move), the intent is to enforce one-time use via Rust's ownership system. However, the `Clone` derive allows any caller to trivially bypass this protection. A malicious coordinator can orchestrate two signing sessions over the same presignature shares with different message hashes, producing two ECDSA signatures that share the same nonce `R`, enabling full secret key extraction via standard nonce-reuse algebra.

---

### Finding Description

`RerandomizedPresignOutput` is declared in `src/ecdsa/robust_ecdsa/mod.rs` with the following derives:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct RerandomizedPresignOutput {
    big_r: AffinePoint,
    e: Scalar,
    alpha: Scalar,
    beta: Scalar,
}
``` [1](#0-0) 

The `sign()` function in `src/ecdsa/robust_ecdsa/sign.rs` accepts this type by value:

```rust
pub fn sign(
    ...
    presignature: RerandomizedPresignOutput,
    msg_hash: Scalar,
) -> Result<impl Protocol<Output = SignatureOption>, InitializationError>
``` [2](#0-1) 

The move-by-value signature is the library's only mechanism to enforce one-time use. The `Clone` derive completely defeats it: any caller can write `presignature.clone()` before passing it to `sign()`, and the compiler will not object. The `Serialize`/`Deserialize` derives additionally allow a presignature to be written to persistent storage and deserialized multiple times, achieving the same effect without even calling `.clone()`.

The library's own documentation explicitly states the security requirement being violated:

> **Never reuse a presignature**, even across failed, aborted, or partially completed signing sessions. [3](#0-2) 

> Each presignature is consumed **exactly once** (one-time use). [4](#0-3) 

The same comment appears in the presigning source itself:

> it's crucial that a presignature is never reused. [5](#0-4) 

The same structural problem exists in the OT-based ECDSA path, where `presign.rs` carries the identical warning: [6](#0-5) 

---

### Impact Explanation

The security consequence of presignature reuse is documented directly in the codebase:

> If different subsets of size at least 2t+1 sign different (h, ε) values using shares derived from the same presignature, the resulting signatures use multiplicatively related nonces and **the secret key can be recovered using standard ECDSA nonce-reuse attacks**. [7](#0-6) 

Two ECDSA signatures `(R, s₁)` and `(R, s₂)` produced with the same nonce `R` but different message hashes `h₁ ≠ h₂` satisfy:

```
s₁ - s₂ = α·(h₁ - h₂)   (mod q)
```

where `α` encodes the inverse nonce. This system is solvable for the secret key `x` using the known public key and both signatures. This is a **Critical** impact: full extraction of the aggregate private signing key material.

---

### Likelihood Explanation

The attack is reachable by a malicious coordinator. The coordinator controls which presignature is used in each signing session. Because `RerandomizedPresignOutput` implements `Serialize`/`Deserialize`, presignatures are routinely stored (e.g., in a database or message queue) between the offline presigning phase and the online signing phase. A coordinator that stores and re-submits the same serialized presignature to participants for two different signing requests triggers the vulnerability without any participant being aware. No cryptographic break is required; the attack is purely operational.

Additionally, the `Clone` derive means that even well-intentioned application code can accidentally reuse a presignature (e.g., by cloning it for logging, retry logic, or parallel signing attempts), making accidental triggering realistic.

---

### Recommendation

Remove `Clone` from `RerandomizedPresignOutput` (and `PresignOutput` before rerandomization) in both the robust and OT-based ECDSA paths. This forces Rust's ownership system to enforce one-time use at compile time — a caller cannot pass the presignature to `sign()` and then use it again without an explicit `.clone()` call that would require adding `Clone` back.

If serialization is required for persistence between protocol phases, consider wrapping the type in a newtype that implements `Serialize` but not `Deserialize` (write-only), or provide a dedicated `consume()` method that returns the inner data and marks the wrapper as spent. At minimum, document clearly that deserializing a stored presignature and signing with it a second time is a critical security violation.

---

### Proof of Concept

```rust
// Attacker-controlled coordinator scenario:
// 1. Run presigning to obtain presignature shares for all participants.
let presign_outputs: Vec<(Participant, PresignOutput)> = run_presign(...);

// 2. Rerandomize for signing context (msg_hash_1, tweak, entropy).
let rerand_args_1 = RerandomizationArguments::new(pk, tweak, msg_hash_1, big_r, participants, entropy);
let rerand_presigns_1: Vec<_> = presign_outputs.iter()
    .map(|(p, ps)| (*p, RerandomizedPresignOutput::rerandomize_presign(ps, &rerand_args_1).unwrap()))
    .collect();

// 3. Clone the rerandomized presignatures BEFORE the first signing session.
//    This is legal because RerandomizedPresignOutput: Clone.
let rerand_presigns_2: Vec<_> = rerand_presigns_1
    .iter()
    .map(|(p, rps)| (*p, rps.clone()))  // <-- Clone bypasses move-based one-time-use enforcement
    .collect();

// 4. Sign message 1 — consumes rerand_presigns_1 by move.
let sig1 = run_sign(rerand_presigns_1, max_malicious, coordinator, pk, msg_hash_1);

// 5. Sign message 2 with the SAME nonce R — consumes the clone.
let sig2 = run_sign(rerand_presigns_2, max_malicious, coordinator, pk, msg_hash_2);

// 6. Both signatures share the same R. Apply standard ECDSA nonce-reuse algebra
//    to recover the aggregate secret key x from (sig1, sig2, msg_hash_1, msg_hash_2).
```

The `Clone` derive on `RerandomizedPresignOutput` is the necessary and sufficient condition that makes step 3 compile and execute without error, directly enabling secret key extraction in step 6.

### Citations

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

**File:** src/ecdsa/robust_ecdsa/sign.rs (L33-41)
```rust
pub fn sign(
    participants: &[Participant],
    coordinator: Participant,
    max_malicious: impl Into<MaxMalicious>,
    me: Participant,
    public_key: AffinePoint,
    presignature: RerandomizedPresignOutput,
    msg_hash: Scalar,
) -> Result<impl Protocol<Output = SignatureOption>, InitializationError> {
```

**File:** docs/ecdsa/robust_ecdsa/signing.md (L151-154)
```markdown
signing parameters are not globally consistent. If different subsets of size at least
$2t + 1$ sign different $(h, \epsilon)$ values using shares derived from the same
presignature, the resulting signatures use multiplicatively related nonces and the
secret key can be recovered using standard ECDSA nonce-reuse attacks.
```

**File:** docs/ecdsa/robust_ecdsa/signing.md (L176-177)
```markdown
3. **Never reuse a presignature**, even across failed, aborted, or partially completed
   signing sessions.
```

**File:** src/ecdsa/robust_ecdsa/README.md (L12-12)
```markdown
Each presignature is consumed **exactly once** (one-time use).
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L28-29)
```rust
/// This work does depend on the private key though, and it's crucial
/// that a presignature is never reused.
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L18-19)
```rust
/// This work does depend on the private key though, and it's crucial
/// that a presignature is never reused.
```
