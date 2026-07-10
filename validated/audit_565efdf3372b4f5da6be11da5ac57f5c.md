### Title
Missing Participant-Set Consistency Check in OT-Based ECDSA Presign Allows Silent Presignature Corruption - (`File: src/ecdsa/ot_based_ecdsa/presign.rs`)

---

### Summary

The `presign` function in `src/ecdsa/ot_based_ecdsa/presign.rs` explicitly omits the check that the participant set passed to `presign` matches the participant set recorded in the `TriplePub` structs used as inputs. The `TriplePub` type stores the original triple-generation participant set in its `participants` field, but `presign` never compares this against the `participants` argument it receives. As a result, a caller can silently run presigning with a mismatched participant set, producing a cryptographically invalid presignature that only fails later during the sign phase.

---

### Finding Description

`TriplePub` records the participant set that generated the triple:

```rust
// src/ecdsa/ot_based_ecdsa/triples/mod.rs:57-65
pub struct TriplePub {
    pub big_a: AffinePoint,
    pub big_b: AffinePoint,
    pub big_c: AffinePoint,
    /// The participants in generating this triple.
    pub participants: Vec<Participant>,
    /// The threshold which will be able to reconstruct it.
    pub threshold: ReconstructionLowerBound,
}
``` [1](#0-0) 

The `presign` function checks that the threshold matches the triples, but explicitly skips the participant-set check with a comment:

```rust
// src/ecdsa/ot_based_ecdsa/presign.rs:38-46
// NOTE: We omit the check that the new participant set was present for
// the triple generation, because presumably they need to have been present
// in order to have shares.

// Also check that we have enough participants to reconstruct shares.
if args.threshold != args.triple0.1.threshold || args.threshold != args.triple1.1.threshold {
    return Err(InitializationError::BadParameters(
        "New threshold must match the threshold of both triples".to_string(),
    ));
}
``` [2](#0-1) 

Inside `do_presign`, Lagrange coefficients are computed using the **presign** participant set, not the triple-generation participant set:

```rust
// src/ecdsa/ot_based_ecdsa/presign.rs:93-103
let lambda_me = participants.lagrange::<Secp256>(me)?;

let k_prime_i = lambda_me * k_i;
let e_i: Scalar = lambda_me * e_i;

let a_prime_i = lambda_me * a_i;
let b_prime_i = lambda_me * b_i;

let big_x: ProjectivePoint = args.keygen_out.public_key.to_element();
let private_share = args.keygen_out.private_share.to_scalar();
let x_prime_i = lambda_me * private_share;
``` [3](#0-2) 

The triple shares (`k_i`, `a_i`, `b_i`, `c_i`, `e_i`) are Shamir shares evaluated at participant indices for the **triple-generation** participant set. Applying Lagrange coefficients from a **different** participant set produces arithmetically incorrect linearized values. The presign protocol completes without error, but the resulting `PresignOutput` is cryptographically invalid. The error only surfaces in `sign.rs` at the final signature verification step:

```rust
// src/ecdsa/ot_based_ecdsa/sign.rs:129-132
if !sig.verify(&public_key, &msg_hash) {
    return Err(ProtocolError::AssertionFailed(
        "signature failed to verify".to_string(),
    ));
}
``` [4](#0-3) 

The sign phase also applies Lagrange coefficients again using the sign participant set:

```rust
// src/ecdsa/ot_based_ecdsa/sign.rs:148-153
let lambda = participants.lagrange::<Secp256K1Sha256>(me)?;
let k_i = lambda * presignature.k;
let sigma_i = lambda * presignature.sigma;
``` [5](#0-4) 

If the presign participant set differed from the triple-generation participant set, the shares in `presignature.k` and `presignature.sigma` are already corrupted by wrong Lagrange coefficients, and double-linearizing them produces an invalid signature.

---

### Impact Explanation

This matches **High: Corruption of presign outputs so honest parties accept inconsistent participant sets or unusable cryptographic outputs.** All honest participants complete the presign protocol without any error, accepting the output as valid. The corruption is silent and only detected later during signing, permanently wasting the consumed triples (which must never be reused) and denying the signing operation for that session.

---

### Likelihood Explanation

The `presign` public API accepts arbitrary `participants` and `PresignArguments`. A malicious coordinator, or any caller who controls protocol initialization, can pass a participant set that differs from `args.triple0.1.participants` while keeping the threshold equal (the only check performed). This requires no cryptographic capability — only the ability to call `presign` with mismatched inputs, which is a normal caller privilege. The `TriplePub.participants` field exists precisely to enable this check, making the omission a clear gap.

---

### Recommendation

In `presign`, after constructing the `ParticipantList`, add an explicit check that the presign participant set matches the participant set recorded in both triples:

```rust
// After line 50 in presign.rs
if participants.as_slice() != args.triple0.1.participants.as_slice() {
    return Err(InitializationError::BadParameters(
        "Presign participant set must match triple0 participant set".to_string(),
    ));
}
if participants.as_slice() != args.triple1.1.participants.as_slice() {
    return Err(InitializationError::BadParameters(
        "Presign participant set must match triple1 participant set".to_string(),
    ));
}
```

This mirrors the threshold check already present at line 43 and closes the participant-set mismatch gap that the existing comment acknowledges but leaves unguarded.

---

### Proof of Concept

1. Generate triples for participant set `P1 = {A, B, C, D}` with threshold 2 using `generate_triple`.
2. Call `presign` with participant set `P2 = {A, B, C}` (same threshold, different set) and the triples from step 1.
3. Observe that `presign` returns `Ok(protocol)` and all participants complete the protocol without error, each holding a `PresignOutput`.
4. Call `sign` with the resulting presignatures.
5. Observe that `sign` returns `ProtocolError::AssertionFailed("signature failed to verify")` because the Lagrange linearization in presign used coefficients for `P2` applied to shares generated for `P1`, producing arithmetically incorrect `k` and `sigma` values.
6. The triples are now consumed and cannot be reused, permanently denying this signing session. [2](#0-1) [1](#0-0)

### Citations

**File:** src/ecdsa/ot_based_ecdsa/triples/mod.rs (L57-65)
```rust
pub struct TriplePub {
    pub big_a: AffinePoint,
    pub big_b: AffinePoint,
    pub big_c: AffinePoint,
    /// The participants in generating this triple.
    pub participants: Vec<Participant>,
    /// The threshold which will be able to reconstruct it.
    pub threshold: ReconstructionLowerBound,
}
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L38-47)
```rust
    // NOTE: We omit the check that the new participant set was present for
    // the triple generation, because presumably they need to have been present
    // in order to have shares.

    // Also check that we have enough participants to reconstruct shares.
    if args.threshold != args.triple0.1.threshold || args.threshold != args.triple1.1.threshold {
        return Err(InitializationError::BadParameters(
            "New threshold must match the threshold of both triples".to_string(),
        ));
    }
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L93-103)
```rust
    let lambda_me = participants.lagrange::<Secp256>(me)?;

    let k_prime_i = lambda_me * k_i;
    let e_i: Scalar = lambda_me * e_i;

    let a_prime_i = lambda_me * a_i;
    let b_prime_i = lambda_me * b_i;

    let big_x: ProjectivePoint = args.keygen_out.public_key.to_element();
    let private_share = args.keygen_out.private_share.to_scalar();
    let x_prime_i = lambda_me * private_share;
```

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L129-132)
```rust
    if !sig.verify(&public_key, &msg_hash) {
        return Err(ProtocolError::AssertionFailed(
            "signature failed to verify".to_string(),
        ));
```

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L148-153)
```rust
    let lambda = participants.lagrange::<Secp256K1Sha256>(me)?;
    let k_i = lambda * presignature.k;

    // Linearize sigmai
    // Spec 1.2
    let sigma_i = lambda * presignature.sigma;
```
