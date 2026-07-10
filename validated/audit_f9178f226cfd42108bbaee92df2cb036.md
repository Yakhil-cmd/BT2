### Title
Presign Participant-Set Mismatch Produces Corrupted Outputs Accepted by Honest Parties — (`src/ecdsa/ot_based_ecdsa/presign.rs`)

---

### Summary

The OT-based ECDSA presign function explicitly omits the check that the participant set supplied to `presign` matches the participant set that was used during Beaver triple generation. A malicious coordinator can invoke `presign` with a different participant set than the one used to generate the triples, causing all honest participants to compute Lagrange-weighted shares against the wrong basis. The resulting `PresignOutput` is cryptographically corrupted but is accepted by every honest party as valid. The consumed triple shares cannot be recovered, permanently denying signing for those honest parties.

---

### Finding Description

In `src/ecdsa/ot_based_ecdsa/presign.rs`, the `presign` entry-point performs several initialization checks (threshold bounds, duplicate participants, self-membership), but it explicitly skips the check that the presign participant set was the same set that participated in triple generation: [1](#0-0) 

```rust
// NOTE: We omit the check that the new participant set was present for
// the triple generation, because presumably they need to have been present
// in order to have shares.
```

Immediately after, `do_presign` computes Lagrange coefficients for the **presign** participant set: [2](#0-1) 

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

The triple shares `k_i`, `a_i`, `b_i`, `c_i` are Shamir shares defined over the **triple-generation** participant set P₁. Their Lagrange coefficients λᵢ^P₁ are baked into the shares' reconstruction property. When `presign` is called with a different participant set P₂, the code computes λᵢ^P₂ instead, so:

```
SUM_i(λᵢ^P₂ · k_i)  ≠  k
```

The reconstructed nonce `k`, the blinded value `w = k·a + b`, and the public nonce `R = k·G` are all wrong. The protocol completes without error because there is no cross-check against the triple's participant set — `TriplePub` stores only a `threshold` field, not the participant list: [3](#0-2) 

```rust
if args.threshold != args.triple0.1.threshold || args.threshold != args.triple1.1.threshold {
    return Err(InitializationError::BadParameters(
        "New threshold must match the threshold of both triples".to_string(),
    ));
}
```

Only the threshold scalar is compared; the participant identity set is never validated. Every honest participant finishes `do_presign`, receives a `PresignOutput`, and considers the presign session successful — but the output is cryptographically invalid.

---

### Impact Explanation

**High — Corruption of presign outputs so honest parties accept unusable cryptographic outputs; permanent denial of signing.**

- Every honest participant completes the presign protocol and stores a `PresignOutput` that appears well-formed but encodes an incorrect nonce `k` and blinded value `w`.
- Any subsequent signing attempt using this output will produce an invalid ECDSA signature (wrong `r = R.x mod n`, wrong `s`).
- The triple shares consumed during presign are single-use and are now spent. There is no recovery path: the honest parties have permanently lost those triples and cannot produce a valid signature for the intended signing session.
- This matches: **"Corruption of presign outputs so honest parties accept unusable cryptographic outputs"** and **"Permanent denial of signing for honest parties under valid protocol inputs."**

---

### Likelihood Explanation

The `presign` public API accepts `participants: &[Participant]` and `PresignArguments { triple0, triple1, keygen_out, threshold }` as independent inputs with no binding between them. A malicious coordinator who controls which participant list is passed to each party's `presign` call can trivially supply a list that differs from the triple-generation list (e.g., a strict subset, or a set with one participant swapped). All honest participants will follow the protocol to completion and accept the corrupted output. No cryptographic break or key leakage is required — only the ability to call the library's public API with mismatched arguments.

---

### Recommendation

1. **Bind the participant set to the triple at generation time.** Add a participant-set commitment (e.g., a sorted hash of participant identifiers) to `TriplePub` during `generate_triple`, and verify in `presign` that the presign participant set produces the same commitment.

2. **Enforce exact participant-set equality.** Until `TriplePub` carries a participant commitment, add a runtime assertion that the presign participant set is identical (same members, same order) to the set used for triple generation, passed explicitly by the caller.

3. **Remove or harden the omission comment.** The current comment ("presumably they need to have been present") is an assumption, not a guarantee. The library's public API does not enforce this invariant, so it must be enforced inside `presign`.

---

### Proof of Concept

```
// Triple generation with participant set P1 = {A, B, C, D, E}, threshold 3
let (pub0, shares0) = deal(&mut rng, &[A, B, C, D, E], threshold).unwrap();
let (pub1, shares1) = deal(&mut rng, &[A, B, C, D, E], threshold).unwrap();

// Malicious coordinator initiates presign with P2 = {A, B, C} — a different set
// All of A, B, C have shares (they were in P1), so no share-availability check fires.
// The omitted participant-set check means presign proceeds without error.
let protocol_A = presign(&[A, B, C], A, PresignArguments {
    triple0: (shares0[A], pub0.clone()),
    triple1: (shares1[A], pub1.clone()),
    keygen_out: keygen_out_A,
    threshold: 3.into(),
}).unwrap();
// ... same for B and C

// All three complete successfully and return PresignOutput.
// But lambda^{A,B,C} ≠ lambda^{A,B,C,D,E}, so:
//   k_reconstructed = SUM(lambda_i^{A,B,C} * k_i) ≠ k
//   R = k_reconstructed * G ≠ correct R
//   w = k_reconstructed * a + b ≠ correct w

// Subsequent signing with this presign output produces an invalid signature.
// Triple shares for A, B, C are permanently consumed — signing is denied.
```

### Citations

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L38-40)
```rust
    // NOTE: We omit the check that the new participant set was present for
    // the triple generation, because presumably they need to have been present
    // in order to have shares.
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L43-47)
```rust
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
