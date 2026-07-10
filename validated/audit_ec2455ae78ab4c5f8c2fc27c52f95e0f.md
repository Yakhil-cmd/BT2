### Title
Presign Participant Set Not Validated Against Triple Generation Participants, Causing Corrupted Presignatures - (File: `src/ecdsa/ot_based_ecdsa/presign.rs`)

### Summary

The OT-based ECDSA `presign()` function validates that the caller-supplied `threshold` matches the threshold embedded in both `TriplePub` structs, but explicitly omits checking that the presign `participants` slice matches the `participants` field stored inside each `TriplePub`. Because Lagrange linearization during presigning uses the presign participant set rather than the triple-generation participant set, any mismatch silently produces a cryptographically invalid presignature that can never yield a valid signature, permanently denying signing for honest parties.

### Finding Description

**Root cause — missing participant-set cross-check**

`TriplePub` records both the threshold and the exact participant set that was present during triple generation: [1](#0-0) 

The `presign()` initializer checks that the caller-supplied threshold matches the triple's threshold, but the code contains an explicit comment acknowledging that the participant-set check is omitted: [2](#0-1) 

No code anywhere in `presign()` or `do_presign()` compares `participants` against `args.triple0.1.participants` or `args.triple1.1.participants`.

**How the mismatch corrupts the presignature**

Inside `do_presign`, every triple share is linearized using Lagrange coefficients computed from the *presign* participant set: [3](#0-2) 

The triple shares `(k_i, e_i, a_i, b_i, c_i)` are polynomial evaluations at participant indices chosen during *triple generation* (participant set P₀). When the presign participant set P₁ ≠ P₀, the Lagrange coefficients `λ(P₁)_i` are wrong for those shares. The sum `Σ λ(P₁)_i · f_k(pᵢ)` does not reconstruct `f_k(0) = k`, so `R = (1/e)·D` is computed from an incorrect `e`, and `σ_i = α·xᵢ − β·aᵢ + cᵢ` is computed from incorrect `α`, `β`. The returned `PresignOutput { big_r, k, sigma }` is cryptographically invalid.

**Attacker-controlled entry path**

A malicious coordinator (or any library caller who controls the orchestration layer) can:

1. Run triple generation with participant set P₀ = {p₁, …, pₙ}.
2. Instruct honest participants to call `presign()` with a different participant set P₁ ⊂ P₀ (e.g., drop one participant), while supplying the same `TriplePub` objects whose embedded `threshold` still matches.
3. The threshold check at line 43 passes; the participant-set check is absent.
4. Every honest participant computes wrong Lagrange coefficients, producing an invalid presignature.
5. At signing time the coordinator's final verification (`sig.verify`) fails: [4](#0-3) 

6. Because presignatures are one-time-use, the consumed triple pair and presignature are permanently lost, and the signing session cannot be retried with the same material.

### Impact Explanation

**High — Corruption of presign outputs causing unusable cryptographic outputs / permanent denial of signing.**

Honest participants complete the presign protocol without error (all internal consistency checks such as `e·G == E` and `α·G == K+A` still pass because they depend only on the presign participant set being internally consistent, not on matching the triple's participant set). They accept and store a `PresignOutput` that is silently invalid. Every subsequent signing attempt using that presignature fails at the coordinator's signature-verification step. Because the presignature is one-time-use, the signing capability for that slot is permanently lost. Under a sustained attack, a malicious coordinator can exhaust the entire pre-generated presignature pool, achieving permanent denial of signing for honest parties.

### Likelihood Explanation

The coordinator role is explicitly part of the protocol model. The library exposes `presign()` as a public API that accepts caller-supplied `participants` and `PresignArguments` independently, with no binding between them beyond the threshold scalar. Any orchestration layer that allows the coordinator to choose the presign participant set (which is the normal operational model) is exposed. The omission is acknowledged in a code comment, indicating it is a known gap rather than an oversight that might be caught in review.

### Recommendation

Add an explicit check in `presign()` that the presign participant set matches the participant set recorded in both `TriplePub` values:

```rust
// After building `participants` (ParticipantList):
let presign_participants: Vec<Participant> = participants.iter().collect();
if presign_participants != args.triple0.1.participants
    || presign_participants != args.triple1.1.participants
{
    return Err(InitializationError::BadParameters(
        "Presign participant set must exactly match the participant set \
         used during triple generation".to_string(),
    ));
}
```

This mirrors the existing threshold check and closes the gap identified in the comment at line 38–40 of `src/ecdsa/ot_based_ecdsa/presign.rs`.

### Proof of Concept

```
1. Run generate_triple(P0={A,B,C,D}, threshold=2) → (TriplePub{participants=[A,B,C,D], threshold=2}, shares)
2. Call presign(participants=[A,B,C], me=A, PresignArguments{
       triple0: (shares_A_from_P0, TriplePub{participants=[A,B,C,D], threshold=2}),
       triple1: (shares_A_from_P0, TriplePub{participants=[A,B,C,D], threshold=2}),
       threshold: 2,
   })
   → threshold check passes (2 == 2), participant check absent → protocol runs
3. do_presign computes lambda_A = lagrange([A,B,C], A) ≠ lagrange([A,B,C,D], A)
   → k'_A, e_A, a'_A, b'_A, x'_A all wrong
   → e = Σ e_j ≠ actual kd product → R = (1/e)·D is wrong
   → PresignOutput{big_r=R_wrong, k=k_A_wrong, sigma=sigma_A_wrong} returned without error
4. sign() → coordinator computes s, verifies (R_wrong, s) against public key → AssertionFailed
5. Presignature consumed; signing permanently denied for this slot.
```

### Citations

**File:** src/ecdsa/ot_based_ecdsa/triples/mod.rs (L56-65)
```rust
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
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

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L92-103)
```rust
    // Spec 1.1
    let lambda_me = participants.lagrange::<Secp256>(me)?;

    let k_prime_i = lambda_me * k_i;
    let e_i: Scalar = lambda_me * e_i;

    let a_prime_i = lambda_me * a_i;
    let b_prime_i = lambda_me * b_i;

    let big_x: ProjectivePoint = args.keygen_out.public_key.to_element();
    let private_share = args.keygen_out.private_share.to_scalar();
    let x_prime_i = lambda_me * private_share;
```

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L129-133)
```rust
    if !sig.verify(&public_key, &msg_hash) {
        return Err(ProtocolError::AssertionFailed(
            "signature failed to verify".to_string(),
        ));
    }
```
