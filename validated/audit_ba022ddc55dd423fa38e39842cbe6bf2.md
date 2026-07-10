### Title
Missing Participant-Set Consistency Check Between Triple Generation and Presigning Allows Corrupted Presignature Output - (File: src/ecdsa/ot_based_ecdsa/presign.rs)

### Summary

The OT-based ECDSA `presign` function accepts Beaver triples that may have been generated under a different participant set than the one currently used for presigning. Because Lagrange coefficients are computed over the *presigning* participant set rather than the *triple-generation* participant set, the resulting presignature shares (`sigma_i`) are cryptographically incorrect, producing unusable presignatures that cause all subsequent signing attempts to fail.

### Finding Description

In `src/ecdsa/ot_based_ecdsa/presign.rs`, the `presign` entry-point validates that the threshold of the supplied triples matches the presigning threshold, but explicitly skips the check that the participant set used during triple generation matches the participant set used during presigning:

```rust
// NOTE: We omit the check that the new participant set was present for
// the triple generation, because presumably they need to have been present
// in order to have shares.
``` [1](#0-0) 

The only consistency check performed is on the threshold scalar:

```rust
if args.threshold != args.triple0.1.threshold || args.threshold != args.triple1.1.threshold {
    return Err(InitializationError::BadParameters(...));
}
``` [2](#0-1) 

Inside `do_presign`, Lagrange coefficients are computed exclusively over the *current* presigning participant set:

```rust
let lambda_me = participants.lagrange::<Secp256>(me)?;
let k_prime_i = lambda_me * k_i;
``` [3](#0-2) 

The triple shares `k_i`, `a_i`, `b_i`, `c_i`, `e_i` are polynomial evaluations that were committed to and verified against the *triple-generation* participant set. When the presigning participant set differs (e.g., after a reshare, a participant is added or removed, or a malicious coordinator supplies triples from a prior session), the Lagrange basis changes. The linearized shares `k_prime_i`, `a_prime_i`, `b_prime_i`, `x_prime_i` no longer sum to the correct aggregate secrets across participants. Consequently, the final presignature value:

```rust
let sigma_i = alpha * private_share - (beta * a_i - c_i);
``` [4](#0-3) 

is computed from inconsistent intermediate values (`alpha`, `beta`) that do not satisfy the required algebraic relations, producing a structurally invalid `PresignOutput`. The `PresignOutput` struct carries no binding to the participant set or keygen session under which it was produced: [5](#0-4) 

so callers cannot detect the mismatch after the fact.

### Impact Explanation

**Impact: High**

Honest parties complete the presign protocol without error (the algebraic consistency checks at lines 127 and 162 may still pass if the mismatch is subtle, or the protocol aborts with a `ProtocolError` that is indistinguishable from a network fault). Either way, the presignature is unusable: the subsequent `sign` phase will produce an invalid ECDSA signature that fails on-chain or at the verifier. Because presignatures are consumed on use and cannot be regenerated without fresh triples, this constitutes a **permanent denial of signing** for the affected signing session. If a malicious coordinator repeatedly supplies mismatched triples, every presigning session can be silently poisoned, permanently blocking honest parties from producing valid signatures.

This maps to the allowed impact: **High — Corruption of presign outputs so honest parties accept unusable cryptographic outputs**.

### Likelihood Explanation

**Likelihood: Medium**

The attack is reachable by a malicious coordinator, who controls which triple public parameters (`TriplePub`) are broadcast to participants. A coordinator can supply a `TriplePub` from a prior triple-generation session (different participant set, same threshold) while directing participants to run presigning with a new participant set. Participants have no way to detect the mismatch because the omitted check is the only place where participant-set binding would be enforced. The scenario also arises non-maliciously after a reshare or refresh: a developer who reuses cached triples with the post-reshare participant set will silently corrupt presignatures.

### Recommendation

1. **Bind triples to their participant set at generation time.** Store the sorted participant list (or a collision-resistant hash of it) inside `TriplePub` alongside the existing `threshold` field.
2. **Enforce consistency in `presign`.** Replace the omitted check with an explicit assertion that the participant set supplied to `presign` matches the participant set recorded in both `TriplePub` values.
3. **Alternatively**, document the invariant as a hard precondition in the public API and add a `debug_assert!` so that violations are caught in testing.

### Proof of Concept

1. Run triple generation with participants `{A, B, C, D}` at threshold 2, producing `(TripleShare, TriplePub)` for each.
2. Perform a reshare that removes participant `D`, yielding a new participant set `{A, B, C}` with the same threshold 2.
3. Call `presign(&[A, B, C], me, PresignArguments { triple0: (share_A_old, pub_old), triple1: ..., keygen_out: new_keygen_out, threshold: 2 })`.
4. The threshold check at line 43 passes (both are 2). No participant-set check is performed.
5. `do_presign` computes `lambda_me` over `{A, B, C}` (3-party Lagrange basis), but `k_i`, `a_i`, etc. are evaluations of polynomials committed under the 4-party basis `{A, B, C, D}`.
6. The resulting `alpha` and `beta` aggregates do not satisfy `alpha·G = K + A` or `beta·G = X + B` under the new basis, causing either an `AssertionFailed` abort (denial of signing) or — if the check is bypassed — a structurally invalid `sigma_i` that produces an invalid final signature. [6](#0-5) [7](#0-6)

### Citations

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

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L93-95)
```rust
    let lambda_me = participants.lagrange::<Secp256>(me)?;

    let k_prime_i = lambda_me * k_i;
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L159-168)
```rust
    // alpha*G =?= K + A
    // beta*G =?= X + B
    // Spec 2.5
    if (ProjectivePoint::GENERATOR * alpha != big_k + big_a)
        || (ProjectivePoint::GENERATOR * beta != big_x + big_b)
    {
        return Err(ProtocolError::AssertionFailed(
            "received incorrect shares of additive triple phase.".to_string(),
        ));
    }
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L179-179)
```rust
    let sigma_i = alpha * private_share - (beta * a_i - c_i);
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L181-185)
```rust
    Ok(PresignOutput {
        big_r,
        k: k_i,
        sigma: sigma_i,
    })
```
