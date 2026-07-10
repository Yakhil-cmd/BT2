Based on my analysis of the code, here is my assessment:

---

### Title
Missing Participant-Set Consistency Check in `presign()` Enables Coordinator-Controlled Denial of Signing — (`src/ecdsa/ot_based_ecdsa/presign.rs`)

### Summary

`presign()` validates that both triples share the same threshold but never validates that they were generated for the same participant set, nor that the presign participant set is consistent with either triple's generation set. `TriplePub` already carries a `participants` field that makes this check trivially implementable, but the code explicitly omits it with a comment acknowledging the gap.

### Finding Description

`TriplePub` stores the participant set used during triple generation: [1](#0-0) 

The `presign()` initialization only checks threshold equality across both triples: [2](#0-1) 

The code explicitly omits the participant-set check with a comment whose reasoning is flawed: [3](#0-2) 

The reasoning "presumably they need to have been present in order to have shares" is incorrect: a malicious coordinator can fabricate or reassign shares from a triple generated for a different participant set.

Inside `do_presign()`, a single Lagrange coefficient over the **presign** participant set P_C is applied uniformly to shares from both triples: [4](#0-3) 

The Round 2 verification then checks: [5](#0-4) 

For `alpha*G == K+A` to hold, `SUM_{i∈P_C} λᵢ^{P_C} · kᵢ` must equal `k` (the secret embedded in triple0) **and** `SUM_{i∈P_C} λᵢ^{P_C} · aᵢ` must equal `a` (the secret embedded in triple1). This is only true if the shares were generated for a participant set that includes P_C. If triple0 was generated for P_A and triple1 for P_B, and P_A ≠ P_B, then at least one of these sums will be wrong, causing the check to fail with `ProtocolError::AssertionFailed`.

### Impact Explanation

A malicious coordinator generates triple0 for P_A = {P1, P2, P3} and triple1 for P_B = {P1, P2, P4} (same threshold, different participant sets). It then distributes these mismatched triples to participants in P_C = {P1, P2, P3}. P3 receives a share of triple1 that is not a valid evaluation of triple1's underlying polynomial (since P3 ∉ P_B). The threshold check at lines 43–47 passes. `do_presign()` proceeds, applies Lagrange over P_C to both triples, and the aggregate `alpha` or `beta` fails the EC point check at lines 162–168. Every honest participant aborts with `ProtocolError::AssertionFailed`. The coordinator can repeat this indefinitely, permanently denying signing.

### Likelihood Explanation

The coordinator role controls which `PresignArguments` are delivered to each participant. The attack requires no cryptographic break — only the ability to supply mismatched `(TripleShare, TriplePub)` pairs, which is entirely within the coordinator's power. The data needed to prevent this (`TriplePub::participants`) is already present in the struct; the check is simply absent.

### Recommendation

In `presign()`, after the threshold check, add:

1. `args.triple0.1.participants == args.triple1.1.participants` — both triples must have been generated for the same participant set.
2. The presign `participants` slice must be a subset of (or equal to) `args.triple0.1.participants` — the presign session must be drawn from the triple generation set.

Both checks are O(n) and use data already present in `TriplePub`.

### Proof of Concept

Using the existing `deal` helper (test-only but structurally identical to `generate_triple`):

```rust
// triple0 for [P1, P2, P3], triple1 for [P1, P2, P4], presign with [P1, P2, P3]
let pa = [P1, P2, P3];
let pb = [P1, P2, P4];
let (pub0, shares0) = deal(&mut rng, &pa, 2.into()).unwrap();
let (pub1, shares1) = deal(&mut rng, &pb, 2.into()).unwrap();

// Coordinator gives P3 a share of triple1 that was generated for P4's slot
// (or any fabricated value — P3 has no legitimate triple1 share)
let protocol = presign(&pa, P3, PresignArguments {
    triple0: (shares0[2].clone(), pub0.clone()),
    triple1: (shares1[2].clone(), pub1.clone()), // shares1[2] is P4's share, not P3's
    keygen_out: ...,
    threshold: 2.into(),
}).unwrap();
// run_protocol → ProtocolError::AssertionFailed at Round 2 verification
```

The threshold check passes (both triples have threshold 2). The protocol aborts at the `alpha*G != K+A` or `beta*G != X+B` check at line 162, permanently denying signing for all honest participants.

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

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L93-99)
```rust
    let lambda_me = participants.lagrange::<Secp256>(me)?;

    let k_prime_i = lambda_me * k_i;
    let e_i: Scalar = lambda_me * e_i;

    let a_prime_i = lambda_me * a_i;
    let b_prime_i = lambda_me * b_i;
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L162-168)
```rust
    if (ProjectivePoint::GENERATOR * alpha != big_k + big_a)
        || (ProjectivePoint::GENERATOR * beta != big_x + big_b)
    {
        return Err(ProtocolError::AssertionFailed(
            "received incorrect shares of additive triple phase.".to_string(),
        ));
    }
```
