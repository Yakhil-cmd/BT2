### Title
Participant-Set Mismatch Between Triple Generation and Presigning Produces Silently Corrupted Presignatures - (File: src/ecdsa/ot_based_ecdsa/presign.rs)

---

### Summary

The OT-based ECDSA presigning protocol explicitly omits any check that the participant set supplied to `presign()` matches the participant set used during triple generation. Because Lagrange coefficients are participant-set-dependent, a mismatch silently produces a cryptographically invalid presignature that honest parties accept as a valid protocol output but that cannot yield a correct signature.

---

### Finding Description

Beaver triples are generated with a specific participant set. Each participant's share `(a_i, b_i, c_i)` is a polynomial evaluation whose Lagrange linearization is meaningful only relative to the exact set of participants present at generation time.

During presigning, `do_presign()` immediately linearizes every triple share using the Lagrange coefficient of the **current** participant set:

```rust
// src/ecdsa/ot_based_ecdsa/presign.rs, lines 93-103
let lambda_me = participants.lagrange::<Secp256>(me)?;

let k_prime_i = lambda_me * k_i;
let e_i: Scalar = lambda_me * e_i;

let a_prime_i = lambda_me * a_i;
let b_prime_i = lambda_me * b_i;
...
let x_prime_i = lambda_me * private_share;
``` [1](#0-0) 

The only cross-check performed before entering `do_presign()` is that the **threshold** value matches the triples:

```rust
// src/ecdsa/ot_based_ecdsa/presign.rs, lines 43-47
if args.threshold != args.triple0.1.threshold || args.threshold != args.triple1.1.threshold {
    return Err(InitializationError::BadParameters(
        "New threshold must match the threshold of both triples".to_string(),
    ));
}
``` [2](#0-1) 

The participant set itself is never verified. The code even documents this omission explicitly:

```rust
// NOTE: We omit the check that the new participant set was present for
// the triple generation, because presumably they need to have been present
// in order to have shares.
``` [3](#0-2) 

`TriplePub` stores only `threshold`, `big_a`, `big_b`, and `big_c` — it carries no record of the participant set used at generation time, so no runtime comparison is possible: [4](#0-3) 

This is the direct analog of the LiquidityGauge bug: just as `totalSupply` changes between when a user's bonus percentage is fixed and when it is applied, the participant set can change between triple generation and presigning — and neither protocol layer detects or compensates for the change.

---

### Impact Explanation

If the participant set at presign time differs from the one at triple-generation time (even with the same threshold, e.g., `{P1,P2,P3,P4}` → `{P1,P2,P3}`), the Lagrange coefficients `lambda_me` computed in `do_presign()` are wrong for the stored shares. The resulting `alpha`, `beta`, `sigma`, and `big_r` values are arithmetically inconsistent with the actual secret key and nonce. Honest participants complete the protocol without error and receive a `PresignOutput` they believe is valid, but any subsequent signing step will produce an invalid ECDSA signature. This constitutes:

> **High: Corruption of presign outputs so honest parties accept inconsistent or unusable cryptographic outputs.**

---

### Likelihood Explanation

The attack requires a malicious coordinator or a misconfigured caller who:
1. Generates triples with participant set `P_old`.
2. Invokes `presign()` with a different participant set `P_new` that has the same threshold (so the only guard passes).

This is a realistic scenario in any deployment where participant sets can change (e.g., after a reshare) and pre-generated triples are reused. The library's own comment acknowledges the check is omitted, confirming the gap is known and unguarded.

---

### Recommendation

1. **Short term**: Record the participant set (or a deterministic hash of it) inside `TriplePub` at generation time. In `presign()`, compare the stored participant set against the supplied `participants` slice and return `InitializationError::BadParameters` on mismatch.

2. **Long term**: Document clearly that triples are bound to a specific participant set and must not be reused across reshares or participant-set changes. Add an integration test that asserts presigning with a mismatched participant set is rejected.

---

### Proof of Concept

```
1. Generate triples with participants = {P1, P2, P3, P4}, threshold = 3.
   → Each triple share (a_i, b_i, c_i) is a degree-2 polynomial evaluation
     whose Lagrange reconstruction requires the 4-element set.

2. Perform a reshare that removes P4, yielding participants = {P1, P2, P3}.

3. Call presign() with participants = {P1, P2, P3}, threshold = 3,
   supplying the triples from step 1.
   → The threshold check (line 43) passes because threshold is still 3.
   → do_presign() computes lambda_me for the 3-element set {P1,P2,P3}.
   → k_prime_i = lambda_{P1,{P1,P2,P3}} * k_i  ≠  lambda_{P1,{P1,P2,P3,P4}} * k_i

4. All participants complete do_presign() without error and receive PresignOutput.

5. Signing with this PresignOutput produces an invalid ECDSA signature,
   permanently denying the ability to sign until new triples are generated.
``` [5](#0-4)

### Citations

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L20-62)
```rust
pub fn presign(
    participants: &[Participant],
    me: Participant,
    args: PresignArguments,
) -> Result<impl Protocol<Output = PresignOutput>, InitializationError> {
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }
    // Spec 1.1
    if args.threshold.value() > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: args.threshold.value(),
            max: participants.len(),
        });
    }

    // NOTE: We omit the check that the new participant set was present for
    // the triple generation, because presumably they need to have been present
    // in order to have shares.

    // Also check that we have enough participants to reconstruct shares.
    if args.threshold != args.triple0.1.threshold || args.threshold != args.triple1.1.threshold {
        return Err(InitializationError::BadParameters(
            "New threshold must match the threshold of both triples".to_string(),
        ));
    }

    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;

    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }

    let ctx = Comms::new();
    let fut = do_presign(ctx.shared_channel(), participants, me, args);
    Ok(make_protocol(ctx, fut))
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

**File:** src/ecdsa/ot_based_ecdsa/mod.rs (L24-34)
```rust
pub struct PresignArguments {
    /// The first triple's public information, and our share.
    pub triple0: (TripleShare, TriplePub),
    /// Ditto, for the second triple.
    pub triple1: (TripleShare, TriplePub),
    /// The output of key generation, i.e. our share of the secret key, and the public key package.
    /// This is of type `KeygenOutput<Secp256K1Sha256>` from Frost implementation
    pub keygen_out: KeygenOutput,
    /// The desired threshold for the presignature, which must match the original threshold
    pub threshold: ReconstructionLowerBound,
}
```
