### Title
Presign Participant Set Not Validated Against Triple Generation Participant Set - (File: `src/ecdsa/ot_based_ecdsa/presign.rs`)

### Summary

The OT-based ECDSA `presign` function explicitly omits the check that the participant set passed to it matches the participant set recorded in `TriplePub` from triple generation. Because `TriplePub` stores the original participants but `presign` uses a caller-supplied participant list for Lagrange interpolation, a malicious coordinator can supply a mismatched participant set, causing the Lagrange coefficients to be computed over the wrong domain. This corrupts the presign computation and causes honest parties to abort, permanently denying signing.

### Finding Description

`TriplePub` records the exact participant set that generated the triple: [1](#0-0) 

The triple shares `(a_i, b_i, c_i)` are Shamir shares evaluated at each participant's scalar, with Lagrange reconstruction defined over that specific participant set. The invariant `a * b = c` holds only when reconstructed using Lagrange coefficients computed over the **triple generation** participant set.

The `presign` function, however, explicitly skips the consistency check: [2](#0-1) 

Inside `do_presign`, Lagrange coefficients are computed from the **presign** participant list, not from `args.triple0.1.participants` or `args.triple1.1.participants`: [3](#0-2) 

The `TriplePub.participants` field is never accessed anywhere in `do_presign`. The presign then checks: [4](#0-3) 

When the participant sets differ, `alpha` and `beta` are computed with wrong Lagrange coefficients, so `alpha*G ≠ K + A` and `beta*G ≠ X + B`, causing an abort. The `TriplePub` has all the information needed to perform this check but it is never consulted.

### Impact Explanation

A malicious coordinator orchestrates triple generation with participant set `{P1, P2, P3}` (threshold 2), then instructs honest parties `P1` and `P2` to run `presign` with participant set `{P1, P2}` while supplying the triple shares from the `{P1, P2, P3}` session. The Lagrange coefficients for `{P1, P2}` differ from those for `{P1, P2, P3}`, so the consistency check `alpha*G =?= K + A` fails and the presign aborts. Since the triple is consumed (one-time use), the honest parties cannot recover: the triple is spent and signing is permanently denied for that presignature slot. A persistent malicious coordinator can repeat this to exhaust all pre-generated triples, permanently blocking signing.

This matches: **High: Permanent denial of signing for honest parties under valid protocol inputs and documented trust assumptions** (malicious coordinator is an explicitly scoped attacker).

### Likelihood Explanation

The `presign` public API accepts arbitrary `participants` and `PresignArguments` independently. A malicious coordinator controls which participant list it tells each party to use when calling `presign`. No cryptographic capability is required — only the ability to supply a different participant list than was used during triple generation. The comment in the code confirms this check was intentionally omitted, meaning no defense exists at the library level.

### Recommendation

In `presign`, after constructing the `ParticipantList`, verify that it matches the participant list stored in both `TriplePub` values:

```rust
// Verify presign participants match triple generation participants
let triple0_participants = ParticipantList::new(&args.triple0.1.participants)
    .ok_or(InitializationError::DuplicateParticipants)?;
let triple1_participants = ParticipantList::new(&args.triple1.1.participants)
    .ok_or(InitializationError::DuplicateParticipants)?;

if participants.participants() != triple0_participants.participants()
    || participants.participants() != triple1_participants.participants()
{
    return Err(InitializationError::BadParameters(
        "presign participant set must match triple generation participant set".to_string(),
    ));
}
```

Remove the comment at lines 38–40 once this check is in place.

### Proof of Concept

1. Run triple generation with `{P0, P1, P2}` at threshold 2. Each party receives `(TripleShare, TriplePub)` where `TriplePub.participants = [P0, P1, P2]`.
2. A malicious coordinator tells `P0` and `P1` to call `presign(&[P0, P1], ...)` with the triple shares from step 1.
3. Inside `do_presign`, `lambda_me = participants.lagrange(me)` is computed over `{P0, P1}` — different Lagrange coefficients than `{P0, P1, P2}`.
4. `alpha = sum(lambda_{P0,P1}(Pi) * k_i + lambda_{P0,P1}(Pi) * a_i)` ≠ `k + a`.
5. The check `ProjectivePoint::GENERATOR * alpha != big_k + big_a` triggers `ProtocolError::AssertionFailed`.
6. The triple is consumed and cannot be reused. Signing is permanently denied for this presignature slot. [5](#0-4) [1](#0-0)

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

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L20-61)
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
