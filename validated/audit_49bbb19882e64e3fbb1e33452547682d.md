### Title
Mismatched Threshold Between Triple Generation and Presigning Permanently Blocks OT-Based ECDSA Signing — (`File: src/ecdsa/ot_based_ecdsa/presign.rs`)

---

### Summary

The OT-based ECDSA `presign` function enforces an exact equality between the caller-supplied presign threshold (`args.threshold`) and the threshold embedded in each Beaver triple (`triple.threshold`). These two values are set independently at different points in the pipeline. If they diverge — for example, after a reshare that changes the threshold — every presigning call fails with `InitializationError::BadParameters`, permanently blocking signing until new triples are regenerated. There is no cross-validation between the keygen threshold and the triple threshold at any point in the pipeline.

---

### Finding Description

In `src/ecdsa/ot_based_ecdsa/presign.rs`, the public `presign` function performs the following check:

```rust
// Also check that we have enough participants to reconstruct shares.
if args.threshold != args.triple0.1.threshold || args.threshold != args.triple1.1.threshold {
    return Err(InitializationError::BadParameters(
        "New threshold must match the threshold of both triples".to_string(),
    ));
}
``` [1](#0-0) 

The triple threshold is fixed at generation time and stored inside `TriplePub`:

```rust
pub struct PresignArguments {
    pub triple0: (TripleShare, TriplePub),
    pub triple1: (TripleShare, TriplePub),
    pub keygen_out: KeygenOutput,
    pub threshold: ReconstructionLowerBound,  // independently supplied
}
``` [2](#0-1) 

The `TriplePub.threshold` is written once during `generate_triple` / `generate_triple_many` and is immutable thereafter: [3](#0-2) 

The `KeygenOutput` type stores only the private share and public key — **no threshold is recorded**: [4](#0-3) 

Consequently, the pipeline has **three independently configurable threshold values** with no cross-validation:

| Value | Set by | Validated against |
|---|---|---|
| `keygen` threshold | `keygen()` caller | Nothing |
| `triple.threshold` | `generate_triple()` caller | `args.threshold` only |
| `args.threshold` | `presign()` caller | `triple.threshold` only |

If a reshare changes the threshold from `T_old` to `T_new`, the operator must regenerate all triples. If they instead call `presign` with `args.threshold = T_new` while still holding triples stamped with `T_old`, the equality check at line 43 always fails and **every presigning call is rejected** until new triples are produced.

---

### Impact Explanation

**High — Permanent denial of signing for honest parties under valid protocol inputs.**

The OT-based ECDSA signing pipeline is three-phase: triple generation → presigning → signing. Presigning is the gateway to signing. If presigning is blocked, no signatures can be produced. The block persists until the operator regenerates all triples with the new threshold — a multi-round (11+) interactive protocol that requires all participants to be online simultaneously. During this window, signing is completely unavailable. The error is returned at initialization before any network communication, so the triples are not consumed, but the signing session is aborted for all participants.

---

### Likelihood Explanation

**Medium.** The scenario arises naturally in any deployment that:
1. Performs a reshare to change the threshold (a documented, supported operation via `reshare()`), and
2. Reuses pre-generated triples from before the reshare.

There is no warning, documentation, or runtime guard that prevents this combination. A malicious coordinator can also trigger this deliberately by instructing participants to run presign with a threshold value that does not match their stored triples, causing a coordinated denial of signing across all participants.

---

### Recommendation

1. **Store the threshold in `KeygenOutput`** so it can be compared against `args.threshold` and `triple.threshold` at presign initialization.
2. **Add a cross-validation check** in `presign()` that asserts `args.threshold == args.keygen_out.threshold == args.triple0.1.threshold == args.triple1.1.threshold`, returning a clear error if any of these diverge.
3. **Document explicitly** that all triples must be regenerated after any reshare that changes the threshold, and consider adding a helper that enforces this invariant.

---

### Proof of Concept

```
1. Run keygen with threshold T=2, participants [P1, P2, P3].
2. Generate triples with threshold T=2 → TriplePub.threshold = 2.
3. Run reshare to change threshold to T'=3, participants [P1, P2, P3, P4].
4. Call presign() with args.threshold = 3 (new threshold) and the old triples (threshold=2).
5. Line 43 evaluates: 3 != 2 → InitializationError::BadParameters is returned.
6. Every participant's presign call fails identically.
7. Signing is blocked until new triples are generated with threshold=3.
```

The root cause is at: [1](#0-0) 

with the independently-set triple threshold originating at: [5](#0-4) 

and no keygen-threshold cross-check anywhere in: [6](#0-5)

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

**File:** src/ecdsa/ot_based_ecdsa/mod.rs (L23-34)
```rust
#[derive(Debug, Clone)]
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

**File:** src/ecdsa/ot_based_ecdsa/mod.rs (L36-49)
```rust
/// The output of the presigning protocol.
///
/// This output is basically all the parts of the signature that we can perform
/// without knowing the message.
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

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L660-668)
```rust
            },
            TriplePub {
                big_a,
                big_b,
                big_c,
                participants: participants.clone().into(),
                threshold,
            },
        ));
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L681-708)
```rust
fn validate_triple_inputs(
    participants: &[Participant],
    threshold: impl Into<ReconstructionLowerBound>,
) -> Result<(ParticipantList, ReconstructionLowerBound), InitializationError> {
    let threshold = threshold.into();
    let threshold_value = threshold.value();
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }
    // Spec 1.1
    if threshold_value > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: threshold_value,
            max: participants.len(),
        });
    }
    if threshold_value < 2 {
        return Err(InitializationError::ThresholdTooSmall {
            threshold: threshold_value,
            min: 2,
        });
    }
    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;
    Ok((participants, threshold))
}
```
