### Title
Missing Minimum Threshold Validation in FROST Signing and OT-Based ECDSA Sign Allows Single-Participant Signature — (`src/frost/mod.rs`, `src/ecdsa/ot_based_ecdsa/sign.rs`)

---

### Summary

`assert_sign_inputs` and `presign` in `src/frost/mod.rs`, and `sign` in `src/ecdsa/ot_based_ecdsa/sign.rs`, accept a `threshold` parameter without enforcing the minimum lower bound of `2`. The DKG entry point `assert_key_invariants` in `src/dkg.rs` explicitly enforces `threshold >= 2`, but the signing-phase entry points omit this check. A caller can pass `threshold = 1` (or `threshold = 0`) to the signing functions, collapsing the t-of-n security guarantee to a 1-of-n scheme and allowing a single participant to unilaterally produce a valid threshold signature.

---

### Finding Description

`assert_key_invariants` in `src/dkg.rs` enforces a minimum threshold of 2:

```rust
// src/dkg.rs lines 580-582
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
``` [1](#0-0) 

However, `assert_sign_inputs` in `src/frost/mod.rs` only checks the upper bound (`threshold > participants.len()`) and never checks the lower bound:

```rust
// src/frost/mod.rs lines 144-150
// validate threshold
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ← no check for threshold < 2
``` [2](#0-1) 

`frost::presign` has the same gap — it checks only the upper bound:

```rust
// src/frost/mod.rs lines 71-77
if args.threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ← no check for threshold < 2
``` [3](#0-2) 

`ot_based_ecdsa::sign` in `src/ecdsa/ot_based_ecdsa/sign.rs` similarly only checks `participants.len() < threshold` (upper-bound direction) and never rejects `threshold = 1` or `threshold = 0`:

```rust
// src/ecdsa/ot_based_ecdsa/sign.rs lines 57-63
if participants.len() < threshold {
    return Err(InitializationError::NotEnoughParticipantsForThreshold { ... });
}
// ← no check for threshold < 2
``` [4](#0-3) 

`ReconstructionLowerBound` is a plain `usize` newtype with no internal invariant enforcing a minimum: [5](#0-4) 

---

### Impact Explanation

In FROST, the `threshold` value passed to `assert_sign_inputs` and `presign` controls how many participants' nonce commitments and signature shares are required for a valid aggregate signature. With `threshold = 1`, the protocol requires only a single participant's share to reconstruct a complete, verifiable signature. A single malicious participant can therefore:

1. Call `frost::presign` with `threshold = 1` and a valid `KeygenOutput`.
2. Call the FROST sign function (via `eddsa` or `redjubjub`) with `threshold = 1`.
3. Produce a fully valid threshold signature unilaterally, without cooperation from any other participant.

This collapses the t-of-n security model to 1-of-n, constituting **unauthorized creation of a valid threshold signature for attacker-chosen inputs**.

For `ot_based_ecdsa::sign`, passing `threshold = 0` bypasses the `participants.len() < threshold` guard entirely (since any `len >= 0`), and the Lagrange linearization in `compute_signature_share` proceeds with the full participant set but with an unchecked threshold, potentially producing a valid signature with a single cooperating participant.

---

### Likelihood Explanation

The `threshold` parameter is caller-supplied at every signing invocation. Any library user — including a malicious participant acting as a coordinator — can pass an arbitrary `ReconstructionLowerBound` value. There is no type-level enforcement preventing `threshold = 1`. The attack requires no privileged access, no leaked keys, and no cryptographic break: it is a straightforward API misuse enabled by the missing lower-bound check.

---

### Recommendation

Add the same `threshold < 2` guard used in `assert_key_invariants` to both `assert_sign_inputs` and `frost::presign` in `src/frost/mod.rs`, and to `sign` in `src/ecdsa/ot_based_ecdsa/sign.rs`:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

Alternatively, enforce the invariant inside `ReconstructionLowerBound::new` (making the constructor fallible) so that no value below 2 can be constructed at all, eliminating the class of bug at the type level.

---

### Proof of Concept

1. Run DKG with `threshold = 2`, `participants = [P1, P2, P3]` — succeeds normally, producing `KeygenOutput` for each participant.
2. Participant P1 (malicious) calls `frost::presign` with `threshold = 1` and their own `KeygenOutput`. The check at line 72 passes because `1 <= 3`. No lower-bound check fires.
3. P1 calls the FROST sign function with `threshold = 1`. `assert_sign_inputs` passes at line 145 because `1 <= 3`. No lower-bound check fires.
4. With `threshold = 1`, the FROST aggregation requires only P1's own signature share. P1 produces a complete, valid EdDSA/RedDSA signature over an attacker-chosen message without any cooperation from P2 or P3.
5. The resulting signature verifies correctly against the group public key established during DKG. [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** src/dkg.rs (L558-596)
```rust
pub fn assert_key_invariants(
    participants: &[Participant],
    me: Participant,
    threshold: impl Into<ReconstructionLowerBound>,
) -> Result<ParticipantList, InitializationError> {
    let threshold = usize::from(threshold.into());
    // need enough participants
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }

    // Step 1.1
    // validate threshold
    if threshold > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold,
            max: participants.len(),
        });
    }
    // Step 1.1
    if threshold < 2 {
        return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
    }

    // ensure uniqueness of participants in the participant list
    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;

    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }
    Ok(participants)
}
```

**File:** src/frost/mod.rs (L44-88)
```rust
pub fn presign<C>(
    participants: &[Participant],
    me: Participant,
    args: &PresignArguments<C>,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = PresignOutput<C>>, InitializationError>
where
    C: Ciphersuite + Send,
    <<<C as frost_core::Ciphersuite>::Group as Group>::Field as Field>::Scalar: Send,
    <<C as frost_core::Ciphersuite>::Group as frost_core::Group>::Element: std::marker::Send,
{
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }

    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;

    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }

    // validate threshold
    if args.threshold.value() > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: args.threshold.into(),
            max: participants.len(),
        });
    }

    let ctx = Comms::new();
    let fut = do_presign(
        ctx.shared_channel(),
        participants,
        me,
        args.keygen_out.private_share,
        rng,
    );
    Ok(make_protocol(ctx, fut))
}
```

**File:** src/frost/mod.rs (L120-160)
```rust
pub fn assert_sign_inputs(
    participants: &[Participant],
    threshold: impl Into<ReconstructionLowerBound>,
    me: Participant,
    coordinator: Participant,
) -> Result<ParticipantList, InitializationError> {
    let threshold = threshold.into();
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }
    let Some(participants) = ParticipantList::new(participants) else {
        return Err(InitializationError::DuplicateParticipants);
    };

    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }

    // validate threshold
    if threshold.value() > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: threshold.value(),
            max: participants.len(),
        });
    }

    // ensure the coordinator is a participant
    if !participants.contains(coordinator) {
        return Err(InitializationError::MissingParticipant {
            role: "coordinator",
            participant: coordinator,
        });
    }
    Ok(participants)
}
```

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L57-63)
```rust
    // ensure number of participants during the signing phase is >= threshold
    if participants.len() < threshold {
        return Err(InitializationError::NotEnoughParticipantsForThreshold {
            threshold,
            participants: participants.len(),
        });
    }
```

**File:** src/thresholds.rs (L9-24)
```rust
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, From, Into,
)]
pub struct ReconstructionLowerBound(usize);

// ----- MaxMalicious conversions -----
impl MaxMalicious {
    pub fn value(self) -> usize {
        self.0
    }
}

impl ReconstructionLowerBound {
    pub fn value(self) -> usize {
        self.0
    }
```
