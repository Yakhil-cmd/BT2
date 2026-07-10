### Title
Missing Minimum Threshold Validation in FROST Presign/Sign Allows Corrupted Signing Outputs — (`src/frost/mod.rs`)

### Summary
The `presign` and `assert_sign_inputs` functions in `src/frost/mod.rs`, and the `presign` function in `src/ecdsa/ot_based_ecdsa/presign.rs`, validate that `threshold <= participants.len()` but do **not** enforce the minimum threshold of 2 that is required by the DKG and triple-generation phases. A malicious coordinator can initiate a signing or presigning session with `threshold = 1`, causing the protocol to complete without returning any error while producing a cryptographically invalid/unusable signature — an exact analog to the "no minimum position requirement" pattern in the reference report.

### Finding Description

The DKG entry point and triple generation both enforce a hard minimum of 2 on the threshold:

- `assert_key_invariants` in `src/dkg.rs` line 580 explicitly rejects `threshold < 2` with `ThresholdTooSmall`. [1](#0-0) 
- `validate_triple_inputs` in `src/ecdsa/ot_based_ecdsa/triples/generation.rs` line 699 does the same. [2](#0-1) 

However, the downstream signing and presigning functions omit this lower-bound check entirely:

- `presign` in `src/frost/mod.rs` (line 72) only checks `threshold > participants.len()`, never `threshold < 2`. [3](#0-2) 
- `assert_sign_inputs` in `src/frost/mod.rs` (line 145) applies the same one-sided check. [4](#0-3) 
- `presign` in `src/ecdsa/ot_based_ecdsa/presign.rs` (line 31) also only checks the upper bound. [5](#0-4) 

`ReconstructionLowerBound` is a plain `usize` newtype with no internal minimum enforcement, so any value including 1 or 0 is accepted by the type system. [6](#0-5) 

When `threshold = 1` is passed to the FROST signing path, Lagrange interpolation is performed over a single-point set. The Lagrange coefficient for a single participant is 1, so the reconstructed signing scalar equals that one participant's raw share `x_i` — not the true aggregate secret `Σ λ_i · x_i`. The resulting signature does not verify against the group public key that was produced by DKG with `threshold ≥ 2`. The protocol state machine returns `Ok(...)` with no `ProtocolError`, so honest participants have no indication that the output is invalid.

The same logic applies to the OT-based ECDSA presign path: with `threshold = 1`, the Lagrange linearization step at line 93 of `src/ecdsa/ot_based_ecdsa/presign.rs` computes `lambda_me * k_i` with a coefficient of 1, producing a presignature whose `big_r` and `sigma` values are inconsistent with the key material from DKG. [7](#0-6) 

### Impact Explanation

**High — Corruption of sign/presign outputs so honest parties accept unusable cryptographic outputs.**

A malicious coordinator controls the `threshold` argument passed to `assert_sign_inputs` / `presign`. By supplying `threshold = 1`, the coordinator causes every honest participant to complete their protocol steps (send nonce commitments, signature shares) and receive an `Ok` result, while the aggregated signature is cryptographically invalid. Honest parties have no in-protocol signal that the output is corrupt; the corruption is only detectable externally at verification time, after all signing work has been performed and the output has been delivered.

### Likelihood Explanation

The coordinator role is a documented, reachable participant in every FROST and OT-based ECDSA signing session. No privileged key material or external compromise is required — the coordinator simply passes `1usize.into()` as the threshold argument. The inconsistency between DKG (which rejects `threshold < 2`) and signing (which does not) makes this easy to trigger accidentally or maliciously.

### Recommendation

Add the same lower-bound guard that `assert_key_invariants` and `validate_triple_inputs` already apply:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

This check should be added to:
1. `presign` in `src/frost/mod.rs` (after line 72)
2. `assert_sign_inputs` in `src/frost/mod.rs` (after line 145)
3. `presign` in `src/ecdsa/ot_based_ecdsa/presign.rs` (after line 31)

### Proof of Concept

1. DKG is run normally with `threshold = 2` and `n ≥ 2` participants, producing valid `KeygenOutput` shares. [8](#0-7) 
2. A malicious coordinator calls `assert_sign_inputs(participants, 1usize, me, coordinator)`. The function checks `1 > participants.len()` (false) and returns `Ok(participants)` — no error. [9](#0-8) 
3. The coordinator initiates `presign` with `PresignArguments { threshold: 1.into(), keygen_out }`. The check `1 > participants.len()` is false; the protocol proceeds. [10](#0-9) 
4. During signing, Lagrange interpolation over a 1-element set yields coefficient 1, so the reconstructed scalar is `x_i` (one participant's raw share) rather than the true aggregate secret.
5. The protocol returns `Ok(signature)` with no error. The signature fails external verification against the group public key, delivering a corrupted, unusable output to all honest participants.

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

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L699-703)
```rust
    if threshold_value < 2 {
        return Err(InitializationError::ThresholdTooSmall {
            threshold: threshold_value,
            min: 2,
        });
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

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L30-36)
```rust
    // Spec 1.1
    if args.threshold.value() > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: args.threshold.value(),
            max: participants.len(),
        });
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
