### Title
Missing Lower-Bound Validation on `threshold` in FROST Signing Allows Corrupted Signing Outputs - (File: `src/frost/mod.rs`)

---

### Summary

`assert_sign_inputs` in `src/frost/mod.rs` validates that `threshold <= participants.len()` but **never checks that `threshold >= 2`**. Every other analogous validation function in the codebase enforces this lower bound. A malicious coordinator or misconfigured caller can pass `threshold = 0` or `threshold = 1` to any FROST signing entry point, causing the signing protocol to proceed with a cryptographically invalid threshold and produce corrupted, unverifiable signature outputs.

---

### Finding Description

`assert_sign_inputs` is the sole input-validation gate for all FROST signing functions. It checks:

```rust
// src/frost/mod.rs L144-150
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
```

There is **no lower-bound check**. Passing `threshold = 0` or `threshold = 1` passes validation silently.

Compare this to every other validation function in the codebase:

- `assert_key_invariants` (`src/dkg.rs` L580-582):
  ```rust
  if threshold < 2 {
      return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
  }
  ```
- `validate_triple_inputs` (`src/ecdsa/ot_based_ecdsa/triples/generation.rs` L699-704):
  ```rust
  if threshold_value < 2 {
      return Err(InitializationError::ThresholdTooSmall { threshold: threshold_value, min: 2 });
  }
  ```

Both DKG and triple generation enforce `threshold >= 2`. FROST signing does not.

`assert_sign_inputs` is called directly by all three FROST signing entry points:

- `sign_v1` / `sign_v2` — `src/frost/eddsa/sign.rs` L47, L73
- `redjubjub::sign` — `src/frost/redjubjub/sign.rs` L50

The `presign` function in `src/frost/mod.rs` (L72-77) has the same defect independently.

---

### Impact Explanation

In FROST, the coordinator aggregates exactly `threshold` signature shares via Lagrange interpolation. The DKG distributes shares over a polynomial of degree `threshold_dkg - 1` (where `threshold_dkg >= 2`). If signing is invoked with `threshold_sign = 1`:

- The coordinator collects only 1 share and applies a trivial Lagrange coefficient of 1.
- The aggregated nonce scalar `z` equals the single participant's share rather than the correct linear combination.
- The resulting `(R, z)` pair fails standard FROST verification against the public key.

If `threshold_sign = 0`:

- The coordinator aggregates zero shares, producing a degenerate or panicking output depending on the FROST library's internal handling.

In both cases, honest participants have committed nonces and sent signature shares; the protocol completes without error from their perspective, but the output signature is cryptographically invalid and unusable. This constitutes **corruption of signing outputs so honest parties accept unusable cryptographic outputs** — a High-severity impact per the allowed scope.

---

### Likelihood Explanation

The `threshold` parameter is supplied by the caller at signing time and is independent of the DKG threshold stored in `KeygenOutput`. A malicious coordinator controlling the signing invocation can pass any `usize` value. Because `assert_sign_inputs` performs no lower-bound check, values of 0 or 1 are accepted without error. The attack requires only the ability to call a public library function with attacker-chosen parameters — no cryptographic capability or key material is needed.

---

### Recommendation

Add the same lower-bound guard that exists in `assert_key_invariants` and `validate_triple_inputs`:

```rust
// src/frost/mod.rs — assert_sign_inputs
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

Apply the same fix to the `presign` function in `src/frost/mod.rs` (L72-77).

---

### Proof of Concept

1. Run DKG with 3 participants and `threshold = 2` (valid, enforced by `assert_key_invariants`).
2. Call `sign_v1` with the same 3 participants but `threshold = 1`:
   ```rust
   sign_v1(
       &participants,
       ReconstructionLowerBound::from(1usize), // passes assert_sign_inputs silently
       me,
       coordinator,
       keygen_output,
       message,
       rng,
   )
   ```
3. `assert_sign_inputs` accepts `threshold = 1` because `1 <= 3` and no lower-bound check exists.
4. The coordinator aggregates a single signature share with Lagrange coefficient 1.
5. The resulting signature fails verification against the public key produced by DKG.

The root cause is the missing `threshold.value() < 2` guard in `assert_sign_inputs` at `src/frost/mod.rs` L144-150, contrasted with the enforced guard at `src/dkg.rs` L580-582 and `src/ecdsa/ot_based_ecdsa/triples/generation.rs` L699-704. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

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

**File:** src/dkg.rs (L579-582)
```rust
    // Step 1.1
    if threshold < 2 {
        return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
    }
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L699-704)
```rust
    if threshold_value < 2 {
        return Err(InitializationError::ThresholdTooSmall {
            threshold: threshold_value,
            min: 2,
        });
    }
```

**File:** src/frost/eddsa/sign.rs (L37-62)
```rust
pub fn sign_v1(
    participants: &[Participant],
    threshold: impl Into<ReconstructionLowerBound>,
    me: Participant,
    coordinator: Participant,
    keygen_output: KeygenOutput,
    message: Vec<u8>,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = SignatureOption>, InitializationError> {
    let threshold = threshold.into();
    let participants = assert_sign_inputs(participants, threshold, me, coordinator)?;

    let comms = Comms::new();
    let chan = comms.shared_channel();
    let fut = fut_wrapper_v1(
        chan,
        participants,
        threshold,
        me,
        coordinator,
        keygen_output,
        message,
        rng,
    );
    Ok(make_protocol(comms, fut))
}
```

**File:** src/frost/redjubjub/sign.rs (L39-65)
```rust
pub fn sign(
    participants: &[Participant],
    threshold: impl Into<ReconstructionLowerBound>,
    me: Participant,
    coordinator: Participant,
    keygen_output: KeygenOutput,
    presignature: PresignOutput,
    message: Vec<u8>,
    randomizer: Option<Randomizer>,
) -> Result<impl Protocol<Output = SignatureOption>, InitializationError> {
    let threshold = threshold.into();
    let participants = assert_sign_inputs(participants, threshold, me, coordinator)?;

    let comms = Comms::new();
    let chan = comms.shared_channel();
    let fut = fut_wrapper(
        chan,
        participants,
        threshold,
        me,
        coordinator,
        keygen_output,
        presignature,
        message,
        randomizer,
    );
    Ok(make_protocol(comms, fut))
```
