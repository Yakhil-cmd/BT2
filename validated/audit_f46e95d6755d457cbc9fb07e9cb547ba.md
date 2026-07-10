### Title
Missing Minimum Threshold Validation in FROST Signing Entry Points Allows Signing Below Security Minimum - (File: `src/frost/mod.rs`)

### Summary
The `assert_sign_inputs` function used by all FROST signing entry points (`sign_v1`, `sign_v2`, `sign`) does not enforce a minimum threshold of 2, unlike the keygen and triple-generation functions. A malicious coordinator or misconfigured caller can pass `threshold = 1` to any FROST signing function. The protocol completes without error but produces an invalid, unusable signature that honest participants accept as a valid protocol output.

### Finding Description
`assert_key_invariants` in `src/dkg.rs` explicitly rejects any threshold below 2: [1](#0-0) 

`validate_triple_inputs` in the OT-based triple generation also enforces the same lower bound: [2](#0-1) 

However, `assert_sign_inputs` in `src/frost/mod.rs` — the shared validation gate for all FROST signing entry points — only checks that the threshold does not exceed the participant count. It contains **no lower-bound check**: [3](#0-2) 

Every FROST signing entry point delegates to this function:

- `sign_v1` and `sign_v2` in `src/frost/eddsa/sign.rs`: [4](#0-3) 

- `sign` in `src/frost/redjubjub/sign.rs`: [5](#0-4) 

When `threshold = 1` is accepted, `construct_key_package` embeds it into the `KeyPackage`: [6](#0-5) [7](#0-6) 

The FROST library then uses this `KeyPackage` to validate the signing package and compute the signature share. With `threshold = 1`, the signing package is accepted with a single commitment, and the coordinator aggregates a single share. Because the key was generated with `threshold >= 2` (Shamir sharing of degree ≥ 1), a single share does not reconstruct the secret. The Lagrange coefficient for a singleton signer set is 1, so the aggregated scalar `s = k_i + c·x_i` does not satisfy `s·G = R + c·X` (where `X` is the true public key). The protocol returns a signature object without error, but the signature is cryptographically invalid.

### Impact Explanation
**High — Corruption of signing outputs so honest parties accept unusable cryptographic outputs.**

The signing protocol terminates successfully and returns a `SignatureOption` to all participants. No error is surfaced. Honest parties have no in-protocol signal that the output is invalid; they only discover the failure when the signature is presented to a verifier. This matches the allowed impact: *"Corruption of … sign … outputs so honest parties accept … unusable cryptographic outputs."*

### Likelihood Explanation
**Low.** Exploitation requires either (a) a misconfigured library caller who passes `threshold = 1` by mistake, or (b) a malicious coordinator who convinces co-signers to invoke `sign` with `threshold = 1`. In a correctly operated deployment, participants would use the threshold agreed upon during keygen. However, the library provides no enforcement mechanism to prevent the mismatch, and the keygen output (`KeygenOutput`) does not record the threshold, so participants have no in-type way to verify consistency: [8](#0-7) 

### Recommendation
Add the same lower-bound guard that exists in `assert_key_invariants` and `validate_triple_inputs` to `assert_sign_inputs`:

```rust
// in src/frost/mod.rs, inside assert_sign_inputs
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

Additionally, consider storing the threshold inside `KeygenOutput` so that signing functions can cross-validate the caller-supplied threshold against the value committed to during key generation.

### Proof of Concept
1. Run keygen with 5 participants and `threshold = 3`.
2. Call `sign_v1` (or `sign_v2` / `sign`) with the same participants but `threshold = 1`.
3. `assert_sign_inputs` passes: `1 <= 5` satisfies the only threshold check.
4. Each participant's `KeyPackage` is built with `min_signers = 1`.
5. The coordinator collects a single commitment and a single signature share.
6. `aggregate` returns a `Signature` object without error.
7. Verifying the signature against the public key fails: the single-share Lagrange reconstruction does not equal the group secret, so `s·G ≠ R + c·X`.
8. Honest parties have accepted a completed protocol run whose output is permanently unusable.

### Citations

**File:** src/dkg.rs (L580-582)
```rust
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

**File:** src/frost/mod.rs (L24-30)
```rust
/// The necessary inputs for the creation of a presignature.
pub struct PresignArguments<C: Ciphersuite> {
    /// The output of key generation, i.e. our share of the secret key, and the public key package.
    pub keygen_out: KeygenOutput<C>,
    /// The threshold for the scheme
    pub threshold: ReconstructionLowerBound,
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

**File:** src/frost/eddsa/sign.rs (L37-88)
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

pub fn sign_v2(
    participants: &[Participant],
    threshold: impl Into<ReconstructionLowerBound> + Copy,
    me: Participant,
    coordinator: Participant,
    keygen_output: KeygenOutput,
    presignature: PresignOutput,
    message: Vec<u8>,
) -> Result<impl Protocol<Output = SignatureOption>, InitializationError> {
    let participants = assert_sign_inputs(participants, threshold, me, coordinator)?;

    let comms = Comms::new();
    let chan = comms.shared_channel();
    let fut = fut_wrapper_v2(
        chan,
        participants,
        threshold.into(),
        me,
        coordinator,
        keygen_output,
        presignature,
        message,
    );
    Ok(make_protocol(comms, fut))
}
```

**File:** src/frost/eddsa/sign.rs (L351-369)
```rust
fn construct_key_package(
    threshold: ReconstructionLowerBound,
    me: Participant,
    signing_share: SigningShare,
    verifying_key: &VerifyingKey,
) -> Result<KeyPackage, ProtocolError> {
    let identifier = me.to_identifier()?;
    let verifying_share = signing_share.into();

    Ok(KeyPackage::new(
        identifier,
        signing_share,
        verifying_share,
        *verifying_key,
        u16::try_from(threshold.value()).map_err(|_| {
            ProtocolError::Other("threshold cannot be converted to u16".to_string())
        })?,
    ))
}
```

**File:** src/frost/redjubjub/sign.rs (L39-66)
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
}
```

**File:** src/frost/redjubjub/sign.rs (L240-261)
```rust
fn construct_key_package(
    threshold: ReconstructionLowerBound,
    me: Participant,
    keygen_output: &KeygenOutput,
) -> Result<KeyPackage, ProtocolError> {
    let identifier = me.to_identifier()?;
    let signing_share = keygen_output.private_share;
    let verifying_share = signing_share.into();
    let verifying_key = keygen_output.public_key;
    let key_package = KeyPackage::new(
        identifier,
        signing_share,
        verifying_share,
        verifying_key,
        u16::try_from(threshold.value()).map_err(|_| {
            ProtocolError::Other("threshold cannot be converted to u16".to_string())
        })?,
    );

    // Ensures the values are zeroized on drop
    Ok(key_package)
}
```
