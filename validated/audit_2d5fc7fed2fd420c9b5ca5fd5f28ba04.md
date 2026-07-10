### Title
Missing Threshold Minimum Validation in FROST Signing and Presigning Protocols — (File: `src/frost/mod.rs`)

---

### Summary

The `assert_sign_inputs` function and the `frost::presign` function in `src/frost/mod.rs` do not enforce the minimum threshold constraint (`threshold >= 2`), unlike `assert_key_invariants` in `src/dkg.rs` which explicitly rejects `threshold < 2`. A caller can therefore initialize a FROST signing or presigning session with `threshold = 1`, causing the FROST library's internal `KeyPackage` to be constructed with `min_signers = 1`. This allows the FROST `aggregate()` function to accept a valid signature produced from a single participant's share, violating the threshold security property.

---

### Finding Description

`assert_key_invariants` in `src/dkg.rs` enforces a minimum threshold of 2:

```rust
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
``` [1](#0-0) 

`validate_triple_inputs` in `src/ecdsa/ot_based_ecdsa/triples/generation.rs` also enforces this:

```rust
if threshold_value < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold: threshold_value, min: 2 });
}
``` [2](#0-1) 

However, `assert_sign_inputs` — the shared validation function used by both `frost::eddsa::sign_v1`, `sign_v2`, and `frost::redjubjub::sign` — only checks the upper bound on threshold and **omits the lower-bound check entirely**:

```rust
// validate threshold
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ← No check: threshold.value() < 2
``` [3](#0-2) 

The same omission exists in `frost::presign`:

```rust
// validate threshold
if args.threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ← No check: args.threshold.value() < 2
``` [4](#0-3) 

Both `frost::eddsa::sign_v1` and `sign_v2` delegate directly to `assert_sign_inputs` without any additional threshold lower-bound check: [5](#0-4) [6](#0-5) 

When `threshold = 1` passes validation, `construct_key_package` builds a `KeyPackage` with `min_signers = 1`:

```rust
Ok(KeyPackage::new(
    identifier,
    signing_share,
    verifying_share,
    *verifying_key,
    u16::try_from(threshold.value())...,
))
``` [7](#0-6) 

The FROST `aggregate()` function uses `min_signers` from the `KeyPackage` to verify that enough signature shares were provided. With `min_signers = 1`, aggregation succeeds with a single participant's share, meaning the threshold security guarantee is entirely absent.

---

### Impact Explanation

**High — Corruption of sign outputs so honest parties accept cryptographic outputs inconsistent with the documented threshold.**

A key generated via DKG with `threshold = 2` (enforced by `assert_key_invariants`) can be used in a signing session initialized with `threshold = 1` (not rejected by `assert_sign_inputs`). The resulting `KeyPackage` has `min_signers = 1`, so the FROST `aggregate()` call succeeds with a single signature share. Honest parties receiving the resulting signature have no way to distinguish it from a legitimately threshold-produced signature — the signature is cryptographically valid under the master public key — but it was produced without the cooperation of the required number of participants. This directly corrupts the threshold signing output and violates the security contract of the scheme.

---

### Likelihood Explanation

**Likelihood: 3 / 5.**

The threshold parameter is supplied by the caller at signing time and is independent of the threshold used during DKG. A developer who misreads the API, copies an example with `threshold = 1`, or derives the threshold from an untrusted configuration source can trigger this path without any warning from the library. The inconsistency between DKG (which rejects `threshold < 2`) and signing (which does not) makes accidental misconfiguration realistic. A malicious coordinator who controls the threshold argument passed to `sign_v1`/`sign_v2` can also deliberately exploit this.

---

### Recommendation

Add the same lower-bound check present in `assert_key_invariants` to both `assert_sign_inputs` and `frost::presign`:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

This mirrors the existing enforcement in `assert_key_invariants`: [8](#0-7) 

and in `validate_triple_inputs`: [2](#0-1) 

---

### Proof of Concept

```rust
// Attacker-controlled call: threshold = 1 passes all checks in assert_sign_inputs
let protocol = frost::eddsa::sign::sign_v1(
    &[participant_a, participant_b],  // len >= 2, passes NotEnoughParticipants check
    1usize,                           // threshold = 1: NOT rejected (no lower-bound check)
    participant_a,                    // me
    participant_a,                    // coordinator
    keygen_output,
    message,
    rng,
).unwrap(); // succeeds — InitializationError::ThresholdTooSmall is never returned

// Inside do_sign_coordinator_v1, construct_key_package is called with threshold=1:
//   KeyPackage::new(..., min_signers = 1)
// frost_ed25519::aggregate() then accepts aggregation with a single signature share,
// producing a valid signature without requiring cooperation from participant_b.
```

The entry path is: caller → `sign_v1` → `assert_sign_inputs` (no lower-bound check) → `fut_wrapper_v1` → `do_sign_coordinator_v1` → `construct_key_package(threshold=1, ...)` → `aggregate()` accepts 1 share. [9](#0-8) [10](#0-9)

### Citations

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

**File:** src/frost/mod.rs (L71-77)
```rust
    // validate threshold
    if args.threshold.value() > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: args.threshold.into(),
            max: participants.len(),
        });
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

**File:** src/frost/eddsa/sign.rs (L46-47)
```rust
    let threshold = threshold.into();
    let participants = assert_sign_inputs(participants, threshold, me, coordinator)?;
```

**File:** src/frost/eddsa/sign.rs (L73-73)
```rust
    let participants = assert_sign_inputs(participants, threshold, me, coordinator)?;
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
