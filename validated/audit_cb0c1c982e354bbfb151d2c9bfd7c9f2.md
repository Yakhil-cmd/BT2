### Title
Missing Lower-Bound Validation on `threshold` in FROST Signing Functions Allows Corrupted Signature Output - (File: src/frost/mod.rs)

---

### Summary

The `assert_sign_inputs` function in `src/frost/mod.rs` and the `sign` function in `src/ecdsa/ot_based_ecdsa/sign.rs` validate that `threshold` does not exceed the participant count (upper bound), but neither enforces a minimum value of 2 (lower bound). The DKG initialization function `assert_key_invariants` in `src/dkg.rs` correctly enforces both bounds. This asymmetry allows a caller to pass `threshold = 1` (or `0`) into the signing phase, causing the protocol to proceed with fewer participants than the security threshold, producing a cryptographically invalid and unusable signature.

---

### Finding Description

`ReconstructionLowerBound` is a plain `usize` wrapper with no built-in validation: [1](#0-0) 

The DKG entry-point `assert_key_invariants` enforces both a lower bound (`< 2`) and an upper bound (`> participants.len()`) on `threshold`: [2](#0-1) 

However, the FROST signing validator `assert_sign_inputs` only enforces the upper bound and omits the lower-bound check entirely: [3](#0-2) 

The same omission exists in the FROST `presign` function: [4](#0-3) 

And in the OT-based ECDSA `sign` function, which checks `participants.len() < threshold` but never `threshold < 2`: [5](#0-4) 

---

### Impact Explanation

**High — Corruption of sign outputs so honest parties accept unusable cryptographic outputs.**

In FROST, each participant computes a partial signature using their key share multiplied by a Lagrange coefficient. The Lagrange coefficients are computed over the set of *actually participating* signers. When `threshold = 1` is accepted:

1. The protocol's minimum-participant gate is satisfied by a single signer.
2. The coordinator can aggregate a partial signature from only one participant, computing a Lagrange coefficient of `1` for that single point.
3. The key shares were generated under a DKG with `threshold ≥ 2`, meaning each share is an evaluation of a degree-`(t−1)` polynomial. A single share evaluated with coefficient `1` does **not** reconstruct the secret `f(0)`.
4. The resulting aggregated signature is cryptographically invalid and will fail standard verification against the master public key.

For `threshold = 0`, Lagrange interpolation over an empty or degenerate participant set may panic or produce undefined arithmetic, causing a permanent denial of signing for all honest parties.

---

### Likelihood Explanation

**Medium.** The threshold value is a caller-supplied parameter at every signing invocation. Any library consumer — including a malicious or buggy coordinator — can pass `threshold = 1` without triggering any error. The DKG phase correctly rejects this value, creating a false sense of security: a developer who observes the DKG guard may not realize the signing path lacks the same guard. The entry path requires no special privilege; it is reachable by any unprivileged library caller.

---

### Recommendation

Add the same lower-bound guard that `assert_key_invariants` already enforces to both `assert_sign_inputs` and `presign` in `src/frost/mod.rs`, and to `sign` in `src/ecdsa/ot_based_ecdsa/sign.rs`:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

This mirrors the existing guard in `src/dkg.rs`: [6](#0-5) 

---

### Proof of Concept

1. Run DKG with `participants = [P1, P2, P3]`, `threshold = 2` — succeeds and produces valid key shares.
2. Call `assert_sign_inputs(&[P1, P2, P3], /*threshold=*/ 1u8, P1, P1)` — **no error is returned** because `1 <= 3` passes the only threshold check at line 145.
3. Proceed to FROST signing with `threshold = 1`; the coordinator collects only P1's partial signature (minimum satisfied).
4. P1's Lagrange coefficient is computed as `1` (single-point interpolation), yielding partial sig `= share_P1 * H(msg)`.
5. The aggregated signature `= share_P1 * H(msg)` does not equal `secret * H(msg)` (since `share_P1 ≠ secret` for `t = 2` DKG).
6. Signature verification against the master public key fails — the signing output is permanently unusable. [7](#0-6) [8](#0-7)

### Citations

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

**File:** src/dkg.rs (L572-582)
```rust
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

**File:** src/frost/mod.rs (L120-159)
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
```

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L22-63)
```rust
pub fn sign(
    participants: &[Participant],
    coordinator: Participant,
    threshold: impl Into<ReconstructionLowerBound>,
    me: Participant,
    public_key: AffinePoint,
    presignature: RerandomizedPresignOutput,
    msg_hash: Scalar,
) -> Result<impl Protocol<Output = SignatureOption>, InitializationError> {
    let threshold = usize::from(threshold.into());
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }

    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;

    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }

    // ensure the coordinator is a participant
    if !participants.contains(coordinator) {
        return Err(InitializationError::MissingParticipant {
            role: "coordinator",
            participant: coordinator,
        });
    }

    // ensure number of participants during the signing phase is >= threshold
    if participants.len() < threshold {
        return Err(InitializationError::NotEnoughParticipantsForThreshold {
            threshold,
            participants: participants.len(),
        });
    }
```
