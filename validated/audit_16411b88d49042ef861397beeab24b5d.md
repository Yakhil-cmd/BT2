### Title
Missing Minimum Threshold Validation in FROST Signing/Presigning Allows Corrupted Signature Outputs - (File: src/frost/mod.rs)

### Summary
The `assert_sign_inputs` and `presign` functions in `src/frost/mod.rs` validate only the upper bound of the threshold (`threshold <= participants.len()`) but omit the lower bound check (`threshold >= 2`) that is enforced in `assert_key_invariants` in `src/dkg.rs`. A malicious coordinator or library caller can pass `threshold = 1` (or `0`) to the FROST signing/presigning entry points, causing the protocol to proceed with fewer participants than the keygen threshold requires. Because the Lagrange interpolation uses the actual participant set, signing with only 2 participants (the hard minimum) against a key generated at threshold ≥ 3 produces a cryptographically invalid signature that honest parties accept as a completed protocol output.

### Finding Description

**Root cause — asymmetric validation between keygen and signing:**

`assert_key_invariants` in `src/dkg.rs` enforces both bounds:

```rust
if threshold > participants.len() { ... }   // upper bound
if threshold < 2 { ... }                    // lower bound  ← present
``` [1](#0-0) 

`assert_sign_inputs` in `src/frost/mod.rs` enforces only the upper bound:

```rust
if threshold.value() > participants.len() { ... }   // upper bound only
// ← lower bound check (threshold < 2) is absent
``` [2](#0-1) 

`presign` in `src/frost/mod.rs` has the same omission:

```rust
if args.threshold.value() > participants.len() { ... }   // upper bound only
``` [3](#0-2) 

The `ReconstructionLowerBound` wrapper type itself imposes no minimum — it is a plain `usize` newtype with a `From<usize>` derivation, so any value including `0` or `1` is accepted without error: [4](#0-3) 

**Exploit path:**

1. Keygen is run honestly with `threshold = 3` (3-of-5 scheme). `assert_key_invariants` enforces `threshold >= 2`, so this is valid.
2. A malicious coordinator calls the EdDSA (or RedJubjub) `sign` function, which internally calls `assert_sign_inputs`, passing `threshold = 1` and a participant list of exactly 2 honest parties (the hard minimum enforced by `participants.len() < 2`).
3. `assert_sign_inputs` passes: `1 <= 2` (upper bound satisfied) and `2 >= 2` (participant count satisfied). [5](#0-4) 
4. The FROST signing protocol proceeds. Lagrange coefficients are computed for the 2-participant set. Because the key shares were generated under a degree-2 polynomial (threshold 3), reconstructing the secret from only 2 evaluation points yields a wrong value.
5. The protocol completes without a runtime error and returns a signature. The signature fails external verification against the public key — honest parties have accepted a corrupted, unusable output.

### Impact Explanation

**High: Corruption of sign outputs so honest parties accept unusable cryptographic outputs.**

Honest participants A and B complete the FROST signing round, receive no protocol error, and believe a valid signature was produced. The signature is in fact cryptographically invalid (wrong Lagrange reconstruction) and will fail verification by any downstream consumer. The malicious coordinator has silently degraded the signing output without triggering any in-protocol alarm. Under repeated exploitation this constitutes effective denial of signing for the honest parties, since every signing session the coordinator orchestrates with `threshold = 1` and a 2-participant subset produces an unusable result.

### Likelihood Explanation

The coordinator role is a normal, documented participant role — not a privileged external actor. Any participant who acts as coordinator for a signing session can supply the `threshold` argument. The `ReconstructionLowerBound` type accepts any `usize`, and the only guard (`threshold <= participants.len()`) is trivially satisfied by `threshold = 1`. No cryptographic capability or leaked secret is required; the attacker only needs to be the session coordinator.

### Recommendation

Add the same lower-bound check that `assert_key_invariants` already enforces to both `assert_sign_inputs` and `presign` in `src/frost/mod.rs`:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

This mirrors the existing check in `assert_key_invariants`: [6](#0-5) 

Optionally, enforce the minimum at the type level by adding a validated constructor to `ReconstructionLowerBound` that rejects values below 2, making it impossible to construct an invalid threshold anywhere in the library: [4](#0-3) 

### Proof of Concept

```
Setup:
  - Run keygen with 5 participants, threshold = 3.
  - All 5 participants obtain valid key shares.

Attack:
  - Malicious coordinator calls frost::eddsa::sign (or redjubjub::sign)
    with participants = [A, B], threshold = ReconstructionLowerBound(1).
  - assert_sign_inputs passes: 1 <= 2 (upper bound), 2 >= 2 (count).
  - FROST signing round executes; A and B each contribute a signature share.
  - Coordinator aggregates with Lagrange coefficients for {A, B} only.
  - Aggregated signature is returned with Ok(…).

Verification:
  - Verify the returned signature against the public key from keygen.
  - Verification fails: the Lagrange reconstruction used 2 shares of a
    degree-2 polynomial, producing an incorrect nonce combination.
  - Honest parties A and B observe a completed protocol with no error,
    but the signature is unusable.
``` [7](#0-6)

### Citations

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
