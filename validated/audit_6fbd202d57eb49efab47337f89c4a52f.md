### Title
Off-by-One in `assert_key_invariants` Allows `threshold == N`, Enabling Permanent Denial of Signing - (File: src/dkg.rs)

### Summary

`assert_key_invariants` uses a strict-greater-than comparison (`threshold > participants.len()`) to reject oversized thresholds, but the DKG protocol specification explicitly requires `threshold < N` (strictly less than). This allows a caller to pass `threshold == N` (all-of-N), which the library silently accepts. Any single participant who refuses to cooperate can then permanently prevent all signing operations, because reconstruction requires every share.

### Finding Description

The DKG specification in `docs/dkg.md` line 50 states:

> 1.1 Each $P_i$ asserts that $1 < \mathsf{threshold} < N$.

The enforcement in `assert_key_invariants` is:

```rust
// Step 1.1
// validate threshold
if threshold > participants.len() {          // ← should be >=
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

The comment even cites "Step 1.1" — the same spec step that mandates `threshold < N` — but the code implements `threshold ≤ N`. The boundary value `threshold == participants.len()` passes both guards and is forwarded into `do_keyshare`, which generates a degree-`(N-1)` polynomial. Shamir reconstruction of a degree-`(N-1)` polynomial requires all `N` evaluation points, so every participant's share is mandatory for any subsequent signing operation.

The same off-by-one is present in `validate_triple_inputs` for OT-based ECDSA triple generation:

```rust
// Spec 1.1
if threshold_value > participants.len() {    // ← should be >=
    return Err(InitializationError::ThresholdTooLarge { ... });
}
```

`assert_reshare_keys_invariants` inherits the bug by delegating to `assert_key_invariants`.

**Attacker-controlled entry path:**

1. A malicious coordinator proposes a DKG session with `threshold = N` (e.g., `threshold = 3` for 3 participants). The library accepts this without error.
2. All honest participants run `keygen` / `reshare` / `refresh` successfully and receive valid-looking shares.
3. The malicious participant now holds a veto: any signing round that requires `threshold` participants will fail permanently if the malicious party withholds its share, because `threshold == N` means every share is required.
4. The malicious participant can selectively refuse to participate in any signing session, permanently blocking all signatures.

### Impact Explanation

**High — Permanent denial of signing for honest parties.**

Once a key is generated with `threshold == N`, no subset smaller than the full participant set can produce a signature. A single malicious or unavailable participant permanently prevents any signing operation. The honest parties cannot recover without running a full reshare with a corrected threshold, which itself requires the cooperation of the malicious party (since the old threshold is `N`). The key material is effectively locked.

### Likelihood Explanation

A library integrator who reads the API signature `threshold: impl Into<ReconstructionLowerBound>` and the error message `"threshold {threshold} is too large, it must be at most {max}"` has no indication that `threshold == N` is forbidden. The library silently accepts it. A malicious coordinator who controls the session setup can deliberately propose `threshold = N` to trap honest participants into an unusable key.

### Recommendation

Change the strict-greater-than to greater-than-or-equal in both locations:

**`src/dkg.rs` — `assert_key_invariants`:**
```rust
- if threshold > participants.len() {
+ if threshold >= participants.len() {
    return Err(InitializationError::ThresholdTooLarge {
        threshold,
        max: participants.len(),
    });
}
```

**`src/ecdsa/ot_based_ecdsa/triples/generation.rs` — `validate_triple_inputs`:**
```rust
- if threshold_value > participants.len() {
+ if threshold_value >= participants.len() {
    return Err(InitializationError::ThresholdTooLarge {
        threshold: threshold_value,
        max: participants.len(),
    });
}
```

Update the error variant message to reflect the corrected bound (`max: participants.len() - 1`).

### Proof of Concept

```rust
// Pseudocode — all three participants complete keygen successfully
let participants = [P1, P2, P3];
let threshold = 3; // == N, accepted by assert_key_invariants

let shares = keygen(&participants, threshold, rng); // succeeds, no error

// Now P3 (malicious) refuses to participate in signing.
// Signing requires threshold=3 shares, but only P1 and P2 cooperate.
// Reconstruction of a degree-2 polynomial from 2 points is impossible.
// All signing attempts fail permanently.
let result = sign(&[P1, P2], threshold, msg, ...);
// → fails: not enough participants to reconstruct
```

The root cause is identical in structure to M-20: the setter (`assert_key_invariants`) uses `>` where the spec requires `>=`, admitting the boundary value `threshold == N` that makes a downstream protocol operation (secret reconstruction / signing) permanently impossible under adversarial conditions. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** src/dkg.rs (L571-582)
```rust
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
```

**File:** src/dkg.rs (L638-668)
```rust
pub fn assert_reshare_keys_invariants<C: Ciphersuite>(
    participants: &[Participant],
    me: Participant,
    threshold: impl Into<ReconstructionLowerBound>,
    old_signing_key: Option<SigningShare<C>>,
    old_threshold: impl Into<ReconstructionLowerBound>,
    old_participants: &[Participant],
) -> Result<(ParticipantList, ParticipantList), InitializationError> {
    let threshold = usize::from(threshold.into());
    let old_threshold = usize::from(old_threshold.into());

    let participants = assert_key_invariants(participants, me, threshold)?;

    let old_participants =
        ParticipantList::new(old_participants).ok_or(InitializationError::DuplicateParticipants)?;

    // Step 1.1
    if old_participants.intersection(&participants).len() < old_threshold {
        return Err(InitializationError::NotEnoughParticipantsForNewThreshold {
            threshold: old_threshold,
            participants: old_participants.intersection(&participants).len(),
        });
    }
    // Step 1.1
    // if me is not in the old participant set then ensure that old_signing_key is None
    if old_participants.contains(me) && old_signing_key.is_none() {
        return Err(InitializationError::BadParameters(format!(
            "party {me:?} is present in the old participant list but provided no share"
        )));
    }
    Ok((participants, old_participants))
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L692-704)
```rust
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
```
