### Title
Missing Strict Upper Bound on `threshold` Allows `threshold = N`, Causing Permanent Denial of Signing — (File: `src/dkg.rs`)

---

### Summary

The DKG protocol specification (`docs/dkg.md`) requires `1 < threshold < N` (strict inequality on both sides). However, `assert_key_invariants` in `src/dkg.rs` only enforces `threshold >= 2` and `threshold <= N`, permitting `threshold = N`. A malicious or negligent coordinator can set `new_threshold = N` during a reshare operation, permanently denying signing for all honest parties with no recovery path inside the library.

---

### Finding Description

**Spec vs. Implementation Discrepancy**

The protocol specification at `docs/dkg.md` line 50 states:

> "1.1 Each P_i asserts that `1 < threshold < N`."

This is a strict upper bound: `threshold` must be strictly less than `N` (the total participant count).

The implementation in `assert_key_invariants` (`src/dkg.rs`, lines 572–582) enforces:

```rust
if threshold > participants.len() {          // allows threshold == N
    return Err(InitializationError::ThresholdTooLarge { ... });
}
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { ... });
}
```

`threshold == participants.len()` (i.e., `threshold = N`) passes both checks and is accepted as valid. This contradicts the specification's strict inequality `threshold < N`.

**Reachable Entry Path**

The public `reshare` function in `src/lib.rs` (lines 106–141) calls `assert_reshare_keys_invariants`, which in turn relies on the same threshold bounds as `assert_key_invariants`. A coordinator invoking `reshare` with `new_threshold = participants.len()` passes all current validation and completes the reshare successfully.

**Permanent DoS Mechanism**

Once `threshold = N` is committed via resharing:

1. Every future signing operation requires all N participants simultaneously.
2. If any single participant is permanently lost (hardware failure, key loss, network partition), signing is permanently denied — N-1 < N = threshold.
3. Recovery via another reshare is also impossible: resharing requires `old_threshold` (= N) participants from the old set to reconstruct the secret, which cannot be satisfied with only N-1 available.
4. No other recovery mechanism (e.g., an "emergency" lower-threshold path) exists in the library.

The library itself documents this class of risk in `README.md` (lines 165–172), noting that functions "wait indefinitely" and that the caller is responsible for managing issues — but there is no caller-side escape hatch once the threshold is set to N.

---

### Impact Explanation

**High — Permanent denial of signing for honest parties.**

After a reshare with `threshold = N` is accepted and any participant is permanently lost, neither signing nor resharing can ever succeed again under the existing key material. The only recovery would be deploying a completely new key generation ceremony from scratch, which is equivalent to the "deploy a new Diamond" recovery described in the external report's exodusMode analogy.

---

### Likelihood Explanation

**Low.** Requires a malicious coordinator (or a negligent one making a misconfiguration) to explicitly pass `new_threshold = participants.len()` during a reshare. The default usage of the library would not naturally produce this value. However, the library provides no guardrail against it, and the spec explicitly forbids it.

---

### Recommendation

Enforce the strict upper bound from the specification in `assert_key_invariants` (`src/dkg.rs`):

```rust
// Change:
if threshold > participants.len() { ... }

// To:
if threshold >= participants.len() {
    return Err(InitializationError::ThresholdTooLarge {
        threshold,
        max: participants.len() - 1,
    });
}
```

This aligns the implementation with the documented protocol invariant `1 < threshold < N` and prevents any coordinator from setting a threshold that makes the system unrecoverable upon a single participant loss.

---

### Proof of Concept

1. N = 5 participants complete an initial keygen with `threshold = 3`.
2. A coordinator initiates reshare with `new_threshold = 5` (= N).
3. `assert_key_invariants` passes: `5 <= 5` and `5 >= 2`. Reshare completes.
4. Participant P5 suffers permanent hardware failure.
5. Signing attempt with P1–P4: fails — needs 5 participants, only 4 available.
6. Reshare attempt with P1–P4 to lower the threshold: fails — `old_threshold = 5`, intersection of old and new sets = 4 < 5 = old_threshold. `assert_reshare_keys_invariants` rejects it.
7. No path to recovery exists within the library. Honest parties P1–P4 are permanently locked out of signing.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** docs/dkg.md (L50-50)
```markdown
1.1 Each $P_i$ asserts that $1 < \mathsf{threshold} < N$.
```

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

**File:** src/lib.rs (L106-141)
```rust
pub fn reshare<C: Ciphersuite>(
    old_participants: &[Participant],
    old_threshold: impl Into<ReconstructionLowerBound> + Send + 'static,
    old_signing_key: Option<SigningShare<C>>,
    old_public_key: VerifyingKey<C>,
    new_participants: &[Participant],
    new_threshold: impl Into<ReconstructionLowerBound> + Copy + Send + 'static,
    me: Participant,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = KeygenOutput<C>>, InitializationError>
where
    Element<C>: Send,
    Scalar<C>: Send,
{
    let comms = Comms::new();
    let threshold = new_threshold;
    let (participants, old_participants) = assert_reshare_keys_invariants::<C>(
        new_participants,
        me,
        threshold,
        old_signing_key,
        old_threshold,
        old_participants,
    )?;
    let fut = do_reshare(
        comms.shared_channel(),
        participants,
        me,
        threshold,
        old_signing_key,
        old_public_key,
        old_participants,
        rng,
    );
    Ok(make_protocol(comms, fut))
}
```
