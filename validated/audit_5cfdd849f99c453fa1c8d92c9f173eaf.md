### Title
Wrong Comparison Operator in `assert_key_invariants` Allows `threshold == N`, Enabling Permanent Denial of Signing — (File: `src/dkg.rs`)

---

### Summary

`assert_key_invariants` uses `>` instead of `>=` when checking the upper bound on `threshold`, allowing callers to run DKG with `threshold == N` (all participants). This directly violates the protocol specification, which requires `1 < threshold < N` (strictly less than N). A key generated under this configuration requires every single participant to be present for signing; any participant going offline after DKG causes permanent, irrecoverable denial of signing for all honest parties.

---

### Finding Description

The protocol specification in `docs/dkg.md` line 50 states:

> **1.1** Each $P_i$ asserts that $1 < \mathsf{threshold} < N$.

The strict upper bound `threshold < N` is a hard protocol invariant. The implementation in `assert_key_invariants` enforces this as:

```rust
// src/dkg.rs, line 573
if threshold > participants.len() {
    return Err(InitializationError::ThresholdTooLarge {
        threshold,
        max: participants.len(),
    });
}
```

The operator `>` only rejects `threshold > N`. It silently accepts `threshold == N`, which the spec explicitly forbids. The correct operator is `>=`.

The lower-bound check immediately below correctly uses `<`:

```rust
// src/dkg.rs, line 580
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
```

So the accepted range is `[2, N]` instead of the specified `[2, N-1]`. [1](#0-0) 

The spec requirement is explicit: [2](#0-1) 

`assert_key_invariants` is the sole pre-flight guard called by both `keygen` and `reshare` (via `assert_reshare_keys_invariants`): [3](#0-2) [4](#0-3) 

---

### Impact Explanation

When `threshold == N`:

- The DKG polynomial has degree `N-1`, so all `N` shares are required to reconstruct the secret.
- Every subsequent signing call requires all `N` participants to be online simultaneously.
- If any single participant is offline, crashes, or is removed from the network after DKG completes, signing is **permanently impossible** — the key is effectively bricked.
- There is no recovery path: resharing would also require all `N` old participants to be present (since `old_threshold == N`), making even key migration impossible.

**Impact: High — Permanent denial of signing for honest parties under valid protocol inputs and documented trust assumptions.**

---

### Likelihood Explanation

The `keygen` and `reshare` public APIs accept `threshold` as a plain `usize`-backed `ReconstructionLowerBound` with no type-level upper bound. A library integrator who reads the documentation ("set threshold to the number of participants you want to require") may naturally pass `threshold = N` for an "all-must-sign" policy, observe that the library accepts it without error, and deploy. The code gives no warning; the spec restriction is only in a markdown doc. **Likelihood: Medium.**

---

### Recommendation

Change the upper-bound comparison from `>` to `>=` in `assert_key_invariants`:

```rust
// src/dkg.rs
// Before (wrong):
if threshold > participants.len() {

// After (correct):
if threshold >= participants.len() {
```

This enforces the spec invariant `threshold < N` and rejects the degenerate `threshold == N` case before any cryptographic work begins.

---

### Proof of Concept

```
participants = [P1, P2, P3]   // N = 3
threshold = 3                  // threshold == N, should be rejected

keygen(&participants, me, 3usize, rng)
  → assert_key_invariants called
  → threshold (3) > participants.len() (3)? NO → passes
  → threshold (3) < 2? NO → passes
  → DKG proceeds, produces shares requiring all 3 participants

// Later: P3 goes offline
sign(&[P1, P2], ..., threshold=3, ...)
  → participants.len() (2) < threshold (3) → InitializationError
  // Signing is permanently impossible; no quorum can ever be formed
  // Resharing also impossible: old_threshold=3 requires all 3 old participants
``` [5](#0-4) [6](#0-5)

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

**File:** src/dkg.rs (L649-649)
```rust
    let participants = assert_key_invariants(participants, me, threshold)?;
```

**File:** docs/dkg.md (L50-50)
```markdown
1.1 Each $P_i$ asserts that $1 < \mathsf{threshold} < N$.
```

**File:** src/lib.rs (L88-102)
```rust
pub fn keygen<C: Ciphersuite>(
    participants: &[Participant],
    me: Participant,
    threshold: impl Into<ReconstructionLowerBound> + Send + Copy + 'static,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = KeygenOutput<C>>, InitializationError>
where
    Element<C>: Send,
    Scalar<C>: Send,
{
    let comms = Comms::new();
    let participants = assert_key_invariants(participants, me, threshold)?;
    let fut = do_keygen::<C>(comms.shared_channel(), participants, me, threshold, rng);
    Ok(make_protocol(comms, fut))
}
```
