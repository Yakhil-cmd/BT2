### Title
Missing Validation of `old_threshold` Against `old_participants` in `assert_reshare_keys_invariants` — (File: `src/dkg.rs`)

---

### Summary

`assert_reshare_keys_invariants` fully validates the **new** threshold via `assert_key_invariants` (enforcing `>= 2` and `<= participants.len()`), but applies **no equivalent validation** to `old_threshold`. A caller can supply `old_threshold = 0` or `old_threshold = 1`, causing the intersection-size guard to pass trivially, and allowing a reshare to proceed with fewer old participants than the original key's threshold required. This corrupts the new key shares accepted by honest parties.

---

### Finding Description

`assert_reshare_keys_invariants` in `src/dkg.rs` is the sole pre-flight guard for the public `reshare` API in `src/lib.rs`. It validates the **new** threshold and participant set thoroughly:

```rust
// src/dkg.rs  lines 646-649
let threshold = usize::from(threshold.into());
let old_threshold = usize::from(old_threshold.into());

let participants = assert_key_invariants(participants, me, threshold)?;
```

`assert_key_invariants` enforces:
- `participants.len() >= 2`
- `threshold >= 2`
- `threshold <= participants.len()`
- uniqueness and self-membership [1](#0-0) 

For `old_threshold` and `old_participants`, the function only checks for duplicate entries:

```rust
// src/dkg.rs  lines 651-652
let old_participants =
    ParticipantList::new(old_participants).ok_or(InitializationError::DuplicateParticipants)?;
``` [2](#0-1) 

The only use of `old_threshold` is the intersection guard:

```rust
// src/dkg.rs  line 655
if old_participants.intersection(&participants).len() < old_threshold {
``` [3](#0-2) 

Because `old_threshold` is a `usize` with no lower-bound check:

- `old_threshold = 0` → `intersection.len() < 0usize` is always `false`; the guard **never fires**.
- `old_threshold = 1` → the guard passes as long as at least one old participant is in the new set, regardless of the actual original threshold.

Neither `old_threshold >= 2` nor `old_threshold <= old_participants.len()` is ever enforced.

The public `reshare` entry point passes `old_threshold` directly from the caller into `assert_reshare_keys_invariants` without any prior sanitisation:

```rust
// src/lib.rs  lines 122-129
let (participants, old_participants) = assert_reshare_keys_invariants::<C>(
    new_participants,
    me,
    threshold,
    old_signing_key,
    old_threshold,   // ← caller-controlled, never range-checked
    old_participants,
)?;
``` [4](#0-3) 

Inside `do_reshare`, the Lagrange coefficient is computed over the **intersection** of old and new participants:

```rust
// src/dkg.rs  lines 611-620
let intersection = old_participants.intersection(&participants);
let secret = old_signing_key
    .map(|x_i| {
        intersection
            .lagrange::<C>(me)
            .map(|lambda| lambda * x_i.to_scalar())
    })
    ...
``` [5](#0-4) 

If the intersection contains fewer participants than the true old threshold (because the guard was bypassed), the Lagrange interpolation is evaluated over an under-determined point set. The resulting `secret` is not the correct reconstruction of the old key's constant term; it is a raw share value multiplied by a degenerate Lagrange coefficient. The new key shares produced by `do_keyshare` will therefore correspond to a **different** key than the original, and honest new participants will accept them.

---

### Impact Explanation

Honest new participants run `do_keyshare` with the corrupted `secret` and produce new key shares that do not correspond to the original public key. Every subsequent signing attempt with those shares will fail or produce invalid signatures. The original key is effectively lost — the reshare output is permanently inconsistent.

This matches: **High — Corruption of reshare outputs so honest parties accept inconsistent public keys or unusable cryptographic outputs.**

---

### Likelihood Explanation

`reshare` is a public library function. Any integrating application that passes an incorrect `old_threshold` — whether through a programming mistake (analogous to the copy-paste typo in the reference report) or through a malicious coordinator supplying a deliberately low value — will trigger the bug. No privileged access or cryptographic break is required; only control over the `old_threshold` argument.

---

### Recommendation

Apply the same validation to `old_threshold` and `old_participants` that `assert_key_invariants` applies to the new threshold and participants. Concretely, inside `assert_reshare_keys_invariants`:

```rust
// After constructing old_participants, add:
if old_participants.len() < 2 {
    return Err(InitializationError::NotEnoughParticipants {
        participants: old_participants.len(),
    });
}
if old_threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold: old_threshold, min: 2 });
}
if old_threshold > old_participants.len() {
    return Err(InitializationError::ThresholdTooLarge {
        threshold: old_threshold,
        max: old_participants.len(),
    });
}
``` [6](#0-5) 

---

### Proof of Concept

1. Run a 3-of-5 DKG to produce `old_key` with `old_threshold = 3`.
2. Call `reshare` with `old_threshold = 1` and a new participant set that shares only **one** member with the old set.
3. `assert_reshare_keys_invariants` accepts the call: `intersection.len() (= 1) < 1` is `false`.
4. `do_reshare` computes `intersection.lagrange(me)` over a single-element set; the Lagrange coefficient is `1`, so `secret = x_i` (the raw share, not the reconstructed key scalar).
5. `do_keyshare` distributes new shares derived from this wrong secret.
6. New participants complete the protocol and hold shares of a key that does not match `old_public_key`. All future signing sessions with these shares produce invalid signatures, and the original key is unrecoverable.

### Citations

**File:** src/dkg.rs (L558-595)
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
```

**File:** src/dkg.rs (L611-620)
```rust
    let intersection = old_participants.intersection(&participants);
    // either extract the share and linearize it or set it to zero
    let secret = old_signing_key
        .map(|x_i| {
            intersection
                .lagrange::<C>(me)
                .map(|lambda| lambda * x_i.to_scalar())
        })
        .transpose()?
        .unwrap_or_else(<C::Group as Group>::Field::zero);
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

**File:** src/lib.rs (L120-141)
```rust
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
