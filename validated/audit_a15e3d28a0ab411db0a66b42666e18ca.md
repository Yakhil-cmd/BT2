### Title
Missing Validation of New-Joiner Signing Key in `assert_reshare_keys_invariants` Allows Mid-Protocol Reshare Abort - (File: `src/dkg.rs`)

---

### Summary

`assert_reshare_keys_invariants` in `src/dkg.rs` contains a comment that explicitly describes a required data-validation check — "if me is not in the old participant set then ensure that `old_signing_key` is None" — but the code implements only the **opposite** check. The described guard is entirely absent. A new joiner (not in `old_participants`) who supplies a non-`None` `old_signing_key` passes initialization without error, enters the live reshare protocol, and then causes a runtime abort inside `do_reshare` when Lagrange interpolation is attempted for a participant not present in the intersection set. This aborts the reshare for all honest parties.

---

### Finding Description

In `src/dkg.rs`, the public pre-flight function `assert_reshare_keys_invariants` is responsible for rejecting invalid caller configurations before the reshare protocol begins. The relevant block reads:

```rust
// Step 1.1
// if me is not in the old participant set then ensure that old_signing_key is None
if old_participants.contains(me) && old_signing_key.is_none() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is present in the old participant list but provided no share"
    )));
}
```

The comment describes the guard: **"if `me` is NOT in the old participant set then ensure that `old_signing_key` is None"**. The code, however, checks the **opposite** condition: it errors only when `me` IS in `old_participants` and the key is `None`. The case where `me` is **not** in `old_participants` but supplies a non-`None` `old_signing_key` is never rejected.

When this misconfigured caller subsequently invokes `do_reshare`, the following code runs:

```rust
let intersection = old_participants.intersection(&participants);
let secret = old_signing_key
    .map(|x_i| {
        intersection
            .lagrange::<C>(me)
            .map(|lambda| lambda * x_i.to_scalar())
    })
    .transpose()?
    .unwrap_or_else(<C::Group as Group>::Field::zero);
```

Because `me` is not in `old_participants`, it is not in `intersection`. The call `intersection.lagrange::<C>(me)` internally calls `index(me)`, which returns `ProtocolError::InvalidIndex` (see `participants.rs` line 135–140). The `transpose()?` propagates this error, aborting the async protocol future mid-execution. All other honest participants who have already committed to the reshare round are left with an incomplete, aborted session.

---

### Impact Explanation

**High — Permanent denial of reshare for honest parties.**

When a new joiner (legitimately not in `old_participants`) accidentally or maliciously supplies a non-`None` `old_signing_key`, the reshare protocol starts successfully (passes initialization), other honest participants begin exchanging round messages, and then the misconfigured party aborts mid-protocol. The reshare session is unrecoverable; honest parties must restart from scratch. A malicious new joiner can repeat this pattern to indefinitely prevent the reshare from completing, permanently denying honest parties the ability to migrate their key shares to the new participant set.

---

### Likelihood Explanation

**Medium.** The `assert_reshare_keys_invariants` function is the documented pre-flight check for reshare. A library caller who is a new joiner and mistakenly passes their old key material (e.g., from a prior epoch) will pass this check without warning. A malicious coordinator or participant who controls the new-joiner role can deliberately trigger this to abort reshare sessions at will. No privileged access or cryptographic break is required — only the ability to call the public reshare API with a non-`None` `old_signing_key` while not being in `old_participants`.

---

### Recommendation

Add the missing guard that the comment already describes. Immediately after the existing check, add:

```rust
// if me is not in the old participant set then ensure that old_signing_key is None
if !old_participants.contains(me) && old_signing_key.is_some() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is not in the old participant list but provided a share"
    )));
}
```

This ensures that the initialization function rejects all invalid configurations before any protocol messages are exchanged, matching the behavior described by the existing comment.

---

### Proof of Concept

1. Run DKG with participants `[A, B, C]`, threshold 2. `A`, `B`, `C` each hold a valid `SigningShare`.
2. Initiate a reshare to a new set `[A, B, D]` (D is a new joiner).
3. Party `D` calls `assert_reshare_keys_invariants` with `old_signing_key = Some(<stale_share>)` and `old_participants = [A, B, C]`.
4. The function returns `Ok(...)` — no error is raised, because `D` is not in `old_participants` and `old_signing_key.is_some()` is not checked.
5. `D` calls `do_reshare`. Inside, `intersection = old_participants.intersection(&[A,B,D]) = [A,B]`. `D` is not in `intersection`.
6. `intersection.lagrange::<C>(D)` → `ProtocolError::InvalidIndex`. `transpose()?` propagates the error.
7. `D`'s protocol future aborts. Parties `A` and `B`, who have already sent round-1 messages, are left in an incomplete state. The reshare fails for all honest parties. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** src/dkg.rs (L610-621)
```rust
    let threshold = threshold.into();
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

**File:** src/participants.rs (L135-140)
```rust
    pub fn index(&self, participant: Participant) -> Result<usize, ProtocolError> {
        self.indices
            .get(&participant)
            .copied()
            .ok_or(ProtocolError::InvalidIndex)
    }
```
