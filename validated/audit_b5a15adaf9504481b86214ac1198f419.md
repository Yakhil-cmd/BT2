### Title
Asymmetric Validation in `assert_reshare_keys_invariants` Allows a New Participant to Permanently Deny Reshare for Honest Parties — (File: `src/dkg.rs`)

---

### Summary

`assert_reshare_keys_invariants` validates only one direction of the signing-key/participant-set relationship: it rejects an *old* participant who omits their key. It never rejects a *new* participant (one absent from `old_participants`) who supplies a key. Because the pre-check passes, `do_reshare` is called; it then fails immediately—before any network message is sent—leaving every honest participant permanently blocked inside `do_keyshare` waiting for messages that will never arrive.

---

### Finding Description

`assert_reshare_keys_invariants` in `src/dkg.rs` (lines 638–669) performs only one of the two symmetric checks:

```rust
// Step 1.1
// if me is not in the old participant set then ensure that old_signing_key is None
if old_participants.contains(me) && old_signing_key.is_none() {   // ← only this branch
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is present in the old participant list but provided no share"
    )));
}
```

The comment directly above the condition describes the **missing** check ("if me is **not** in the old participant set then ensure that `old_signing_key` is None"), yet the code implements the **opposite** condition. The symmetric guard that is absent is:

```rust
// MISSING:
if !old_participants.contains(me) && old_signing_key.is_some() {
    return Err(InitializationError::BadParameters(...));
}
```

Because this guard is absent, a new participant (`me ∉ old_participants`) may pass `old_signing_key = Some(fake_share)` and the pre-check returns `Ok`. The caller then invokes `do_reshare` (lines 600–635):

```rust
let intersection = old_participants.intersection(&participants);
let secret = old_signing_key
    .map(|x_i| {
        intersection
            .lagrange::<C>(me)          // ← me is NOT in intersection
            .map(|lambda| lambda * x_i.to_scalar())
    })
    .transpose()?                       // ← propagates ProtocolError::InvalidIndex
    ...
```

`intersection.lagrange(me)` returns `Err(ProtocolError::InvalidIndex)` because `me` is absent from the intersection. The `?` operator propagates this error and `do_reshare` returns **before** `do_keyshare` is ever called—meaning no session-ID broadcast, no commitment broadcast, no share exchange. Every honest participant already inside `do_keyshare` is now blocked indefinitely at the very first `do_broadcast` call waiting for a message from the malicious participant that will never arrive.

---

### Impact Explanation

**High — Permanent denial of reshare for honest parties.**

All honest participants enter `do_keyshare` and block at:

```rust
let session_ids = do_broadcast(&mut chan, &participants, me, my_session_id).await?;
```

The protocol has no timeout mechanism; `recv_from_others` / `do_broadcast` wait unconditionally for every listed participant. A single malicious new participant can therefore permanently stall the entire reshare ceremony, preventing the group from ever obtaining new key shares.

---

### Likelihood Explanation

Any participant that is being *added* in a reshare (i.e., `me ∉ old_participants`, `me ∈ new_participants`) controls the `old_signing_key` argument it passes to the library. Intentionally supplying `Some(arbitrary_share)` instead of `None` is a one-line change that bypasses the pre-check and triggers the denial. No cryptographic material needs to be leaked; no trusted component needs to be compromised. The attack is reachable by any unprivileged library caller who is a new participant in the reshare.

---

### Recommendation

Add the missing symmetric guard immediately after the existing check in `assert_reshare_keys_invariants`:

```rust
// Existing check (old participant must supply a key)
if old_participants.contains(me) && old_signing_key.is_none() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is present in the old participant list but provided no share"
    )));
}

// ADD: new participant must NOT supply a key
if !old_participants.contains(me) && old_signing_key.is_some() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is not present in the old participant list but provided a share"
    )));
}
```

---

### Proof of Concept

Setup: `old_participants = [P1, P2, P3]`, `new_participants = [P1, P2, P3, P4]`, threshold = 2.

1. P1, P2, P3 call `assert_reshare_keys_invariants` correctly and proceed to `do_reshare` → `do_keyshare`; they block at `do_broadcast` waiting for P4's session-ID message.
2. P4 (new participant, `me ∉ old_participants`) calls `assert_reshare_keys_invariants` with `old_signing_key = Some(SigningShare::new(arbitrary_scalar))`.
3. The pre-check at line 663 evaluates `old_participants.contains(P4) && old_signing_key.is_none()` → `false && _ = false`; **no error is returned**.
4. P4 calls `do_reshare`; `old_participants.intersection(&new_participants).lagrange::<C>(P4)` returns `Err(ProtocolError::InvalidIndex)` because P4 is not in the intersection.
5. `do_reshare` returns the error before calling `do_keyshare`; P4 never sends any network message.
6. P1, P2, P3 remain blocked indefinitely inside `do_broadcast` — reshare is permanently denied. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** src/dkg.rs (L342-365)
```rust
async fn do_keyshare<C: Ciphersuite>(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    threshold: ReconstructionLowerBound,
    secret: Scalar<C>,
    old_reshare_package: Option<(VerifyingKey<C>, ParticipantList)>,
    rng: &mut impl CryptoRngCore,
) -> Result<KeygenOutput<C>, ProtocolError> {
    let mut all_full_commitments = ParticipantMap::new(&participants);
    let mut domain_separator = DomainSeparator::new();
    // Make sure you do not call do_keyshare with zero as secret on an old participant
    let (old_verification_key, old_participants) =
        assert_keyshare_inputs(me, &secret, old_reshare_package)?;

    // Start Round 1
    // Step 1.2
    let mut my_session_id = [0u8; 32]; // 256 bits
    rng.fill_bytes(&mut my_session_id);
    // Step 1.3 & 2.1
    let session_ids = do_broadcast(&mut chan, &participants, me, my_session_id).await?;

    // Start Round 2
    // generate your secret polynomial p with the constant term set to the secret
```

**File:** src/dkg.rs (L600-635)
```rust
pub async fn do_reshare<C: Ciphersuite>(
    chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    threshold: impl Into<ReconstructionLowerBound>,
    old_signing_key: Option<SigningShare<C>>,
    old_public_key: VerifyingKey<C>,
    old_participants: ParticipantList,
    mut rng: impl CryptoRngCore,
) -> Result<KeygenOutput<C>, ProtocolError> {
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

    let old_reshare_package = Some((old_public_key, old_participants));
    let keygen_output = do_keyshare::<C>(
        chan,
        participants,
        me,
        threshold,
        secret,
        old_reshare_package,
        &mut rng,
    )
    .await?;

    Ok(keygen_output)
}
```

**File:** src/dkg.rs (L638-669)
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
}
```
