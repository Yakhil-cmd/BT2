### Title
Missing Validation in `assert_reshare_keys_invariants` Allows Malicious New Joiner to Provide Non-None `old_signing_key`, Causing Reshare DoS — (File: `src/dkg.rs`)

---

### Summary

`assert_reshare_keys_invariants` in `src/dkg.rs` validates that an old participant provides a signing key, but omits the symmetric check: that a **new joiner** (not in the old participant set) must **not** provide a signing key. A malicious new joiner can pass `old_signing_key = Some(...)`, bypass the initialization guard, and cause `do_reshare` to fail immediately inside the protocol future before any network messages are sent. All honest participants then wait indefinitely for messages from the failed participant, permanently blocking the reshare for the session.

---

### Finding Description

In `src/dkg.rs`, the function `assert_reshare_keys_invariants` performs pre-protocol validation. The comment on line 662 explicitly states the intended invariant:

> "if me is not in the old participant set then ensure that old_signing_key is None"

However, the code only enforces the **opposite** half of the invariant: [1](#0-0) 

```rust
// if me is not in the old participant set then ensure that old_signing_key is None
if old_participants.contains(me) && old_signing_key.is_none() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is present in the old participant list but provided no share"
    )));
}
```

The check guards against an **old participant** omitting their key, but there is **no check** for the reverse: a **new joiner** (`!old_participants.contains(me)`) providing a non-None `old_signing_key`. This means `assert_reshare_keys_invariants` returns `Ok(...)` for a new joiner who supplies a fabricated signing key. [2](#0-1) 

When the protocol subsequently runs `do_reshare`, the following computation is reached: [3](#0-2) 

```rust
let intersection = old_participants.intersection(&participants);
let secret = old_signing_key
    .map(|x_i| {
        intersection
            .lagrange::<C>(me)   // ← me is NOT in intersection
            .map(|lambda| lambda * x_i.to_scalar())
    })
    .transpose()?               // ← propagates ProtocolError immediately
    .unwrap_or_else(<C::Group as Group>::Field::zero);
```

Because `me` (the new joiner) is not in `old_participants`, it is not in `intersection`. `intersection.lagrange::<C>(me)` returns a `ProtocolError`. The `.transpose()?` propagates this error, causing `do_reshare` to abort **before any network message is sent**.

The protocol future for the malicious participant terminates with an error immediately. All other honest participants are blocked waiting for messages from this participant that will never arrive. [4](#0-3) 

The README explicitly documents this waiting behavior:

> "All our public functions that involve network interactions…are designed to wait indefinitely for the expected messages." [5](#0-4) 

---

### Impact Explanation

**High — Permanent denial of reshare for honest parties.**

A single malicious new joiner can abort the entire reshare session for all honest participants by providing a fabricated `old_signing_key`. Because the failure occurs before any message is sent, honest participants have no way to detect the abort and will wait indefinitely (until an application-level timeout, if one is implemented). The reshare session is unrecoverable without restarting with a different participant set. This directly matches the allowed impact: *"High: Permanent denial of signing, key generation, reshare, refresh, or CKD for honest parties under valid protocol inputs and documented trust assumptions."*

---

### Likelihood Explanation

**Medium.** The attacker must be a participant invited into the new reshare set (a new joiner). No privileged access is required — any new joiner can supply an arbitrary `old_signing_key = Some(fabricated_value)`. The missing guard is in the public validation API, so the error is not caught before the protocol starts. The attack is deterministic and requires no cryptographic capability.

---

### Recommendation

Add the symmetric guard in `assert_reshare_keys_invariants` immediately after the existing check:

```rust
// if me is not in the old participant set then ensure that old_signing_key is None
if old_participants.contains(me) && old_signing_key.is_none() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is present in the old participant list but provided no share"
    )));
}
// NEW: symmetric check — new joiners must not supply a signing key
if !old_participants.contains(me) && old_signing_key.is_some() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is not present in the old participant list but provided a share"
    )));
}
```

This ensures the invalid state is rejected at initialization time, before the protocol future is created and before other participants begin waiting. [6](#0-5) 

---

### Proof of Concept

1. Run a keygen with participants `[P0, P1, P2]`, threshold 2.
2. Initiate a reshare to new participants `[P0, P1, P2, P3]` (P3 is a new joiner).
3. P3 (malicious) calls `assert_reshare_keys_invariants` with `old_signing_key = Some(fabricated_share)`. The check at line 663 evaluates `old_participants.contains(P3) && old_signing_key.is_none()` → `false && false` → **no error returned**.
4. P3 proceeds to call `do_reshare`. Inside, `intersection.lagrange::<C>(P3)` fails because P3 is not in `old_participants ∩ new_participants` from the old side. `do_reshare` returns `ProtocolError` immediately, before sending any message.
5. P0, P1, P2 are waiting for Round 1 messages from all participants including P3. P3 never sends. All honest participants block indefinitely.
6. The reshare session is permanently stalled for the session. [7](#0-6)

### Citations

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

**File:** README.md (L165-172)
```markdown
* All our public functions that involve network interactions, such as `keygen`,
  `reshare`, `sign`, and `ckd`, are designed to wait indefinitely for the
  expected messages. For instance, if a message needed to proceed is never
  received, the function will enter an infinite wait loop. This behavior is
  intentional, allowing the caller to determine how long to wait in each
  situation. Consequently, **the caller is responsible** for managing potential
  issues, such as implementing timeouts or other mechanisms to prevent functions
  from running indefinitely.
```
