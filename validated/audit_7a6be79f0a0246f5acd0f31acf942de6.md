### Title
Contradictory Validation Comment vs. Code in `assert_reshare_keys_invariants` Allows New Participant to Stall Reshare Protocol - (File: src/dkg.rs)

### Summary

`assert_reshare_keys_invariants` contains a comment describing a guard that is the logical inverse of the guard actually implemented. The comment says "if me is **not** in the old participant set then ensure that `old_signing_key` is None," but the code checks the opposite condition (`old_participants.contains(me) && old_signing_key.is_none()`). The intended guard — rejecting a new participant who supplies a non-`None` signing key — is entirely absent. A malicious new participant can therefore pass `old_signing_key = Some(…)` through validation, causing `do_reshare` to panic with `ProtocolError::InvalidIndex` before any network round begins, permanently stalling the reshare session for all honest parties.

### Finding Description

**Root cause — `src/dkg.rs`, lines 661–667:**

```rust
// Step 1.1
// if me is not in the old participant set then ensure that old_signing_key is None
if old_participants.contains(me) && old_signing_key.is_none() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is present in the old participant list but provided no share"
    )));
}
``` [1](#0-0) 

The comment describes the guard `!old_participants.contains(me) && old_signing_key.is_some()`. The code implements `old_participants.contains(me) && old_signing_key.is_none()`. These are mutually exclusive conditions; the intended guard is never evaluated.

**Propagation — `src/lib.rs`, lines 122–140:**

`reshare()` calls `assert_reshare_keys_invariants` and, on success, passes the original `old_signing_key` directly into `do_reshare`. [2](#0-1) 

**Failure site — `src/dkg.rs`, lines 611–620:**

```rust
let intersection = old_participants.intersection(&participants);
let secret = old_signing_key
    .map(|x_i| {
        intersection
            .lagrange::<C>(me)          // ← me is NOT in intersection
            .map(|lambda| lambda * x_i.to_scalar())
    })
    .transpose()?                       // ← propagates InvalidIndex
    .unwrap_or_else(…);
``` [3](#0-2) 

Because `me` is not in `old_participants`, it is not in `intersection`. `ParticipantList::lagrange` calls `ParticipantList::index`, which returns `Err(ProtocolError::InvalidIndex)` for any participant not in the list. [4](#0-3) 

The `?` operator propagates this error, causing `do_reshare`'s future to resolve to `Err` before Round 1 (`do_broadcast` for session IDs) is ever reached. [5](#0-4) 

All honest participants block waiting for the malicious participant's Round-1 broadcast that never arrives, stalling the entire reshare session.

### Impact Explanation

**Severity: High — Permanent denial of reshare for honest parties.**

A single malicious new participant (one not present in `old_participants`) can abort every reshare session indefinitely. Because `do_keyshare` requires all participants to complete and broadcast success via `broadcast_success`, the failure of one participant before Round 1 causes all others to wait without bound (or until an external timeout), and the reshare never produces new key shares. [6](#0-5) [7](#0-6) 

This matches the allowed High impact: *"Permanent denial of … reshare … for honest parties under valid protocol inputs and documented trust assumptions."*

### Likelihood Explanation

Any participant who is legitimately invited into the new participant set but is **not** in the old participant set can trigger this. No privileged access, leaked keys, or cryptographic breaks are required — only the ability to call `reshare()` with `old_signing_key = Some(arbitrary_share)`. The attacker controls a standard library entry point.

### Recommendation

Add the missing guard immediately after (or instead of) the existing one in `assert_reshare_keys_invariants`:

```rust
// if me is not in the old participant set, old_signing_key must be None
if !old_participants.contains(me) && old_signing_key.is_some() {
    return Err(InitializationError::BadParameters(format!(
        "party {me:?} is not in the old participant list but provided a share"
    )));
}
```

The existing guard (checking that an old participant supplies a key) is correct and should be retained alongside the new one.

### Proof of Concept

```
Setup:
  old_participants = [P0, P1, P2]   (threshold = 2)
  new_participants = [P0, P1, P2, P3]
  me = P3  (new participant, NOT in old_participants)

Attack:
  P3 calls reshare(
      old_participants = [P0,P1,P2],
      old_threshold    = 2,
      old_signing_key  = Some(<any SigningShare>),  // ← should be None
      old_public_key   = <valid key>,
      new_participants = [P0,P1,P2,P3],
      new_threshold    = 2,
      me               = P3,
      rng              = …,
  )

Step 1: assert_reshare_keys_invariants
  old_participants.contains(P3) → false
  Existing check: false && … → skipped  ✓ (no error raised)
  Missing check:  !false && Some(…).is_some() → would have errored, but absent

Step 2: do_reshare called with old_signing_key = Some(…)
  intersection = {P0,P1,P2} ∩ {P0,P1,P2,P3} = {P0,P1,P2}
  intersection.lagrange(P3) → Err(ProtocolError::InvalidIndex)
  ? propagates → do_reshare future resolves to Err immediately

Step 3: P0, P1, P2 block on Round-1 broadcast from P3 → reshare stalls
```

### Citations

**File:** src/dkg.rs (L307-337)
```rust
async fn broadcast_success(
    chan: &mut SharedChannel,
    participants: &ParticipantList,
    me: Participant,
    session_id: HashOutput,
) -> Result<(), ProtocolError> {
    // broadcast node me succeded
    let vote_list = do_broadcast(chan, participants, me, (true, session_id)).await?;
    // unwrap here would never fail as the broadcast protocol ends only when the map is full
    let vote_list = vote_list
        .into_vec_or_none()
        .ok_or_else(|| ProtocolError::AssertionFailed("vote_list is empty".to_string()))?;
    // go through all the list of votes and check if any is fail or some does not contain the session id

    if !vote_list.iter().all(|(_, ref sid)| sid == &session_id) {
        return Err(ProtocolError::AssertionFailed(
            "A participant
                broadcast the wrong session id. Aborting Protocol!"
                .to_string(),
        ));
    }

    if !vote_list.iter().all(|&(boolean, _)| boolean) {
        return Err(ProtocolError::AssertionFailed(
            "A participant
                seems to have failed its checks. Aborting Protocol!"
                .to_string(),
        ));
    }
    // Wait for all the tasks to complete
    Ok(())
```

**File:** src/dkg.rs (L362-362)
```rust
    let session_ids = do_broadcast(&mut chan, &participants, me, my_session_id).await?;
```

**File:** src/dkg.rs (L531-531)
```rust
    broadcast_success(&mut chan, &participants, me, session_id).await?;
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

**File:** src/dkg.rs (L661-667)
```rust
    // Step 1.1
    // if me is not in the old participant set then ensure that old_signing_key is None
    if old_participants.contains(me) && old_signing_key.is_none() {
        return Err(InitializationError::BadParameters(format!(
            "party {me:?} is present in the old participant list but provided no share"
        )));
    }
```

**File:** src/lib.rs (L122-140)
```rust
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
