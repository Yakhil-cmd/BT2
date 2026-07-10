### Title
Single Malicious Participant Can Permanently Abort DKG/Reshare/Refresh for All Honest Parties via `broadcast_success` — (File: `src/dkg.rs`)

---

### Summary

The `broadcast_success` function at the end of every DKG, reshare, and refresh protocol requires **all** participants to broadcast `(true, session_id)`. A single malicious participant can broadcast `(false, session_id)` — even after all honest parties have successfully validated their shares — causing every honest party to abort the protocol. Because the malicious participant can repeat this on every attempt, honest parties are permanently denied key generation, resharing, and refresh under any participant set that includes the adversary.

---

### Finding Description

At the conclusion of `do_keyshare`, which is the shared implementation of `keygen`, `reshare`, and `refresh`, every participant calls `broadcast_success`: [1](#0-0) 

`broadcast_success` uses `do_broadcast` (the echo-broadcast primitive) to collect a vote from every participant, then checks that **all** votes are `true`: [2](#0-1) 

The critical lines are:

```rust
if !vote_list.iter().all(|&(boolean, _)| boolean) {
    return Err(ProtocolError::AssertionFailed(
        "A participant seems to have failed its checks. Aborting Protocol!"
    ));
}
``` [3](#0-2) 

A malicious participant simply broadcasts `(false, session_id)` instead of `(true, session_id)`. The echo-broadcast layer (`reliable_broadcast_receive_all`) is Byzantine-fault-tolerant for the *delivery* of messages, so all honest parties will reliably agree on the malicious party's `false` vote. The `all(…)` predicate then causes every honest party to return an error and discard their freshly computed `KeygenOutput`.

The same `do_keyshare` path is reached by all three public entry points: [4](#0-3) [5](#0-4) 

A secondary, compounding pattern is `recv_from_others`, which also requires **all** participants to respond before the protocol can advance: [6](#0-5) 

`recv_from_others` is called twice inside `do_keyshare` — once to collect commitment hashes and once to collect signing shares: [7](#0-6) [8](#0-7) 

If a malicious participant withholds either message, the `while !seen.full()` loop never terminates, permanently stalling every honest party at that round with no timeout.

---

### Impact Explanation

**Impact: High — Permanent denial of key generation, reshare, and refresh for honest parties.**

Every call to `keygen`, `reshare`, or `refresh` funnels through `do_keyshare`, which unconditionally calls `broadcast_success` as its final step. A single adversarial participant who is part of the declared participant set can abort every attempt by casting a `false` vote. Because the echo-broadcast guarantees that all honest parties see the same `false`, the abort is deterministic and repeatable. Honest parties cannot complete key generation, cannot rotate shares, and cannot refresh shares as long as the malicious participant remains in the set. The resulting denial is functionally permanent for any fixed participant configuration that includes the adversary.

---

### Likelihood Explanation

**Likelihood: Medium.**

Any participant who has been admitted to the protocol (e.g., a compromised node, a griefing party, or a participant who later turns adversarial) can trigger this with a single-bit change to their outgoing broadcast message. No cryptographic material needs to be leaked, and no external dependency is required. The attack requires only that the adversary be a declared member of the participant list, which is the normal operating condition for threshold protocols.

---

### Recommendation

Replace the unanimous-success gate with a threshold-aware abort mechanism:

1. **Threshold-based success vote**: Instead of requiring `all(boolean == true)`, accept the protocol as successful if at least `threshold` (or `n − f`) participants broadcast success. Participants who broadcast failure can be identified and excluded from the next attempt.

2. **Identify and exclude the aborter**: Record which participant broadcast `false` and surface that identity to the caller so the participant set can be updated before retrying, rather than silently aborting with no attribution.

3. **Add timeouts to `recv_from_others`**: The unbounded `while !seen.full()` loop should have a configurable deadline so that a non-responsive participant causes a clean, attributed error rather than an indefinite hang.

---

### Proof of Concept

```
Participants: {A (honest), B (honest), C (malicious)}
Threshold: 2

Round 1–4: All parties complete honestly.
Round 5 (broadcast_success):
  A broadcasts (true,  sid)
  B broadcasts (true,  sid)
  C broadcasts (false, sid)   ← single-bit deviation

Echo-broadcast delivers C's (false, sid) reliably to A and B.

A evaluates: vote_list.iter().all(|(b,_)| *b)
  → false (because C voted false)
  → returns Err("A participant seems to have failed its checks.")

B evaluates identically → same error.

Result: A and B discard their KeygenOutput.
        C can repeat this on every subsequent keygen/reshare/refresh attempt.
        Honest parties are permanently denied a usable key share.
``` [3](#0-2) [2](#0-1)

### Citations

**File:** src/dkg.rs (L307-338)
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
}
```

**File:** src/dkg.rs (L422-426)
```rust
    for (from, their_commitment_hash) in
        recv_from_others(&chan, wait_round_1, &participants, me).await?
    {
        all_hash_commitments.put(from, their_commitment_hash);
    }
```

**File:** src/dkg.rs (L514-528)
```rust
    for (from, signing_share_from) in
        recv_from_others(&chan, wait_round_3, &participants, me).await?
    {
        // Verify the share
        // this deviates from the original FROST DKG paper
        // however it matches the FROST implementation of ZCash
        let full_commitment_from = all_full_commitments.index(from)?;
        // Step 5.2
        validate_received_share::<C>(me, from, &signing_share_from, full_commitment_from)?;

        // Compute the sum of all the owned secret shares
        // At the end of this loop, I will be owning a valid secret signing share
        // Step 5.3
        my_signing_share = my_signing_share + signing_share_from.to_scalar();
    }
```

**File:** src/dkg.rs (L530-531)
```rust
    // Step 5.4 and Step 5.5
    broadcast_success(&mut chan, &participants, me, session_id).await?;
```

**File:** src/dkg.rs (L540-553)
```rust
pub async fn do_keygen<C: Ciphersuite>(
    chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    threshold: impl Into<ReconstructionLowerBound>,
    mut rng: impl CryptoRngCore,
) -> Result<KeygenOutput<C>, ProtocolError> {
    let threshold = threshold.into();
    // pick share at random
    let secret = SigningKey::<C>::new(&mut rng).to_scalar();
    // call keyshare
    let keygen_output =
        do_keyshare::<C>(chan, participants, me, threshold, secret, None, &mut rng).await?;
    Ok(keygen_output)
```

**File:** src/dkg.rs (L600-634)
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
```

**File:** src/protocol/helpers.rs (L6-27)
```rust
pub async fn recv_from_others<T>(
    chan: &SharedChannel,
    waitpoint: u64,
    participants: &ParticipantList,
    me: Participant,
) -> Result<Vec<(Participant, T)>, ProtocolError>
where
    T: serde::de::DeserializeOwned,
{
    let mut seen = ParticipantCounter::new(participants);
    seen.put(me);
    let mut messages = Vec::with_capacity(participants.others(me).count());

    while !seen.full() {
        let (from, msg) = chan.recv(waitpoint).await?;
        if seen.put(from) {
            messages.push((from, msg));
        }
    }

    Ok(messages)
}
```
