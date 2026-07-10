### Title
Single Malicious Participant Can Permanently Abort DKG/Reshare/Refresh by Broadcasting a False Success Vote - (File: src/dkg.rs)

---

### Summary

The `broadcast_success` function in `src/dkg.rs` requires **all** N participants to broadcast `(true, session_id)` in the final round of DKG. A single malicious participant — even one within the documented `MaxFaulty = (N-1)/3` Byzantine tolerance bound — can deviate by broadcasting `(false, session_id)`, causing every honest party to abort key generation after completing all cryptographic work. Because the attacker can repeat this indefinitely, it constitutes permanent denial of DKG, reshare, and refresh for honest parties.

---

### Finding Description

`broadcast_success` is the final step of `do_keyshare`, which implements DKG, reshare, and refresh:

```rust
// src/dkg.rs lines 307-338
async fn broadcast_success(
    chan: &mut SharedChannel,
    participants: &ParticipantList,
    me: Participant,
    session_id: HashOutput,
) -> Result<(), ProtocolError> {
    let vote_list = do_broadcast(chan, participants, me, (true, session_id)).await?;
    let vote_list = vote_list
        .into_vec_or_none()
        .ok_or_else(|| ProtocolError::AssertionFailed("vote_list is empty".to_string()))?;

    if !vote_list.iter().all(|(_, ref sid)| sid == &session_id) {
        return Err(ProtocolError::AssertionFailed(
            "A participant broadcast the wrong session id. Aborting Protocol!".to_string(),
        ));
    }

    if !vote_list.iter().all(|&(boolean, _)| boolean) {
        return Err(ProtocolError::AssertionFailed(
            "A participant seems to have failed its checks. Aborting Protocol!".to_string(),
        ));
    }
    Ok(())
}
``` [1](#0-0) 

The function is called unconditionally at the end of `do_keyshare`, after all secret shares have been computed and validated:

```rust
// src/dkg.rs line 531
broadcast_success(&mut chan, &participants, me, session_id).await?;
``` [2](#0-1) 

The check `vote_list.iter().all(|&(boolean, _)| boolean)` requires **every** participant's vote to be `true`. A malicious participant who sends `(false, session_id)` via the echo-broadcast channel will have their vote faithfully delivered to all honest parties by the Byzantine-reliable broadcast layer. The honest parties then unconditionally abort.

The echo-broadcast protocol (`do_broadcast` → `reliable_broadcast_receive_all`) is Byzantine fault-tolerant and will correctly deliver the malicious `false` vote to all honest participants: [3](#0-2) 

The protocol's own documentation states `MaxFaulty = (N-1)/3` as the Byzantine tolerance bound, meaning up to that many malicious participants should be tolerated. However, `broadcast_success` enforces a unanimous-success requirement that is incompatible with any Byzantine fault tolerance — a single deviating participant suffices to abort. [4](#0-3) 

---

### Impact Explanation

**High — Permanent denial of key generation, reshare, and refresh for honest parties.**

`do_keyshare` is the shared core of `do_keygen`, `do_reshare`, and `do_refresh`: [5](#0-4) [6](#0-5) 

All three operations fail if `broadcast_success` returns an error. Because the malicious participant can repeat the attack on every session attempt, honest parties can never obtain valid key shares, making signing permanently impossible. No cryptographic material is leaked; the impact is complete denial of the key-management lifecycle.

---

### Likelihood Explanation

**High.** Any single participant in the DKG/reshare/refresh session can perform this attack:

- No special privilege is required beyond being a listed participant.
- The attacker participates honestly through all cryptographic rounds (avoiding detection by proof-of-knowledge and share-validity checks), then deviates only in the final `broadcast_success` round.
- The echo-broadcast layer guarantees the malicious `false` vote is delivered to all honest parties — the attacker does not need to control the network.
- The attack is repeatable at zero marginal cost on every retry.

---

### Recommendation

Replace the unanimous-success requirement with a threshold-tolerant check. The protocol should abort only if **more than `MaxFaulty`** participants report failure. Participants who report failure (or whose votes are missing) should be identified and excluded from the next session rather than causing a global abort. Concretely:

1. Count the number of `false` votes in `vote_list`.
2. If `false_count > max_malicious`, abort and report the identified malicious participants.
3. If `false_count <= max_malicious`, continue — the honest majority has confirmed success.

This mirrors the Byzantine fault-tolerance guarantee already provided by the echo-broadcast layer and aligns `broadcast_success` with the documented `MaxFaulty` bound.

---

### Proof of Concept

**Setup**: N = 4 participants (P0, P1, P2, P3); threshold = 2; `MaxFaulty = (4-1)/3 = 1`. P3 is malicious.

1. All four participants run `do_keyshare` honestly through rounds 1–5 (session-id broadcast, commitment broadcast, share distribution, share validation).
2. P0, P1, P2 call `broadcast_success` and send `(true, session_id)` via `do_broadcast`.
3. P3 deviates: instead of calling `broadcast_success` with `(true, session_id)`, it sends `(false, session_id)` through the echo-broadcast channel.
4. The echo-broadcast protocol faithfully delivers P3's `(false, session_id)` to P0, P1, and P2 (Byzantine reliability guarantees delivery within the `MaxFaulty = 1` bound).
5. P0, P1, P2 each evaluate `vote_list.iter().all(|&(boolean, _)| boolean)` → `false` (because P3's entry is `false`).
6. All three honest parties return `Err(ProtocolError::AssertionFailed("A participant seems to have failed its checks. Aborting Protocol!"))`.
7. No `KeygenOutput` is returned; honest parties hold no usable key shares.
8. P3 repeats on every retry, permanently blocking key generation. [1](#0-0) [2](#0-1)

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

**File:** src/dkg.rs (L529-537)
```rust

    // Step 5.4 and Step 5.5
    broadcast_success(&mut chan, &participants, me, session_id).await?;

    // Return the key pair
    Ok(KeygenOutput {
        private_share: SigningShare::new(my_signing_share),
        public_key: verifying_key,
    })
```

**File:** src/dkg.rs (L540-554)
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
}
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

**File:** src/protocol/echo_broadcast.rs (L334-348)
```rust
pub async fn do_broadcast<'a, T>(
    chan: &mut SharedChannel,
    participants: &'a ParticipantList,
    me: Participant,
    data: T,
) -> Result<ParticipantMap<'a, T>, ProtocolError>
where
    T: Serialize + Clone + DeserializeOwned + PartialEq,
{
    let wait_broadcast = chan.next_waitpoint();
    let send_vote = reliable_broadcast_send(chan, wait_broadcast, participants, me, data)?;
    let vote_list =
        reliable_broadcast_receive_all(chan, wait_broadcast, participants, me, send_vote).await?;
    Ok(vote_list)
}
```
