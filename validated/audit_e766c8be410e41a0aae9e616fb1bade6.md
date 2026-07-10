### Title
Single Malicious Participant Aborts All Honest Parties in DKG/Reshare/Refresh Final Round — (`src/dkg.rs`)

### Summary

`broadcast_success` applies a zero-tolerance session-id consistency check over the output of a reliable broadcast. Because the reliable broadcast protocol guarantees that all honest parties *will* deliver whatever value a malicious sender broadcasts, a single malicious participant within the documented BFT threshold (`MaxFaulty = ⌊(N−1)/3⌋`) can broadcast a wrong `session_id` in the final round and cause every honest party to return `Err(AssertionFailed)`, permanently aborting DKG, reshare, and refresh.

---

### Finding Description

`do_keyshare` concludes at Step 5.4 by calling `broadcast_success`, which runs a full reliable echo-broadcast and then checks that every delivered value matches the local `session_id`:

```rust
// src/dkg.rs:314
let vote_list = do_broadcast(chan, participants, me, (true, session_id)).await?;
```

```rust
// src/dkg.rs:321-327
if !vote_list.iter().all(|(_, ref sid)| sid == &session_id) {
    return Err(ProtocolError::AssertionFailed(
        "A participant broadcast the wrong session id. Aborting Protocol!"
            .to_string(),
    ));
}
``` [1](#0-0) 

The reliable broadcast protocol (`reliable_broadcast_receive_all`) guarantees the **Agreement** property: once any correct process delivers a value from sender M, every correct process eventually delivers that same value. It does **not** prevent M from broadcasting an arbitrary value. For N=4 with `echo_t=2`, `ready_t=1`:

- M sends `SEND(wrong_sid)` to H1, H2, H3.
- Each honest party echoes `ECHO(wrong_sid)` to all others.
- Each honest party collects 3 echo votes > `echo_t=2` → sends `READY(wrong_sid)`.
- Each honest party collects 3 ready votes > `2*ready_t=2` → **delivers** `wrong_sid` for M's slot. [2](#0-1) 

After delivery, the check at line 321 fails for **all** honest parties because `wrong_sid ≠ session_id`. The `?` propagation at the call site aborts `do_keyshare` for every honest participant:

```rust
// src/dkg.rs:531
broadcast_success(&mut chan, &participants, me, session_id).await?;
``` [3](#0-2) 

This affects `do_keygen`, `do_reshare`, and `do_refresh` since all three funnel through `do_keyshare`. [4](#0-3) [5](#0-4) 

---

### Impact Explanation

Every honest party returns a terminal `Err(AssertionFailed)` from `do_keyshare`. There is no retry path inside the protocol; the caller must restart the entire DKG/reshare/refresh from scratch. Because the malicious party can repeat the attack on every attempt, this constitutes **permanent denial** of key generation, resharing, and refresh for all honest parties.

---

### Likelihood Explanation

The documented BFT tolerance is `MaxFaulty = ⌊(N−1)/3⌋`:

> "our DKG/Resharing protocol can only tolerate n/3 malicious parties" [6](#0-5) [7](#0-6) 

For N=4, `MaxFaulty=1`. A single compromised participant — well within the stated tolerance — is sufficient. The attack requires only that the malicious party substitute a random 32-byte value for `session_id` in the final broadcast. No cryptographic material needs to be broken; the attacker only needs to deviate in one message field in one round.

---

### Recommendation

The `broadcast_success` check must be made fault-tolerant. Two concrete options:

1. **Remove the session-id from the final broadcast entirely.** The `session_id` was already bound into all prior commitments and proofs; re-broadcasting it in the final round adds no security and creates this abort vector. Broadcast only the boolean success flag.

2. **Accept up to `MaxFaulty` mismatched session-ids.** Count how many delivered entries differ from the local `session_id` and abort only if that count exceeds `MaxFaulty = ⌊(N−1)/3⌋`. This mirrors the fault-tolerance already provided by the underlying broadcast layer.

---

### Proof of Concept

**Setup:** N=4 participants (H1, H2, H3, M), threshold=2, `MaxFaulty=1`.

**Steps:**
1. Run `do_keygen` with all four participants.
2. M participates honestly through rounds 1–5 (broadcasts correct `my_session_id`, correct commitment, correct proof, correct share evaluations).
3. In the final `broadcast_success` call, M sends `SEND((true, random_32_bytes))` instead of `SEND((true, session_id))`.
4. H1, H2, H3 each echo and ready-amplify `random_32_bytes` for M's slot (3 echo votes > `echo_t=2`; 3 ready votes > `2*ready_t=2`).
5. `vote_list` for H1, H2, H3 each contains `(true, random_32_bytes)` for M's entry.
6. The check `sid == &session_id` fails for M's entry on every honest party.
7. H1, H2, H3 all return `Err(AssertionFailed("A participant broadcast the wrong session id. Aborting Protocol!"))`.

**Expected assertion:** all three honest parties return `Err`, DKG fails despite only 1 malicious party within the documented `MaxFaulty=1` tolerance. [8](#0-7) [9](#0-8)

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

**File:** src/protocol/echo_broadcast.rs (L67-78)
```rust
fn echo_ready_thresholds(n: usize) -> (usize, usize) {
    // case where no malicious parties are assumed: when n <= 3/
    // In this case the echo and ready thresholds are both 0
    // later we compare if we have collected more votes than these thresholds
    if n <= 3 {
        return (0, 0);
    }
    // we should always have n >= 3*threshold + 1
    let broadcast_threshold = (n - 1) / 3;
    let echo_threshold = usize::midpoint(n, broadcast_threshold);
    (echo_threshold, broadcast_threshold)
}
```

**File:** src/protocol/echo_broadcast.rs (L293-325)
```rust
                if state_sid.data_ready.get(&data).ok_or_else(|| {
                    ProtocolError::Other("Missing element in CounterList".to_string())
                })? > 2 * ready_t
                {
                    // skip all types of messages sent for session sid from now on
                    state_sid.finish_send = true;
                    state_sid.finish_echo = true;
                    state_sid.finish_ready = true;

                    // return a map of participant data
                    let p = participants
                        .get_participant(sid)
                        .ok_or_else(|| ProtocolError::Other("Missing participant".to_string()))?;
                    // make a list of data and return them
                    vote_output.put(p, data.clone());

                    // Output error if the received vote after broadcast is not
                    // the same as the one originally sent
                    if sid == participants.index(me)? && MessageType::Send(data) != send_vote {
                        return Err(ProtocolError::AssertionFailed(
                            "Too many malicious parties, way above the assumed threshold:
                            The message output after the broadcast protocol is not the same as
                            the one originally sent by me"
                                .to_string(),
                        ));
                    }

                    // if all the ready slots are set to true
                    // then all sessions have ended successfully
                    // we can thus output that the n instances of the broadcast protocols have succeeded
                    if state.iter().all(|x| x.finish_ready) {
                        return Ok(vote_output);
                    }
```

**File:** README.md (L157-163)
```markdown
* **🚨 Important 🚨:** Our DKG/Resharing protocol is the same for ECDSA, EdDSA
  and CKD but differs depending on the underlying elliptic curve instantiation.
  Internally, this DKG makes use of a reliable broadcast channel implemented for
  asynchronous peer-to-peer communication. Due to a fundamental impossibility
  theorem for asynchronous broadcast channel, our DKG/Resharing protocol can
  only tolerate $\frac{n}{3}$ malicious parties where $n$ is the total number of
  parties.
```

**File:** docs/dkg.md (L28-29)
```markdown
Due to the fact that PedPop+ utilizes reliable broadcast channel to securely generate private shares, it thus lies on the edge between the asynchronous distributed systems and cryptography. For this reason, we set
$\mathsf{MaxFaulty} = \frac{N - 1}{3}$ as an invariable parameter and allow our key generation and key resharing protocols to fix/modify only the $\mathsf{threshold}$ depending on the scheme requirements and on the library user's choice.
```
