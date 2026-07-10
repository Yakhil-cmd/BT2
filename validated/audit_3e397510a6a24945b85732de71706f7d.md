### Title
Single Malicious Participant Can Permanently Abort DKG/Reshare/Refresh for All Honest Parties via False Success Vote - (`File: src/dkg.rs`)

---

### Summary

The final round of the DKG, reshare, and refresh protocols requires **unanimous** agreement from all N participants via `broadcast_success`. A single malicious participant can broadcast a `false` success vote, causing the entire key generation to abort for all honest parties who have already completed all prior rounds successfully.

---

### Finding Description

In `src/dkg.rs`, the `do_keyshare` function concludes with a call to `broadcast_success` at line 531:

```rust
// Step 5.4 and Step 5.5
broadcast_success(&mut chan, &participants, me, session_id).await?;
```

The `broadcast_success` function (lines 307–338) uses `do_broadcast` — the echo broadcast primitive — to collect a success vote `(true, session_id)` from every participant, then enforces **unanimous** agreement:

```rust
async fn broadcast_success(...) -> Result<(), ProtocolError> {
    let vote_list = do_broadcast(chan, participants, me, (true, session_id)).await?;
    let vote_list = vote_list
        .into_vec_or_none()
        .ok_or_else(|| ...)?;

    if !vote_list.iter().all(|(_, ref sid)| sid == &session_id) {
        return Err(ProtocolError::AssertionFailed(...));
    }

    if !vote_list.iter().all(|&(boolean, _)| boolean) {   // ← unanimous check
        return Err(ProtocolError::AssertionFailed(
            "A participant seems to have failed its checks. Aborting Protocol!".to_string(),
        ));
    }
    Ok(())
}
```

The echo broadcast protocol (`reliable_broadcast_receive_all`) is Byzantine fault-tolerant for the *delivery* of messages — it guarantees that every honest party receives the same value from each sender. However, it does **not** prevent a malicious sender from broadcasting `(false, session_id)` as their own contribution. Once delivered, the `all(|&(boolean, _)| boolean)` check at line 329 fails, and the entire DKG aborts for every honest participant.

The attack path is:
1. Malicious participant P_m participates honestly through all DKG rounds (polynomial generation, commitment broadcast, share distribution, share verification).
2. In the final `broadcast_success` round, P_m sends `(false, session_id)` instead of `(true, session_id)` over the network channel.
3. The echo broadcast protocol faithfully delivers P_m's `false` vote to all honest parties (this is the *guarantee* of reliable broadcast).
4. Every honest party's `broadcast_success` returns `Err(ProtocolError::AssertionFailed(...))`.
5. All honest parties discard their computed shares and the DKG fails permanently.

This is structurally identical to the external report: a push-to-all mechanism where any single recipient/participant can abort the entire flow for all innocent parties.

---

### Impact Explanation

**High — Permanent denial of key generation, reshare, and refresh for honest parties.**

All three operations (`do_keygen`, `do_reshare`, `do_refresh`) funnel through `do_keyshare`, which unconditionally calls `broadcast_success` as its final step. A single malicious participant can repeatedly abort every DKG attempt, permanently preventing the honest majority from establishing a shared key. The honest parties lose all work invested in prior rounds and cannot recover without excluding the malicious participant and restarting.

---

### Likelihood Explanation

Any participant in the DKG session can trigger this. No special privilege is required beyond being listed in the `participants` array. The attacker participates honestly through all expensive rounds (to avoid early detection) and only deviates in the final, cheap broadcast step. The attack is repeatable at negligible cost.

---

### Recommendation

Replace the unanimous `all(boolean)` check with a threshold-based or identification-based approach:

1. **Identify and exclude the liar:** Since the echo broadcast guarantees that all honest parties see the same vote from each sender, the identity of the participant who voted `false` is known. The protocol can log the culprit and proceed with the remaining honest participants (if the threshold is still met).
2. **Threshold success check:** Require only a quorum (e.g., ≥ threshold) of `true` votes rather than unanimity, consistent with the fault-tolerance model already used in the echo broadcast layer.
3. **Remove the success broadcast entirely:** The share-verification step in Round 5 already provides cryptographic assurance that each honest party's share is valid. A separate success vote adds no security and only introduces a new DOS vector.

---

### Proof of Concept

**Relevant code locations:**

`broadcast_success` unanimous check: [1](#0-0) 

Called unconditionally at the end of `do_keyshare`: [2](#0-1) 

`do_broadcast` delivers every sender's message to all honest parties (exit condition requires all N sessions to complete): [3](#0-2) 

All three public entry points (`do_keygen`, `do_reshare`, `do_refresh`) reach `broadcast_success` through `do_keyshare`: [4](#0-3) [5](#0-4) 

**Attack scenario (3-of-5 DKG):**
- 5 participants run `do_keygen`.
- Participants P1–P4 are honest; P5 is malicious.
- P5 participates honestly through rounds 1–5 (polynomial, commitment, share distribution, share verification all succeed).
- In `broadcast_success`, P5 sends `(false, session_id)` over the channel instead of `(true, session_id)`.
- The echo broadcast delivers P5's `false` to P1–P4.
- P1–P4 each hit the `all(boolean)` check, find `false`, and return `Err(AssertionFailed(...))`.
- The DKG is permanently aborted. P5 can repeat this on every retry.

### Citations

**File:** src/dkg.rs (L329-335)
```rust
    if !vote_list.iter().all(|&(boolean, _)| boolean) {
        return Err(ProtocolError::AssertionFailed(
            "A participant
                seems to have failed its checks. Aborting Protocol!"
                .to_string(),
        ));
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

**File:** src/protocol/echo_broadcast.rs (L321-325)
```rust
                    // then all sessions have ended successfully
                    // we can thus output that the n instances of the broadcast protocols have succeeded
                    if state.iter().all(|x| x.finish_ready) {
                        return Ok(vote_output);
                    }
```
