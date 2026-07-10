### Title
Single Malicious Participant Can Permanently Halt DKG / Reshare for All Honest Parties via Invalid Private Share — (`File: src/dkg.rs`)

---

### Summary

A single malicious participant in the DKG or reshare protocol can cause all honest parties to wait indefinitely by sending a valid public commitment but an invalid private share to exactly one honest participant. That honest participant aborts before reaching the final `broadcast_success` round, while all remaining honest participants block forever waiting for its vote. Because the library's `recv_from_others` loop requires messages from **every** participant before it can proceed, the abort of one party permanently stalls the entire group.

---

### Finding Description

The `do_keyshare` function in `src/dkg.rs` implements the PedPop+ DKG/reshare protocol in five rounds. In Round 4 (Step 4.6), each participant privately sends a secret polynomial evaluation to every other participant:

```rust
// Step 4.6
for p in participants.others(me) {
    let signing_share_to_p = secret_coefficients.eval_at_participant(p)?;
    chan.send_private(wait_round_3, p, &signing_share_to_p)?;
}
```

In Round 5 (Step 5.2), each recipient validates the received share against the sender's publicly broadcast commitment:

```rust
// Step 5.2
validate_received_share::<C>(me, from, &signing_share_from, full_commitment_from)?;
```

If `validate_received_share` returns `ProtocolError::InvalidSecretShare(from)`, the `?` operator immediately propagates the error and the honest participant exits `do_keyshare` **without ever reaching** the final success broadcast at line 531:

```rust
// Step 5.4 and Step 5.5
broadcast_success(&mut chan, &participants, me, session_id).await?;
```

`broadcast_success` calls `do_broadcast`, which internally calls `reliable_broadcast_receive_all`. That function loops on:

```rust
while !seen.full() {
    let (from, msg) = chan.recv(wait).await?;
    ...
}
```

Because `seen.full()` requires a message from **every** participant, and the aborted participant will never send its vote, all remaining honest participants block in this loop indefinitely.

The attack is precise and surgical:

1. Malicious participant P_m broadcasts a **valid** commitment and proof-of-knowledge in Round 3 (passes `verify_proof_of_knowledge` and `verify_commitment_hash`).
2. P_m sends **valid** shares to all participants except the chosen target P_h.
3. P_m sends an **invalid** share to P_h via `chan.send_private`.
4. P_h's `validate_received_share` fails → P_h aborts before `broadcast_success`.
5. All other honest participants are already inside `broadcast_success`'s `do_broadcast`, waiting for P_h's vote that will never arrive.

The attack is repeatable on every retry, making the denial effectively permanent as long as P_m remains in the participant set.

---

### Impact Explanation

**High — Permanent denial of DKG, reshare, and refresh for honest parties.**

All honest participants (except the targeted P_h) are permanently blocked inside `broadcast_success`. P_h itself has already aborted with an error. No honest party can complete the protocol and obtain a valid key share. Because the attack can be replayed on every restart attempt (P_m simply sends another invalid share to P_h or a different target), the denial is not bounded by a single session. This affects `keygen`, `reshare`, and `refresh` equally, since all three call `do_keyshare`.

---

### Likelihood Explanation

Any participant who is admitted to the DKG or reshare session can execute this attack. The malicious participant needs only to:
- Participate honestly through Rounds 1–3 (so their commitment passes verification).
- Send a single crafted invalid scalar as the private share to one target in Round 4.

No cryptographic break, no key leakage, and no external dependency is required. The attacker controls only their own private channel messages, which is within the standard threat model for a malicious participant.

---

### Recommendation

1. **Identify and exclude the culprit before aborting.** When `validate_received_share` fails, the error already names the sender (`ProtocolError::InvalidSecretShare(from)`). Instead of immediately aborting, the honest participant should broadcast the identity of the cheating party so that all other participants can agree to exclude P_m and restart without them.

2. **Broadcast failure before exiting.** If a participant must abort, it should still participate in the `broadcast_success` round by broadcasting `(false, session_id)` so that all other participants receive a definitive signal and can abort cleanly rather than waiting indefinitely.

3. **Implement a complaint/accusation round.** Standard DKG protocols (e.g., Pedersen DKG, GJKR) include a complaint round after share distribution. A participant who receives an invalid share publicly accuses the sender; if the accusation is valid, the sender is disqualified. This prevents a single malicious participant from halting the protocol.

---

### Proof of Concept

**Setup:** 4 participants `[P1, P2, P3, P4]`, threshold = 2. P4 is malicious.

**Round 1–3 (honest):** P4 generates a valid polynomial, computes a valid commitment, and broadcasts it. All participants accept P4's commitment.

**Round 4 (attack):** P4 sends valid shares `f_4(P1)`, `f_4(P2)`, `f_4(P3)` to P1, P2, P3 respectively — except it sends a random garbage scalar `r ≠ f_4(P1)` to P1.

**Round 5:**
- P1 calls `validate_received_share(P1, P4, r, commitment_P4)` → fails → P1 exits `do_keyshare` at line 522 with `ProtocolError::InvalidSecretShare(P4)`.
- P2, P3, P4 all pass share validation and reach `broadcast_success` at line 531.
- Inside `broadcast_success`, `do_broadcast` calls `reliable_broadcast_receive_all`, which loops `while !seen.full()` waiting for P1's vote.
- P1 has already exited. Its vote never arrives.
- P2, P3, P4 are permanently blocked.

**Result:** DKG fails for all parties. No key shares are produced. Restarting the protocol with P4 still present allows P4 to repeat the attack against any target. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** src/dkg.rs (L259-285)
```rust
fn validate_received_share<C: Ciphersuite>(
    me: Participant,
    from: Participant,
    signing_share_from: &SigningShare<C>,
    commitment: &VerifiableSecretSharingCommitment<C>,
) -> Result<(), ProtocolError> {
    let id = me.to_identifier::<C>()?;

    // The verification is exactly the same as the regular SecretShare verification;
    // however the required components are in different places.
    // Build a temporary SecretShare so what we can call verify().
    let secret_share = SecretShare::new(id, *signing_share_from, commitment.clone());

    // Verify the share. We don't need the result.
    // Identify the culprit if an InvalidSecretShare error is returned.
    secret_share.verify().map_err(|e| {
        if let Error::InvalidSecretShare { .. } = e {
            ProtocolError::InvalidSecretShare(from)
        } else {
            ProtocolError::AssertionFailed(format!(
                "could not
            extract the verification key matching the secret
            share sent by {from:?}"
            ))
        }
    })?;
    Ok(())
```

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

**File:** src/dkg.rs (L498-522)
```rust
    // Step 4.6
    for p in participants.others(me) {
        // securely send to each other participant a secret share
        // using the evaluation secret polynomial on the identifier of the recipient
        // should not panic as secret_coefficients are created internally
        let signing_share_to_p = secret_coefficients.eval_at_participant(p)?;
        // send the evaluation privately to participant p
        chan.send_private(wait_round_3, p, &signing_share_to_p)?;
    }

    // Start Round 5
    // compute my secret evaluation of my private polynomial
    // should not panic as secret_coefficients are created internally
    let mut my_signing_share = secret_coefficients.eval_at_participant(me)?.0;
    // receive evaluations from all participants
    // Step 5.1
    for (from, signing_share_from) in
        recv_from_others(&chan, wait_round_3, &participants, me).await?
    {
        // Verify the share
        // this deviates from the original FROST DKG paper
        // however it matches the FROST implementation of ZCash
        let full_commitment_from = all_full_commitments.index(from)?;
        // Step 5.2
        validate_received_share::<C>(me, from, &signing_share_from, full_commitment_from)?;
```

**File:** src/dkg.rs (L530-531)
```rust
    // Step 5.4 and Step 5.5
    broadcast_success(&mut chan, &participants, me, session_id).await?;
```

**File:** src/protocol/helpers.rs (L19-24)
```rust
    while !seen.full() {
        let (from, msg) = chan.recv(waitpoint).await?;
        if seen.put(from) {
            messages.push((from, msg));
        }
    }
```
