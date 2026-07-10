### Title
Honest Participant Abort Without Failure Broadcast Causes Permanent Denial of Key Generation — (File: `src/dkg.rs`)

---

### Summary
When a participant in `do_keyshare` encounters a fatal error mid-protocol (e.g., an invalid secret share injected by a malicious participant), it returns immediately without participating in the final `broadcast_success` round. Other honest participants, already waiting inside `broadcast_success`'s echo-broadcast loop, block indefinitely for the aborted participant's vote — permanently denying key generation to all remaining honest parties.

---

### Finding Description

`do_keyshare` (`src/dkg.rs:342`) is the shared implementation of DKG, reshare, and refresh. Its final step is:

```rust
// src/dkg.rs:531
broadcast_success(&mut chan, &participants, me, session_id).await?;
```

`broadcast_success` (lines 307–338) always broadcasts `(true, session_id)` via `do_broadcast` (the echo-broadcast protocol) and then asserts that **every** participant's vote is `(true, correct_session_id)`:

```rust
if !vote_list.iter().all(|(_, ref sid)| sid == &session_id) { ... }
if !vote_list.iter().all(|&(boolean, _)| boolean) { ... }
``` [1](#0-0) 

The echo-broadcast protocol (`reliable_broadcast_receive_all`) runs **N independent broadcast instances** — one per participant as sender — and only terminates when **all N** instances complete. Each instance requires the designated sender to emit a SEND message to start.

If a participant (A) fails earlier in the protocol — for example at line 522:

```rust
validate_received_share::<C>(me, from, &signing_share_from, full_commitment_from)?;
``` [2](#0-1) 

— it returns `ProtocolError::InvalidSecretShare(from)` immediately and **never reaches `broadcast_success`**. Consequently, A never emits its SEND message for the echo-broadcast round. The remaining honest participants, already inside `broadcast_success`, wait indefinitely for A's SEND message.

There is no timeout in `MessageBuffer::pop` (`src/protocol/internal.rs:245–255`); it awaits unconditionally:

```rust
receiver_lock
    .next()
    .await
    .expect("Reference to sender held")
``` [3](#0-2) 

A malicious participant M can deliberately trigger this by sending a cryptographically invalid share exclusively to participant A via the private channel at line 505:

```rust
chan.send_private(wait_round_3, p, &signing_share_to_p)?;
``` [4](#0-3) 

A detects the invalid share, aborts, and never signals failure to the rest of the group. The remaining honest participants hang forever.

---

### Impact Explanation

All honest participants except A are permanently blocked inside `broadcast_success`. They cannot complete DKG/reshare/refresh, cannot obtain key shares, and cannot sign. The library provides no timeout or abort-notification mechanism (`MessageBuffer::pop` blocks unconditionally), so the denial is indefinite from the library's perspective. This matches the allowed **High** impact: **Permanent denial of key generation for honest parties under valid protocol inputs and documented trust assumptions**.

---

### Likelihood Explanation

Any single malicious participant in the protocol can execute this attack with minimal effort: craft one invalid share for one target honest participant, send it privately, and participate honestly in all other rounds. The attack requires no cryptographic break, no external compromise, and no coordination beyond being a registered participant. The private share channel (`send_private`) is the exact mechanism that makes targeted delivery to a single victim trivially achievable.

---

### Recommendation

When a participant detects a fatal error before `broadcast_success`, it should still participate in the final broadcast round with a failure signal (e.g., `(false, session_id)`) before returning the error. `broadcast_success` should be refactored to accept an optional error and broadcast the appropriate flag. This mirrors the fix recommended for SmartEscrow: perform the cleanup (notify peers of termination) before exiting, so that other participants can detect the failure and abort gracefully rather than waiting indefinitely.

---

### Proof of Concept

1. Participants: honest A, B, C, D; malicious M. All run `do_keyshare`.
2. M sends a valid share to B, C, D but a crafted invalid share to A (`src/dkg.rs:505`, `chan.send_private`).
3. A reaches line 522 (`validate_received_share`), which returns `Err(ProtocolError::InvalidSecretShare(M))`.
4. A exits `do_keyshare` with an error — it never calls `broadcast_success` and never emits a SEND message for the echo-broadcast round.
5. B, C, D complete share validation, reach line 531, and enter `broadcast_success` → `do_broadcast`.
6. `reliable_broadcast_receive_all` opens session A (A as sender) and calls `MessageBuffer::pop` waiting for A's SEND message.
7. A's SEND message never arrives. `pop` blocks unconditionally (`src/protocol/internal.rs:252–254`).
8. B, C, D are permanently stuck. Key generation is denied for all honest parties. [5](#0-4) [3](#0-2)

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

**File:** src/dkg.rs (L499-506)
```rust
    for p in participants.others(me) {
        // securely send to each other participant a secret share
        // using the evaluation secret polynomial on the identifier of the recipient
        // should not panic as secret_coefficients are created internally
        let signing_share_to_p = secret_coefficients.eval_at_participant(p)?;
        // send the evaluation privately to participant p
        chan.send_private(wait_round_3, p, &signing_share_to_p)?;
    }
```

**File:** src/dkg.rs (L520-523)
```rust
        let full_commitment_from = all_full_commitments.index(from)?;
        // Step 5.2
        validate_received_share::<C>(me, from, &signing_share_from, full_commitment_from)?;

```

**File:** src/dkg.rs (L531-531)
```rust
    broadcast_success(&mut chan, &participants, me, session_id).await?;
```

**File:** src/protocol/internal.rs (L245-255)
```rust
    async fn pop(&self, header: MessageHeader) -> (Participant, MessageData) {
        let receiver = {
            let mut messages_lock = self.messages.lock().expect("lock should not fail");
            messages_lock.entry(header).or_default().receiver.clone()
        };
        let mut receiver_lock = receiver.lock().await;
        receiver_lock
            .next()
            .await
            .expect("Reference to sender held")
    }
```
