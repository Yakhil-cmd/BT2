### Title
Single Unresponsive Participant Causes Permanent Denial of DKG, Reshare, and Refresh — (`src/protocol/helpers.rs`, `src/protocol/echo_broadcast.rs`, `src/dkg.rs`)

---

### Summary

Every round of the DKG, reshare, and refresh protocols requires **all N participants** to respond before any honest party can advance. There is no timeout and no mechanism to skip or exclude a non-responsive participant. A single malicious (or crashed) participant who stops sending messages at any round permanently stalls the protocol for all honest parties, with no recovery path available from within the library.

---

### Finding Description

The core message-gathering primitive `recv_from_others` in `src/protocol/helpers.rs` loops unconditionally until every participant in the full set has been heard from:

```rust
while !seen.full() {
    let (from, msg) = chan.recv(waitpoint).await?;
    ...
}
``` [1](#0-0) 

`seen.full()` returns `true` only when the internal counter reaches zero — i.e., when **all N** participants have contributed. [2](#0-1) 

The underlying `recv` call on `SharedChannel` delegates to `MessageBuffer::pop`, which calls `receiver_lock.next().await` with no timeout — it blocks the async task indefinitely if no message arrives. [3](#0-2) 

The echo-broadcast layer has the same property. `reliable_broadcast_receive_all` only returns once **all N** broadcast sessions have reached the `finish_ready` state:

```rust
if state.iter().all(|x| x.finish_ready) {
    return Ok(vote_output);
}
``` [4](#0-3) 

`do_keyshare` — the shared implementation of DKG, reshare, and refresh — calls both primitives at every round:

| Round | Call | Blocks on |
|---|---|---|
| Round 1 | `do_broadcast` (session IDs) | all N |
| Round 2–3 | `do_broadcast` (commitments + proofs) | all N |
| Round 4 | `recv_from_others` (secret shares) | all N |
| Round 5 | `broadcast_success` → `do_broadcast` | all N | [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) 

If a participant stops sending at **any** of these rounds, every other honest participant's async task blocks forever at the corresponding `recv` or `do_broadcast` call. The library exposes no API to abort, time out, or restart the stalled instance; the only recourse is to kill the process and restart the entire protocol from scratch with a different participant set — which itself requires all-N cooperation.

This is structurally identical to the reported Vault bug: just as a paused Aave plugin blocks every deposit/withdrawal and cannot be removed because removal also requires withdrawal, a silent participant blocks every DKG/reshare/refresh round and cannot be bypassed because every round requires that participant.

---

### Impact Explanation

A single malicious participant can permanently deny key generation, reshare, and refresh to all honest parties. Because the library has no internal timeout or exclusion mechanism, the stall is unrecoverable from within the running protocol instance. This maps directly to the allowed High impact: **Permanent denial of key generation, reshare, or refresh for honest parties under valid protocol inputs and documented trust assumptions.**

---

### Likelihood Explanation

Any registered participant — including a newly added one in a reshare — can trigger this by simply dropping off the network after receiving other participants' shares (gaining information while denying completion). The attack requires no cryptographic capability, no key material, and no privileged access. It is reachable by any participant the caller admits to the protocol.

---

### Recommendation

1. **Add a per-round deadline** to `recv_from_others` and `reliable_broadcast_receive_all`. If a participant has not responded within a configurable timeout, return a typed error identifying the silent participant so the caller can exclude them and restart.

2. **Expose the identified culprit** in the error type so callers can restart DKG/reshare with the non-responsive participant removed from the set.

3. **Document the liveness assumption** explicitly: the current protocol requires all N participants to be live and responsive throughout every round, which is a stronger assumption than the t-of-N threshold used for signing.

---

### Proof of Concept

```
Setup: participants = [P1, P2, P3], threshold = 2

1. All three call do_keygen / do_keyshare.
2. Round 1 (session-ID broadcast): P1, P2, P3 all send — proceeds normally.
3. Round 2–3 (commitment broadcast): P1, P2, P3 all send — proceeds normally.
4. Round 4 (secret-share exchange): P3 sends its shares to P1 and P2,
   then goes silent (drops its recv loop).
5. P1 and P2 each call recv_from_others for the secret-share waitpoint.
   seen.full() requires both P2→P1 and P3→P1 (resp. P1→P2 and P3→P2).
   P3 never sends its share to P1 or P2 (or sends to one but not the other).
6. P1 and P2 block indefinitely at `chan.recv(waitpoint).await` inside
   recv_from_others — no timeout fires, no error is returned.
7. DKG never completes. No key shares are produced.
   P3 has learned P1's and P2's shares from round 4 but prevented key
   generation from finishing.
``` [9](#0-8) [10](#0-9)

### Citations

**File:** src/protocol/helpers.rs (L6-26)
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
```

**File:** src/participants.rs (L329-331)
```rust
    pub fn full(&self) -> bool {
        self.counter == 0
    }
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

**File:** src/protocol/echo_broadcast.rs (L323-325)
```rust
                    if state.iter().all(|x| x.finish_ready) {
                        return Ok(vote_output);
                    }
```

**File:** src/dkg.rs (L362-362)
```rust
    let session_ids = do_broadcast(&mut chan, &participants, me, my_session_id).await?;
```

**File:** src/dkg.rs (L435-441)
```rust
    let commitments_and_proofs_map = do_broadcast(
        &mut chan,
        &participants,
        me,
        (commitment, proof_of_knowledge),
    )
    .await?;
```

**File:** src/dkg.rs (L513-528)
```rust
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

        // Compute the sum of all the owned secret shares
        // At the end of this loop, I will be owning a valid secret signing share
        // Step 5.3
        my_signing_share = my_signing_share + signing_share_from.to_scalar();
    }
```

**File:** src/dkg.rs (L531-531)
```rust
    broadcast_success(&mut chan, &participants, me, session_id).await?;
```
