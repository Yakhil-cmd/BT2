### Title
Echo Broadcast Threshold Formula Returns Zero for n ≤ 3, Bypassing Byzantine Fault Tolerance in DKG — (`File: src/protocol/echo_broadcast.rs`)

---

### Summary

The `echo_ready_thresholds` function in `src/protocol/echo_broadcast.rs` returns `(0, 0)` for any participant count `n ≤ 3`. This means no quorum is required for message delivery in the echo broadcast protocol when `n = 2` or `n = 3`. Because DKG uses echo broadcast to agree on polynomial commitments, a single malicious participant in a 3-party DKG can equivocate — sending different commitments to different honest parties — causing them to derive inconsistent master public keys.

---

### Finding Description

The `echo_ready_thresholds` function computes the echo and ready thresholds for the Byzantine Reliable Broadcast protocol:

```rust
fn echo_ready_thresholds(n: usize) -> (usize, usize) {
    // case where no malicious parties are assumed: when n <= 3
    if n <= 3 {
        return (0, 0);
    }
    let broadcast_threshold = (n - 1) / 3;
    let echo_threshold = usize::midpoint(n, broadcast_threshold);
    (echo_threshold, broadcast_threshold)
}
``` [1](#0-0) 

When `n ≤ 3`, both `echo_t` and `ready_t` are `0`. These thresholds are used in `reliable_broadcast_receive_all` as follows:

- **Echo phase delivery condition**: `count > echo_t` → `count > 0` → any single ECHO triggers READY
- **Ready amplification condition**: `count > ready_t` → `count > 0` → any single READY triggers amplification
- **Delivery condition**: `count > 2 * ready_t` → `count > 0` → any single READY delivers the message [2](#0-1) [3](#0-2) 

Because each participant processes its own simulated ECHO immediately (via `is_simulated_vote = true`), with `echo_t = 0` a participant delivers a message after receiving only its own simulated ECHO — before receiving any message from other parties. This means:

**Equivocation attack with n = 3:**
1. Malicious party `M` sends `SEND(data_A)` to honest party `A` and `SEND(data_B)` to honest party `B`.
2. `A` echoes `data_A`, processes its own simulated ECHO (`count = 1 > 0`), sends `READY(data_A)`, and immediately delivers `data_A` (since `count = 1 > 0 = 2 * ready_t`).
3. `B` echoes `data_B`, processes its own simulated ECHO (`count = 1 > 0`), sends `READY(data_B)`, and immediately delivers `data_B`.
4. `A` and `B` now hold different values for `M`'s broadcast — the echo broadcast's equivocation protection is completely absent.

DKG imports and calls `do_broadcast` to agree on polynomial commitments across all participants: [4](#0-3) 

With inconsistent commitments, each honest party computes a different master public key (`pk = Σ C_j(0)`), corrupting the DKG output.

The DKG initialization enforces `participants.len() >= 2` and `threshold >= 2`, making `n = 3, threshold = 2` (1 malicious party tolerated) a fully valid and common configuration: [5](#0-4) 

The comment in `echo_ready_thresholds` states "no malicious parties are assumed when n ≤ 3", but this assumption is **never enforced** at the DKG initialization layer. The DKG's own threshold semantics explicitly tolerate `threshold - 1` malicious parties, creating a direct mismatch for `n = 3`.

---

### Impact Explanation

**High — Corruption of DKG outputs so honest parties accept inconsistent public keys.**

A malicious participant in a 3-party DKG can cause the two honest parties to derive different master public keys. Any subsequent signing or resharing built on these inconsistent keys will produce unusable or invalid outputs. The inconsistency is undetectable within the DKG protocol itself (there is no cross-party public key consistency check in fresh keygen).

---

### Likelihood Explanation

`n = 3` with `threshold = 2` is a minimal and realistic deployment configuration (e.g., 2-of-3 multisig). Any such deployment with one malicious participant is fully vulnerable. No special preconditions are required beyond the attacker being one of the three participants.

---

### Recommendation

Remove the blanket `n ≤ 3 → (0, 0)` shortcut and apply the standard formula for all `n ≥ 2`, or enforce at DKG initialization that `participants.len() >= 4` when Byzantine fault tolerance is required. If `n ≤ 3` configurations must be supported, document clearly that they provide **no** Byzantine fault tolerance and that all participants must be trusted.

---

### Proof of Concept

With `n = 3`, `echo_t = 0`, `ready_t = 0`:

```
Participants: A (honest), B (honest), M (malicious)

M's broadcast session (sid = M's index):
  M → A: SEND(commitment_A)   // equivocating
  M → B: SEND(commitment_B)   // different value

A processes SEND(commitment_A):
  A sends ECHO(commitment_A) to all
  A processes own simulated ECHO: count(commitment_A) = 1 > 0 = echo_t
  → A sends READY(commitment_A)
  A processes own simulated READY: count(commitment_A) = 1 > 0 = 2*ready_t
  → A DELIVERS commitment_A  ← immediately, no quorum

B processes SEND(commitment_B):
  B sends ECHO(commitment_B) to all
  B processes own simulated ECHO: count(commitment_B) = 1 > 0 = echo_t
  → B sends READY(commitment_B)
  B processes own simulated READY: count(commitment_B) = 1 > 0 = 2*ready_t
  → B DELIVERS commitment_B  ← immediately, no quorum

Result:
  A computes pk_A = commitment_A + C_A(0) + C_B(0)
  B computes pk_B = commitment_B + C_A(0) + C_B(0)
  pk_A ≠ pk_B  → DKG output is inconsistent
``` [6](#0-5)

### Citations

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

**File:** src/protocol/echo_broadcast.rs (L191-235)
```rust
        match vote.clone() {
            // Receive send vote then echo to everybody
            MessageType::Send(data) => {
                // If the sender is not the one identified by the session id (sid)
                // or if the sender have already delivered a MessageType::Send message
                // then skip.
                // The second condition prevents a malicious party starting the protocol
                // on behalf on somebody else
                if state_sid.finish_send || sid != participants.index(from)? {
                    continue;
                }
                vote = MessageType::Echo(data);
                // upon receiving a send message, echo it
                chan.send_many(wait, &(&sid, &vote))?;
                state_sid.finish_send = true;

                // simulate an echo vote sent by me
                is_simulated_vote = true;
                from = me;
            }
            // Receive send vote then echo to everybody
            MessageType::Echo(data) => {
                // skip if I received echo message from the sender in a specific session (sid)
                // or if I had already passed to the ready phase in this same session
                if !state_sid.seen_echo.put(from) || state_sid.finish_echo {
                    continue;
                }
                // insert or increment the number of collected echo of a specific vote
                state_sid.data_echo.insert_or_increase_counter(data.clone());

                // upon gathering strictly more than (n+f)/2 votes
                // for a result, deliver Ready.
                if state_sid.data_echo.get(&data).ok_or_else(|| {
                    ProtocolError::Other("Missing element in CounterList".to_string())
                })? > echo_t
                {
                    vote = MessageType::Ready(data);
                    chan.send_many(wait, &(&sid, &vote))?;
                    // state that the echo phase for session id (sid) is done
                    state_sid.finish_echo = true;

                    // simulate a ready vote sent by me
                    is_simulated_vote = true;
                    from = me;
                }
```

**File:** src/protocol/echo_broadcast.rs (L280-296)
```rust
                if state_sid.data_ready.get(&data).ok_or_else(|| {
                    ProtocolError::Other("Missing element in CounterList".to_string())
                })? > ready_t
                    && !state_sid.finish_amplification
                {
                    vote = MessageType::Ready(data.clone());
                    chan.send_many(wait, &(&sid, &vote))?;
                    state_sid.finish_amplification = true;

                    // simulate a ready vote sent by me
                    is_simulated_vote = true;
                    from = me;
                }
                if state_sid.data_ready.get(&data).ok_or_else(|| {
                    ProtocolError::Other("Missing element in CounterList".to_string())
                })? > 2 * ready_t
                {
```

**File:** src/dkg.rs (L10-11)
```rust
    echo_broadcast::do_broadcast, helpers::recv_from_others, internal::SharedChannel,
};
```

**File:** src/dkg.rs (L637-660)
```rust
// Step 1.1
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
```
