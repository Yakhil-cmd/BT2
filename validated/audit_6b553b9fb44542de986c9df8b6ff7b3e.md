### Title
Single Malicious Participant Can Permanently Stall DKG, Reshare, Refresh, and Presign via Unbounded `recv_from_others` — (File: `src/protocol/helpers.rs`)

---

### Summary

The `recv_from_others` helper function, used in DKG, reshare, refresh, and FROST presign protocols, blocks indefinitely until **every** participant in the session has delivered a message. A single malicious participant can permanently stall these protocols by withholding their message. Unlike the echo-broadcast layer, which explicitly tolerates up to `⌊(N−1)/3⌋` Byzantine faults, `recv_from_others` has no timeout, no fault-tolerance threshold, and no fallback path — directly analogous to the "failing messenger blocks the entire execution path" pattern in the external report.

---

### Finding Description

`recv_from_others` in `src/protocol/helpers.rs` implements an unbounded collection loop:

```rust
while !seen.full() {
    let (from, msg) = chan.recv(waitpoint).await?;   // blocks forever if any peer is silent
    if seen.put(from) {
        messages.push((from, msg));
    }
}
```

`seen.full()` returns `true` only when **all** N participants (minus self) have been recorded. [1](#0-0) 

`chan.recv(waitpoint).await` is an unbounded async wait backed by `MessageBuffer::pop`, which itself calls `receiver_lock.next().await` — a future that never resolves if no message arrives for that header. [2](#0-1) 

This function is called at three critical points:

**1. DKG / Reshare / Refresh — Round 1 (commitment-hash collection):**
```rust
for (from, their_commitment_hash) in
    recv_from_others(&chan, wait_round_1, &participants, me).await?
``` [3](#0-2) 

**2. DKG / Reshare / Refresh — Round 4 (secret-share collection):**
```rust
for (from, signing_share_from) in
    recv_from_others(&chan, wait_round_3, &participants, me).await?
``` [4](#0-3) 

**3. FROST Presign — Round 1 (nonce-commitment collection):**
```rust
for (from, commitment) in recv_from_others(&chan, commit_waitpoint, &participants, me).await? {
    commitments_map.insert(from.to_identifier()?, commitment);
}
``` [5](#0-4) 

**The inconsistency with echo broadcast:** The echo broadcast, which is used in the DKG broadcast rounds, explicitly handles missing or malformed messages by continuing the loop:

```rust
match chan.recv(wait).await {
    Ok(value) => (from, (sid, vote)) = value,
    _ => continue,   // graceful: skip bad messages, keep waiting for valid ones
};
``` [6](#0-5) 

In contrast, `recv_from_others` propagates any deserialization error immediately via `?`, and — more critically — simply never returns if a participant is silent. There is no equivalent of the echo broadcast's `> echo_t` threshold that allows progress with fewer than N responses. [7](#0-6) 

The echo broadcast documentation explicitly states it tolerates `3·MaxFaulty+1 ≤ N` Byzantine faults and is "used exclusively in the DKG protocol." Yet the DKG protocol also calls `recv_from_others` in rounds 1 and 4, which carry zero fault tolerance. [8](#0-7) 

**Secondary attack surface — deserialization abort:** A malicious participant can send a message with a syntactically valid `MessageHeader` (correct channel tag + waitpoint) but a malformed MessagePack payload. `Comms::recv` will deserialize and return `Err(...)`, which `recv_from_others` propagates via `?`, immediately aborting the protocol for the honest participant — even though the echo broadcast would have silently skipped the same message. [9](#0-8) 

---

### Impact Explanation

A single malicious participant — one who is legitimately enrolled in the participant list — can:

- **Stall DKG indefinitely**: by not sending their commitment hash in Round 1 or their secret share in Round 4. All honest participants block in `recv_from_others`. No new key can be generated.
- **Stall reshare / refresh indefinitely**: same mechanism, same rounds in `do_keyshare`. Existing key shares cannot be redistributed or refreshed.
- **Stall FROST presign indefinitely**: by not sending their nonce commitment. Signing cannot proceed for any message until the presign completes.

This maps directly to **High: Permanent denial of signing, key generation, reshare, or refresh for honest parties under valid protocol inputs and documented trust assumptions.** The library explicitly advertises Byzantine fault tolerance via echo broadcast, establishing that malicious participants are within the threat model; `recv_from_others` is the unprotected gap.

---

### Likelihood Explanation

The attack requires only that the adversary be a registered participant — no cryptographic break, no key leakage, no external dependency failure. The attacker simply stops sending at the targeted round. The attack is:

- **Trivially executable**: withhold one message.
- **Undetectable before the fact**: honest parties cannot distinguish a slow participant from a silent one until a timeout (which does not exist).
- **Repeatable**: if honest parties restart with a new participant set, the same participant (or a colluding one) can repeat the attack.

---

### Recommendation

1. **Add a timeout to `recv_from_others`**: return an error identifying the non-responsive participant(s) after a configurable deadline, allowing the orchestration layer to restart the protocol with a different participant set.
2. **Handle deserialization errors gracefully**: mirror the echo broadcast pattern — skip malformed messages rather than propagating the error, so a single bad message does not abort the entire protocol.
3. **Consider threshold-based collection for presign**: FROST signing only requires `t` participants; the presign commitment collection could proceed once `t` valid commitments are received, rather than waiting for all N signing participants.

---

### Proof of Concept

**Scenario: DKG stall via silent participant**

1. Initiate DKG with participants `[P1, P2, P3]`, threshold `t=2`.
2. All participants complete the echo-broadcast rounds (session-ID broadcast, commitment+PoK broadcast) successfully.
3. In Round 1, `P1` and `P2` call `chan.send_many(wait_round_1, &commitment_hash)` as expected.
4. `P3` (malicious) does **not** send its commitment hash.
5. `P1` and `P2` each enter `recv_from_others(&chan, wait_round_1, &participants, me)`.
6. `seen.full()` never becomes `true` for either honest participant because `P3`'s slot remains empty.
7. `chan.recv(wait_round_1).await` blocks indefinitely inside `MessageBuffer::pop` → `receiver_lock.next().await`.
8. DKG never completes. No key is generated. The protocol is permanently stalled until an external timeout kills the session.

The same attack applies to Round 4 (secret-share collection) and to FROST presign (nonce-commitment collection), with identical mechanics.

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

**File:** src/protocol/internal.rs (L330-341)
```rust
    async fn recv<T: DeserializeOwned>(
        &self,
        header: MessageHeader,
    ) -> Result<(Participant, T), ProtocolError> {
        let (from, data) = self.incoming.pop(header).await;
        let message_data = data.get(MessageHeader::LEN..).ok_or_else(|| {
            ProtocolError::DeserializationError("Failed to deserialize message data".to_string())
        })?;
        let decoded: Result<T, Box<dyn error::Error + Send + Sync>> =
            rmp_serde::decode::from_slice(message_data).map_err(std::convert::Into::into);
        Ok((from, decoded?))
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

**File:** src/dkg.rs (L514-516)
```rust
    for (from, signing_share_from) in
        recv_from_others(&chan, wait_round_3, &participants, me).await?
    {
```

**File:** src/frost/mod.rs (L109-111)
```rust
    for (from, commitment) in recv_from_others(&chan, commit_waitpoint, &participants, me).await? {
        commitments_map.insert(from.to_identifier()?, commitment);
    }
```

**File:** src/protocol/echo_broadcast.rs (L179-182)
```rust
            match chan.recv(wait).await {
                Ok(value) => (from, (sid, vote)) = value,
                _ => continue,
            };
```

**File:** src/protocol/README.md (L39-49)
```markdown
### Echo Broadcast (`echo_broadcast.rs`)

Implements Authenticated Double-Echo Broadcast (Byzantine Reliable Broadcast) following \[[CGR](https://link.springer.com/book/10.1007/978-3-642-15260-3)\]. See the [network layer documentation](../../docs/network-layer.md) for the full specification.

```
Phase 1: SEND   -- sender sends initial value to all parties
Phase 2: ECHO   -- all parties echo what they received
Phase 3: READY  -- parties signal readiness after sufficient echoes
```

This provides reliable delivery guarantees even with up to `floor((N-1)/3)` malicious parties. Used exclusively in the DKG protocol.
```
