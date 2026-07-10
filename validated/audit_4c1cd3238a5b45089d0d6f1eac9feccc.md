### Title
Single Unresponsive Participant Permanently Blocks DKG, Reshare, and Refresh for All Honest Parties - (File: `src/protocol/helpers.rs`)

---

### Summary

The `recv_from_others` helper function waits indefinitely for **all N participants** to send point-to-point messages, with no timeout or exclusion mechanism. A single unresponsive participant permanently blocks DKG, reshare, and refresh. Because reshare is the only mechanism to remove a participant from the set, and reshare itself calls `recv_from_others`, there is no recovery path once a participant goes permanently silent.

---

### Finding Description

`recv_from_others` in `src/protocol/helpers.rs` spins on `seen.full()`, which only becomes true when every participant in the `ParticipantList` has contributed: [1](#0-0) 

```rust
let mut seen = ParticipantCounter::new(participants);
seen.put(me);
// ...
while !seen.full() {          // ← loops until ALL N participants have sent
    let (from, msg) = chan.recv(waitpoint).await?;
    if seen.put(from) {
        messages.push((from, msg));
    }
}
```

This function is called at two critical points inside `do_keyshare` (the shared core of keygen, reshare, and refresh):

**Round 3.1 — commitment-hash collection:** [2](#0-1) 

**Round 5.1 — signing-share collection:** [3](#0-2) 

It is also called in the FROST presign protocol: [4](#0-3) 

If any single participant stops sending messages at any of these points, the `while !seen.full()` loop never exits. The protocol hangs indefinitely with no error, no timeout, and no way to proceed.

The only mechanism to remove an unresponsive participant is `do_reshare`, which itself calls `do_keyshare`, which calls `recv_from_others`. Therefore:

- An unresponsive participant blocks reshare.
- Reshare is the only way to remove the unresponsive participant.
- The participant set is permanently frozen.

This is structurally identical to the MultiStrategyVault bug: just as `_deallocateAssets` iterates over all strategies and calls `undeploy` on each with no skip mechanism, `recv_from_others` iterates over all participants and requires each to respond with no skip mechanism. [5](#0-4) 

---

### Impact Explanation

**High — Permanent denial of key generation, reshare, and refresh for honest parties.**

Once a participant becomes permanently unresponsive:

1. `do_keyshare` (keygen / reshare / refresh) hangs at `recv_from_others` and never returns.
2. Honest parties cannot rotate keys, change the threshold, or evict the bad participant.
3. If the silent participant's share is later compromised, honest parties cannot perform a refresh to invalidate it.

Signing itself (FROST sign, ECDSA sign) only requires a threshold subset, so it is unaffected. But all key-management operations are permanently blocked.

---

### Likelihood Explanation

Any participant can become unresponsive due to hardware failure, network partition, or deliberate refusal to send messages. A malicious participant who wants to permanently freeze the key-management lifecycle need only participate honestly through keygen (to obtain a valid share) and then go silent the next time reshare or refresh is initiated. No cryptographic capability is required — simply not sending a message is sufficient.

---

### Recommendation

1. **Add a timeout to `recv_from_others`**: after a configurable deadline, return an error identifying which participants did not respond, allowing the caller to abort cleanly rather than hang.
2. **Allow partial completion in point-to-point rounds**: for rounds where the protocol can tolerate up to `MaxFaulty = ⌊(N−1)/3⌋` silent parties (consistent with the documented BFT threshold), collect messages from `N − MaxFaulty` participants instead of requiring all N.
3. **Expose a participant-exclusion API**: provide a way for the coordinator to restart reshare/refresh with a reduced participant list that excludes the unresponsive party, without requiring the unresponsive party's cooperation.

---

### Proof of Concept

1. Run DKG with N = 4 participants (threshold = 3, MaxFaulty = 1).
2. All participants complete Round 1 (broadcast session IDs) and Round 2 (send commitment hashes).
3. Participant P₁ goes silent — it never sends its commitment hash in Round 3.1.
4. Participants P₂, P₃, P₄ each call `recv_from_others` at `wait_round_1`.
5. `seen.full()` never becomes true because P₁ never contributes; the loop spins forever.
6. DKG never completes for any honest party.
7. Honest parties attempt `do_reshare` to remove P₁ — same `recv_from_others` call, same infinite loop.
8. Key management is permanently blocked with no recovery path. [6](#0-5) [2](#0-1) [7](#0-6)

### Citations

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

**File:** src/frost/mod.rs (L109-111)
```rust
    for (from, commitment) in recv_from_others(&chan, commit_waitpoint, &participants, me).await? {
        commitments_map.insert(from.to_identifier()?, commitment);
    }
```
