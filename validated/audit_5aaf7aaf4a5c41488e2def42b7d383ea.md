### Title
Single Malicious Participant Permanently Blocks DKG, Presign, and Signing via Message Withholding — (`src/protocol/helpers.rs`)

---

### Summary

`recv_from_others` in `src/protocol/helpers.rs` unconditionally waits for **all N** participants to deliver a message before the calling protocol round can advance. A single malicious participant who is legitimately included in the participant list can permanently stall every honest party in DKG, reshare, refresh, robust-ECDSA presign, OT-based ECDSA presign, FROST EdDSA signing, and CKD by simply withholding their message in any round that calls this helper. No threshold tolerance is applied; the loop never exits until every participant has been heard from.

---

### Finding Description

**Root cause — `src/protocol/helpers.rs` lines 19–24:**

```rust
while !seen.full() {
    let (from, msg) = chan.recv(waitpoint).await?;
    if seen.put(from) {
        messages.push((from, msg));
    }
}
```

`seen.full()` returns `true` only when every participant in the list has contributed exactly one message. There is no timeout, no threshold-based early exit, and no mechanism to proceed with a subset of responses. If any single participant never sends, the `await` on `chan.recv` suspends indefinitely.

**Affected call sites (non-exhaustive):**

| Protocol | File | Round |
|---|---|---|
| DKG / Reshare / Refresh | `src/dkg.rs:422–426` | Commitment-hash collection |
| DKG / Reshare / Refresh | `src/dkg.rs:514–528` | Secret-share collection |
| Robust ECDSA presign | `src/ecdsa/robust_ecdsa/presign.rs:135` | Polynomial-evaluation collection |
| OT-based ECDSA presign | `src/ecdsa/ot_based_ecdsa/presign.rs:114` | `e_j` share collection |
| FROST EdDSA sign (v1) | `src/frost/eddsa/sign.rs:126,150` | Commitment + signature-share collection |
| CKD coordinator | `src/confidential_key_derivation/protocol.rs:51` | BLS-share collection |
| Triple generation | `src/ecdsa/ot_based_ecdsa/triples/generation.rs:309,400,464` | Multiple rounds |

The echo-broadcast primitive (`do_broadcast` / `reliable_broadcast_receive_all`) does implement Byzantine-fault-tolerant thresholds (`echo_t`, `ready_t`) derived from `n ≥ 3f+1`. However, `recv_from_others` — used in every non-broadcast round — applies **no such tolerance**. The two primitives are used side-by-side in the same protocol (e.g., `do_keyshare` calls `do_broadcast` for commitment broadcast and `recv_from_others` for secret-share distribution), creating an inconsistency: the broadcast rounds tolerate up to `f = (n−1)/3` silent faults, but every other round tolerates zero.

**Exploit path:**

1. Attacker is legitimately included as participant `P_m` in a DKG, reshare, presign, or signing session (no privileged access required — any participant slot suffices).
2. `P_m` participates honestly through all broadcast rounds (so echo-broadcast completes and does not flag `P_m` as malicious).
3. In the first non-broadcast round (e.g., the commitment-hash round in DKG at `src/dkg.rs:422`, or the polynomial-evaluation round in robust presign at `src/ecdsa/robust_ecdsa/presign.rs:135`), `P_m` simply does not send its message.
4. Every honest party blocks indefinitely inside `recv_from_others` at `chan.recv(waitpoint).await?`.
5. No error is returned; no timeout fires; the protocol never completes.

---

### Impact Explanation

**High — Permanent denial of signing, key generation, reshare, refresh, or CKD for honest parties under valid protocol inputs and documented trust assumptions.**

A single participant below the threshold can unilaterally prevent the entire group from ever producing a key, presignature, or signature. Because the block is indefinite (no timeout), the denial is permanent for that session. Repeated across sessions, a single malicious node can render the threshold system entirely inoperable for all honest parties.

---

### Likelihood Explanation

Any participant who is included in a session can trigger this with zero cryptographic capability — they simply do not transmit. The attacker needs no keys, no special role, and no knowledge of other parties' secrets. The attack is trivially repeatable across every new session.

---

### Recommendation

Replace the all-or-nothing `recv_from_others` with a threshold-aware variant that:
- Accepts responses from any `t`-of-`N` participants (where `t` is the reconstruction threshold), or
- Applies a configurable deadline after which the round proceeds with the messages received so far, excluding silent participants from the output set.

For rounds where all-N responses are cryptographically required (e.g., secret-share distribution where each party's share is unique), the protocol should be restructured to use a complaint/accusation round so that a silent participant can be identified and excluded, allowing the remaining honest parties to restart with a reduced participant set.

---

### Proof of Concept

```
Participants: P_0, P_1, P_2, P_3  (threshold t=2, max_malicious=1)
Attacker: P_3 (legitimate participant, no special privileges)

Round 1 (broadcast, echo-broadcast): P_3 participates honestly.
  -> do_broadcast completes for all parties.

Round 2 (recv_from_others, commitment-hash): P_3 sends nothing.
  -> P_0, P_1, P_2 each enter:
       while !seen.full() {
           let (from, msg) = chan.recv(waitpoint).await?;  // <-- blocks forever
       }
  -> DKG never completes. No key is generated.
  -> Identical attack applies to presign (robust: src/ecdsa/robust_ecdsa/presign.rs:135,
     OT-based: src/ecdsa/ot_based_ecdsa/presign.rs:114) and FROST signing
     (src/frost/eddsa/sign.rs:126).
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** src/ecdsa/robust_ecdsa/presign.rs (L135-139)
```rust
    for (_, package) in recv_from_others(&chan, wait_round_1, &participants, me).await? {
        // Step 2.2
        // calculate the respective sum of the different shares received from each participant
        shares.add_shares(&package);
    }
```

**File:** src/frost/eddsa/sign.rs (L126-128)
```rust
    for (from, commitment) in recv_from_others(&chan, commit_waitpoint, &participants, me).await? {
        commitments_map.insert(from.to_identifier()?, commitment);
    }
```

**File:** src/confidential_key_derivation/protocol.rs (L50-55)
```rust
    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
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
