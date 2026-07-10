### Title
Malicious DKG Participant Can Equivocate on Commitment Hash to Permanently Deny Key Generation — (File: `src/dkg.rs`)

---

### Summary

In `do_keyshare`, the per-participant commitment hash (Step 2.8–2.9) is disseminated via a plain `chan.send_many` call — a simple, non-authenticated broadcast — while the actual polynomial commitment (Step 3.2) is disseminated via `do_broadcast`, which is a full Byzantine Reliable Broadcast (BRB). A malicious participant can exploit this asymmetry by sending a different commitment hash to each honest participant. Because the actual commitment is then reliably broadcast (consistent across all honest parties), the `verify_commitment_hash` check will succeed for some honest participants and fail for others. The resulting split causes some honest participants to abort mid-protocol while others continue waiting for them, permanently hanging the DKG for all honest parties.

---

### Finding Description

In `do_keyshare` the commitment hash is sent and collected as follows:

```
// src/dkg.rs lines 408–426
let commit_domain_separator = domain_separator.clone();
let commitment_hash =
    domain_separate_hash(&mut domain_separator, &(&me, &commitment, &session_id))?;

// Step 2.9 — plain broadcast, NOT reliable broadcast
let wait_round_1 = chan.next_waitpoint();
chan.send_many(wait_round_1, &commitment_hash)?;

let mut all_hash_commitments = ParticipantMap::new(&participants);
all_hash_commitments.put(me, commitment_hash);

for (from, their_commitment_hash) in
    recv_from_others(&chan, wait_round_1, &participants, me).await?
{
    all_hash_commitments.put(from, their_commitment_hash);
}
``` [1](#0-0) 

The actual commitment is then sent via BRB:

```
// src/dkg.rs lines 435–441
let commitments_and_proofs_map = do_broadcast(
    &mut chan,
    &participants,
    me,
    (commitment, proof_of_knowledge),
)
.await?;
``` [2](#0-1) 

After BRB completes, every honest participant verifies the received commitment against the stored hash:

```
// src/dkg.rs lines 462–469
verify_commitment_hash(
    &session_id,
    p,
    &mut commit_domain_separator.clone(),
    commitment_i,
    &all_hash_commitments,
)?;
``` [3](#0-2) 

`verify_commitment_hash` recomputes `H(participant, commitment, session_id)` and compares it to the stored hash:

```
// src/dkg.rs lines 222–236
fn verify_commitment_hash<C: Ciphersuite>(
    session_id: &HashOutput,
    participant: Participant,
    domain_separator: &mut DomainSeparator,
    commitment: &VerifiableSecretSharingCommitment<C>,
    all_hash_commitments: &ParticipantMap<'_, HashOutput>,
) -> Result<(), ProtocolError> {
    let actual_commitment_hash = all_hash_commitments.index(participant)?;
    let commitment_hash =
        domain_separate_hash(domain_separator, &(&participant, &commitment, &session_id))?;
    if *actual_commitment_hash != commitment_hash {
        return Err(ProtocolError::InvalidCommitmentHash);
    }
    Ok(())
}
``` [4](#0-3) 

**Attack path:**

A malicious participant `P_m` bypasses `send_many` and instead uses `send_private` (available on `SharedChannel`) to send:
- `hash_A = H(C_m, P_m, sid)` to honest participant `P_1`
- `hash_B ≠ H(C_m, P_m, sid)` to honest participant `P_2`

`P_m` then reliably broadcasts commitment `C_m` (consistent across all honest parties, as guaranteed by BRB).

In Round 4:
- `P_1` checks `H(C_m) == hash_A` → passes, accepts `C_m`, continues.
- `P_2` checks `H(C_m) == hash_B` → fails, returns `ProtocolError::InvalidCommitmentHash`, **aborts**.

`P_2` never reaches Round 5 (share distribution) or the final `broadcast_success` round. `P_1` proceeds to Round 5 and then calls `broadcast_success`:

```
// src/dkg.rs lines 530–531
broadcast_success(&mut chan, &participants, me, session_id).await?;
``` [5](#0-4) 

`broadcast_success` calls `do_broadcast`, which internally calls `reliable_broadcast_receive_all`. That function loops until every participant's `finish_ready` flag is set:

```
// src/protocol/echo_broadcast.rs lines 322–325
if state.iter().all(|x| x.finish_ready) {
    return Ok(vote_output);
}
``` [6](#0-5) 

Because `P_2` aborted before this round, it never sends any `Send/Echo/Ready` messages. `P_1`'s loop never terminates. **`P_1` hangs indefinitely.**

`ParticipantMap::put` uses first-write-wins semantics, so `P_m` cannot overwrite a hash once stored, but it can deliver a different hash to each honest peer before any of them stores a value:

```
// src/participants.rs lines 237–246
pub fn put(&mut self, participant: Participant, data: T) {
    if let Some(&i) = self.participants.indices.get(&participant) {
        if let Some(data_i) = self.data.get_mut(i) {
            if data_i.is_none() {
                *data_i = Some(data);
                self.count += 1;
            }
        }
    }
}
``` [7](#0-6) 

---

### Impact Explanation

This is a **High: Permanent denial of key generation for honest parties**. A single malicious participant can prevent the DKG (and therefore reshare/refresh, since they share `do_keyshare`) from ever completing. Honest participants that pass the hash check hang indefinitely in `broadcast_success` waiting for peers that already aborted. No timeout or liveness mechanism exists in the loop. The attack applies equally to keygen, reshare, and refresh because all three call `do_keyshare`.

---

### Likelihood Explanation

Any participant who controls their own protocol implementation can substitute `send_private` calls for `send_many` in the commitment-hash round. No cryptographic capability is required — only the ability to send different byte strings to different peers, which is trivially achievable by any participant running a modified client. The attack is deterministic and requires no brute force.

---

### Recommendation

Replace the plain `send_many` / `recv_from_others` exchange for commitment hashes with a call to `do_broadcast` (BRB). BRB guarantees that if any honest participant accepts a value for `P_m`, all honest participants accept the same value. This eliminates the equivocation window entirely. The additional round cost is acceptable given that the commitment-hash round already exists solely for binding purposes.

---

### Proof of Concept

1. `P_m` computes `C_m` and `hash_A = H(C_m, P_m, sid)`.
2. `P_m` calls `chan.send_private(wait_round_1, P_1, &hash_A)` and `chan.send_private(wait_round_1, P_2, &hash_B)` where `hash_B` is any value ≠ `hash_A`.
3. `P_m` participates honestly in the BRB round, broadcasting `C_m` to all.
4. `P_1` stores `hash_A`, receives `C_m` via BRB, verifies `H(C_m) == hash_A` → OK.
5. `P_2` stores `hash_B`, receives `C_m` via BRB, verifies `H(C_m) == hash_B` → `ProtocolError::InvalidCommitmentHash`, aborts.
6. `P_1` reaches `broadcast_success`, enters `reliable_broadcast_receive_all`, and waits forever for `P_2`'s `Ready` message that never arrives.
7. DKG never produces a `KeygenOutput` for any honest participant.

### Citations

**File:** src/dkg.rs (L222-236)
```rust
fn verify_commitment_hash<C: Ciphersuite>(
    session_id: &HashOutput,
    participant: Participant,
    domain_separator: &mut DomainSeparator,
    commitment: &VerifiableSecretSharingCommitment<C>,
    all_hash_commitments: &ParticipantMap<'_, HashOutput>,
) -> Result<(), ProtocolError> {
    let actual_commitment_hash = all_hash_commitments.index(participant)?;
    let commitment_hash =
        domain_separate_hash(domain_separator, &(&participant, &commitment, &session_id))?;
    if *actual_commitment_hash != commitment_hash {
        return Err(ProtocolError::InvalidCommitmentHash);
    }
    Ok(())
}
```

**File:** src/dkg.rs (L408-426)
```rust
    // Step 2.8
    let commit_domain_separator = domain_separator.clone();
    let commitment_hash =
        domain_separate_hash(&mut domain_separator, &(&me, &commitment, &session_id))?;

    // Step 2.9
    let wait_round_1 = chan.next_waitpoint();
    chan.send_many(wait_round_1, &commitment_hash)?;
    // receive commitment_hash

    let mut all_hash_commitments = ParticipantMap::new(&participants);
    all_hash_commitments.put(me, commitment_hash);

    // Step 3.1
    for (from, their_commitment_hash) in
        recv_from_others(&chan, wait_round_1, &participants, me).await?
    {
        all_hash_commitments.put(from, their_commitment_hash);
    }
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

**File:** src/dkg.rs (L462-469)
```rust
        // verify that the commitment sent hashes to the received commitment_hash in round 1
        verify_commitment_hash(
            &session_id,
            p,
            &mut commit_domain_separator.clone(), // you want to have the same state
            commitment_i,
            &all_hash_commitments,
        )?;
```

**File:** src/dkg.rs (L530-531)
```rust
    // Step 5.4 and Step 5.5
    broadcast_success(&mut chan, &participants, me, session_id).await?;
```

**File:** src/protocol/echo_broadcast.rs (L322-325)
```rust
                    // we can thus output that the n instances of the broadcast protocols have succeeded
                    if state.iter().all(|x| x.finish_ready) {
                        return Ok(vote_output);
                    }
```

**File:** src/participants.rs (L237-246)
```rust
    pub fn put(&mut self, participant: Participant, data: T) {
        if let Some(&i) = self.participants.indices.get(&participant) {
            if let Some(data_i) = self.data.get_mut(i) {
                if data_i.is_none() {
                    *data_i = Some(data);
                    self.count += 1;
                }
            }
        }
    }
```
