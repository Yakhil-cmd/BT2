Looking at the `echo_ready_thresholds` function in `src/protocol/echo_broadcast.rs` and how it feeds into the DKG protocol in `src/dkg.rs`, I found a genuine analog.

---

### Title
BRB Threshold Edge Case for n=3 Allows Malicious Participant to Equivocate, Corrupting DKG Public Key — (`src/protocol/echo_broadcast.rs`)

---

### Summary

The `echo_ready_thresholds` function returns `(0, 0)` for `n ≤ 3`, collapsing the echo-broadcast consistency guarantee. For a valid `(2,3)` DKG configuration, a single malicious participant can send different polynomial commitments to each honest party. Because BRB delivers on the very first self-echo with these thresholds, no cross-checking occurs, and the two honest parties finish DKG holding different public keys while both reporting success.

---

### Finding Description

**Root cause — `echo_ready_thresholds`:**

```rust
// src/protocol/echo_broadcast.rs, lines 67-78
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

For `n = 3`, the formula itself already yields `broadcast_threshold = (3-1)/3 = 0` and `echo_threshold = midpoint(3, 0) = 1`. The special-case branch overrides this with `(0, 0)`, which is strictly weaker.

**Why `(0, 0)` breaks consistency:**

With `echo_t = 0`, the check `count > echo_t` is satisfied by the *simulated self-echo* that is injected immediately after processing a `Send` message:

```rust
// src/protocol/echo_broadcast.rs, lines 223-235
if state_sid.data_echo.get(&data)...? > echo_t {   // 0 — true after 1 echo
    vote = MessageType::Ready(data);
    chan.send_many(wait, &(&sid, &vote))?;
    state_sid.finish_echo = true;
    is_simulated_vote = true;
    from = me;
}
``` [2](#0-1) 

Similarly, `ready_t = 0` means both amplification (`count > 0`) and delivery (`count > 2*0 = 0`) fire on the first self-simulated Ready. Each honest party therefore delivers whatever it received in the malicious `Send` message, with no cross-checking against the other honest party.

**How this corrupts DKG:**

`do_keyshare` uses `do_broadcast` (which calls `reliable_broadcast_receive_all`) for two critical steps:

1. Broadcasting polynomial commitments and proofs of knowledge (Round 3/4).
2. Broadcasting the final success vote (Round 5).

```rust
// src/dkg.rs, lines 435-441
let commitments_and_proofs_map = do_broadcast(
    &mut chan,
    &participants,
    me,
    (commitment, proof_of_knowledge),
).await?;
``` [3](#0-2) 

The commitment hash is sent via plain `send_many` (not BRB), so the malicious party can also send different hashes to each honest party:

```rust
// src/dkg.rs, lines 414-415
let wait_round_1 = chan.next_waitpoint();
chan.send_many(wait_round_1, &commitment_hash)?;
``` [4](#0-3) 

The `verify_commitment_hash` check then passes independently for each honest party against its own (different) hash:

```rust
// src/dkg.rs, lines 462-469
verify_commitment_hash(
    &session_id,
    p,
    &mut commit_domain_separator.clone(),
    commitment_i,
    &all_hash_commitments,
)?;
``` [5](#0-4) 

The final `broadcast_success` only checks that all parties broadcast `(true, session_id)`; it does not verify that all parties computed the same public key:

```rust
// src/dkg.rs, lines 321-335
if !vote_list.iter().all(|(_, ref sid)| sid == &session_id) { ... }
if !vote_list.iter().all(|&(boolean, _)| boolean) { ... }
``` [6](#0-5) 

**The library's own invariant check permits `n = 3`:**

```rust
// src/dkg.rs, lines 565-582
if participants.len() < 2 { ... }
if threshold > participants.len() { ... }
if threshold < 2 { ... }
``` [7](#0-6) 

No guard prevents `n = 3, threshold = 2`. Users calling `keygen` with three participants receive no warning that the BRB layer assumes zero malicious parties for this size.

---

### Impact Explanation

A malicious participant in a `(2, 3)` DKG (or reshare/refresh) can cause the two honest parties to finish the protocol holding **different public keys** while both reporting success. Any subsequent threshold signing round will produce signatures that are unverifiable by the other honest party, permanently breaking the signing capability. This matches:

> **High: Corruption of DKG outputs so honest parties accept inconsistent public keys.**

---

### Likelihood Explanation

- `n = 3` is the smallest valid participant count the library accepts.
- A `(2, 3)` setup is the most common minimal threshold configuration in practice.
- The attack requires only that the malicious party send two different `Send` messages at the BRB layer — a trivial network-level manipulation requiring no cryptographic capability.
- No existing invariant check or runtime detection prevents or surfaces the inconsistency.

---

### Recommendation

Remove the `n ≤ 3` special case and let the formula run for all `n`:

```rust
fn echo_ready_thresholds(n: usize) -> (usize, usize) {
    if n <= 1 {
        return (0, 0); // degenerate; handled elsewhere
    }
    let broadcast_threshold = (n - 1) / 3;
    let echo_threshold = usize::midpoint(n, broadcast_threshold);
    (echo_threshold, broadcast_threshold)
}
```

For `n = 3` this yields `(1, 0)`: the echo condition becomes `count > 1`, requiring two distinct echo votes before proceeding to Ready. A malicious equivocator cannot produce two honest echoes for two different values simultaneously, so the protocol stalls (liveness failure) rather than delivering inconsistent values (safety failure).

Alternatively, add a guard in `assert_key_invariants` rejecting `n < 4` with a clear error message documenting the BRB limitation.

---

### Proof of Concept

**Setup:** participants `[A, B, M]`, threshold `2`, `M` is malicious.

1. **Round 1 (session IDs):** All broadcast honestly; `session_id` is consistent.
2. **Round 2 (commitment hashes):** `M` calls `send_many` sending `hash_A` to `A` and `hash_B ≠ hash_A` to `B`. Both are accepted without cross-checking.
3. **Round 3 (commitments via BRB):** `M` sends `Send(commitment_A)` to `A` and `Send(commitment_B)` to `B`. With `echo_t = 0`, each honest party immediately self-echoes, self-readies, and delivers its own received value. `A` delivers `commitment_A`; `B` delivers `commitment_B`.
4. **Commitment hash verification:** `A` checks `H(commitment_A) == hash_A` ✓; `B` checks `H(commitment_B) == hash_B` ✓. Both pass.
5. **Public key computation:**
   - `A`: `public_key_A = commitment_A_A + commitment_B_A + commitment_M_A`

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

**File:** src/protocol/echo_broadcast.rs (L223-235)
```rust
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

**File:** src/dkg.rs (L321-335)
```rust
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
```

**File:** src/dkg.rs (L414-415)
```rust
    let wait_round_1 = chan.next_waitpoint();
    chan.send_many(wait_round_1, &commitment_hash)?;
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

**File:** src/dkg.rs (L565-582)
```rust
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }

    // Step 1.1
    // validate threshold
    if threshold > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold,
            max: participants.len(),
        });
    }
    // Step 1.1
    if threshold < 2 {
        return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
    }
```
