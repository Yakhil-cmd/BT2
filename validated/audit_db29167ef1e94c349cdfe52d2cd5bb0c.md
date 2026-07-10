### Title
Malicious Participant Can Permanently Abort DKG by Broadcasting `false` in `broadcast_success` — (File: src/dkg.rs)

### Summary

The `broadcast_success` function in `src/dkg.rs` is called at the final step of DKG (Step 5.4/5.5) and aborts the entire protocol if **any** participant broadcasts `false` or a mismatched `session_id`. Because the function always broadcasts `(true, session_id)` for honest participants, the only source of a `false` vote is a malicious participant. A single malicious participant within the documented n/3 fault tolerance can exploit this to permanently deny DKG completion for all honest parties, violating the protocol's liveness guarantee.

### Finding Description

**Root cause — `broadcast_success` in `src/dkg.rs`:**

```rust
async fn broadcast_success(
    chan: &mut SharedChannel,
    participants: &ParticipantList,
    me: Participant,
    session_id: HashOutput,
) -> Result<(), ProtocolError> {
    let vote_list = do_broadcast(chan, participants, me, (true, session_id)).await?;
    let vote_list = vote_list
        .into_vec_or_none()
        .ok_or_else(|| ProtocolError::AssertionFailed("vote_list is empty".to_string()))?;

    if !vote_list.iter().all(|(_, ref sid)| sid == &session_id) {
        return Err(ProtocolError::AssertionFailed(
            "A participant broadcast the wrong session id. Aborting Protocol!"
        ));
    }

    if !vote_list.iter().all(|&(boolean, _)| boolean) {
        return Err(ProtocolError::AssertionFailed(
            "A participant seems to have failed its checks. Aborting Protocol!"
        ));
    }
    Ok(())
}
``` [1](#0-0) 

This function is invoked unconditionally at the end of `do_keyshare` after all cryptographic checks (proof-of-knowledge, commitment hash, share verification) have already passed: [2](#0-1) 

**Attack path:**

1. A malicious participant P_m participates honestly through all DKG rounds (Rounds 1–5), passing every cryptographic check.
2. At Step 5.4, instead of broadcasting `(true, session_id)`, P_m broadcasts `(false, session_id)` (or `(true, wrong_session_id)`).
3. The reliable echo-broadcast (`do_broadcast`) guarantees delivery of P_m's value to all honest parties — this is the protocol's own consistency guarantee working against it.
4. Every honest participant's `broadcast_success` call receives P_m's `false` in `vote_list` and hits the hard abort: `return Err(ProtocolError::AssertionFailed("A participant seems to have failed its checks. Aborting Protocol!"))`.
5. All honest participants discard their freshly computed key shares and return an error. DKG fails entirely.
6. P_m can repeat this on every DKG attempt indefinitely.

The analog to M-5 is exact: in M-5, `require(isAlive[_gauge])` reverts unconditionally when a gauge is dead, making poke permanently fail. Here, `!vote_list.iter().all(|&(boolean, _)| boolean)` aborts unconditionally when any participant broadcasts `false`, making DKG permanently fail under a malicious-but-tolerated participant. [3](#0-2) 

### Impact Explanation

**High — Permanent denial of key generation for honest parties under documented trust assumptions.**

The README explicitly documents that DKG tolerates up to n/3 malicious parties:

> "our DKG/Resharing protocol can only tolerate n/3 malicious parties" [4](#0-3) 

A single malicious participant within this tolerance can cause every DKG, reshare, and refresh attempt to fail at the final step. All prior computation (5 rounds of expensive cryptographic work including reliable broadcasts) is wasted. Honest parties never obtain key shares. The same attack applies to `do_reshare` and `do_refresh` since they all call `do_keyshare` → `broadcast_success`. [5](#0-4) 

### Likelihood Explanation

**High.** Any participant who is included in the DKG participant set and deviates from the protocol at Step 5.4 triggers this. No special privilege is required beyond being a listed participant. The deviation is trivial: send `(false, session_id)` instead of `(true, session_id)` during the `broadcast_success` round. The reliable echo-broadcast guarantees the malicious value is consistently delivered to all honest parties, so the abort is deterministic and repeatable.

### Recommendation

The `broadcast_success` check must not abort when a minority of participants (≤ n/3) broadcast `false`. Two options:

1. **Threshold-based acceptance**: Count `false` votes; abort only if strictly more than n/3 participants broadcast `false` or a mismatched session_id. This preserves the liveness guarantee.

2. **Remove the check entirely**: All cryptographic invariants (proof-of-knowledge, commitment hash, share validity) are already verified in Rounds 4–5. The `broadcast_success` round adds no cryptographic security — it only provides a non-binding "I succeeded" signal that a malicious party can trivially falsify. Removing it eliminates the DoS surface without weakening security.

### Proof of Concept

Setup: n=4 participants (P0, P1, P2, P3), threshold=2. n/3 ≈ 1.33, so 1 malicious participant is within tolerance.

1. P3 is malicious. All four participants run `keygen` / `do_keyshare`.
2. Rounds 1–5 proceed honestly. All participants compute valid key shares and reach `broadcast_success`.
3. P3 deviates: instead of calling `do_broadcast(chan, participants, me, (true, session_id))`, P3 sends `(false, session_id)` to all peers via the broadcast channel.
4. The echo-broadcast protocol delivers P3's `(false, session_id)` consistently to P0, P1, P2.
5. Each of P0, P1, P2 executes:
   ```rust
   if !vote_list.iter().all(|&(boolean, _)| boolean) {
       return Err(ProtocolError::AssertionFailed(
           "A participant seems to have failed its checks. Aborting Protocol!"
       ));
   }
   ```
   and returns an error, discarding their valid key shares.
6. DKG fails. P3 repeats on every retry, permanently blocking key generation. [1](#0-0) [6](#0-5)

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

**File:** src/dkg.rs (L529-537)
```rust

    // Step 5.4 and Step 5.5
    broadcast_success(&mut chan, &participants, me, session_id).await?;

    // Return the key pair
    Ok(KeygenOutput {
        private_share: SigningShare::new(my_signing_share),
        public_key: verifying_key,
    })
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

**File:** README.md (L160-163)
```markdown
  asynchronous peer-to-peer communication. Due to a fundamental impossibility
  theorem for asynchronous broadcast channel, our DKG/Resharing protocol can
  only tolerate $\frac{n}{3}$ malicious parties where $n$ is the total number of
  parties.
```
