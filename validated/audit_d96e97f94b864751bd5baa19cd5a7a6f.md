### Title
Single Malicious Participant Can Permanently Abort DKG, Reshare, and Refresh for All Honest Parties via False Success Broadcast - (File: `src/dkg.rs`)

---

### Summary

The `broadcast_success` function in `src/dkg.rs` is called at the end of every DKG, reshare, and refresh protocol run. It unconditionally broadcasts `(true, session_id)` for the calling honest party, then asserts that **every** participant's received vote is also `true`. A single malicious participant can broadcast `(false, session_id)` through the echo broadcast protocol, causing all honest parties to abort with `ProtocolError::AssertionFailed` — permanently denying key generation, resharing, and refresh to the entire honest set.

---

### Finding Description

`broadcast_success` is the final step of `do_keyshare`, which backs all three public DKG operations: `keygen`, `reshare`, and `refresh`. [1](#0-0) 

The function always broadcasts `(true, session_id)` for the honest caller: [2](#0-1) 

After collecting all votes via the echo broadcast, it performs a hard abort if any single vote is `false`: [3](#0-2) 

This check is applied to the output of `do_broadcast`, which is the echo broadcast protocol. The echo broadcast guarantees that all honest parties **agree** on the message a given sender broadcast — meaning if a malicious participant reliably broadcasts `(false, session_id)` in their own session, every honest party will receive and record that `false` vote. The `all(|&(boolean, _)| boolean)` predicate then fails for every honest party simultaneously, and the entire DKG aborts.

This call site is at the very end of `do_keyshare`, after all polynomial commitments, proofs of knowledge, and secret share evaluations have been exchanged: [4](#0-3) 

`do_keyshare` is the shared implementation for all three public DKG operations:

- `do_keygen` → public `keygen` [5](#0-4) 
- `do_reshare` → public `reshare` and `refresh` [6](#0-5) 
- `refresh` via `do_reshare` [7](#0-6) 

The analog to the external report is exact: just as `Disqualifier.processUser()` could revert the entire staking transaction for honest users, a malicious participant's `false` success vote reverts the entire DKG for all honest parties.

---

### Impact Explanation

**High — Permanent denial of key generation, reshare, and refresh for honest parties under valid protocol inputs and documented trust assumptions.**

A single malicious participant can abort every DKG attempt indefinitely. Since `keygen`, `reshare`, and `refresh` all route through `do_keyshare` → `broadcast_success`, none of these operations can ever complete while the malicious participant remains in the participant set. This permanently prevents the honest parties from establishing or rotating a shared key, which in turn blocks all downstream signing, presigning, and CKD operations that depend on a valid `KeygenOutput`.

---

### Likelihood Explanation

**High.** The attacker needs only to be a registered participant in the protocol — no special privilege, no leaked key material, no cryptographic break. The BFT threshold is `MaxFaulty = (N-1)/3`; for `N = 4`, a single malicious party is within tolerance for the echo broadcast layer, yet is sufficient to trigger the abort. The malicious party simply deviates from the honest behavior of broadcasting `true` and instead broadcasts `false` in their own echo broadcast session. The echo broadcast protocol then reliably delivers this `false` to all honest parties, guaranteeing the abort fires on every honest node.

---

### Recommendation

The `broadcast_success` check should not treat a `false` vote from any single participant as a fatal error for all honest parties. Instead:

1. **Identify and exclude the misbehaving participant** rather than aborting the entire protocol. The echo broadcast already attributes each vote to its sender, so the culprit is identifiable.
2. **Continue the protocol** if the remaining honest participants still meet the cryptographic threshold, analogous to the external report's recommendation to "claim a bounty for the ineligible user before completing the transaction" rather than reverting entirely.
3. At minimum, return a structured error that names the offending participant (similar to `ProtocolError::MaliciousParticipant`) so the caller can retry without that party, rather than silently aborting with a generic `AssertionFailed`.

---

### Proof of Concept

**Setup:** 4 participants `P1, P2, P3, P4` run `keygen`. `P4` is malicious. `MaxFaulty = 1`, so `P4` is within the BFT tolerance.

**Attack steps:**

1. `P4` participates honestly through Rounds 1–5 of `do_keyshare` (broadcasts valid session ID, commitment, proof of knowledge, and secret share evaluations).
2. In Round 5.4, instead of calling `broadcast_success` with `(true, session_id)`, `P4` broadcasts `(false, session_id)` through the echo broadcast.
3. The echo broadcast protocol reliably delivers `P4`'s `(false, session_id)` to `P1`, `P2`, and `P3`.
4. Each of `P1`, `P2`, `P3` reaches the check at `src/dkg.rs:329`:
   ```rust
   if !vote_list.iter().all(|&(boolean, _)| boolean) {
       return Err(ProtocolError::AssertionFailed(
           "A participant seems to have failed its checks. Aborting Protocol!"
       ));
   }
   ```
5. All three honest parties return `Err(ProtocolError::AssertionFailed(...))`. No `KeygenOutput` is produced. The attack can be repeated on every subsequent `keygen`, `reshare`, or `refresh` attempt as long as `P4` is in the participant list. [3](#0-2) [8](#0-7)

### Citations

**File:** src/dkg.rs (L302-338)
```rust
/// This function takes err as input.
/// If err is None then broadcast success
/// otherwise, broadcast failure
/// If during broadcast it receives an error then propagates it
/// This function is used in the final round of DKG
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

**File:** src/dkg.rs (L530-531)
```rust
    // Step 5.4 and Step 5.5
    broadcast_success(&mut chan, &participants, me, session_id).await?;
```

**File:** src/dkg.rs (L540-553)
```rust
pub async fn do_keygen<C: Ciphersuite>(
    chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    threshold: impl Into<ReconstructionLowerBound>,
    mut rng: impl CryptoRngCore,
) -> Result<KeygenOutput<C>, ProtocolError> {
    let threshold = threshold.into();
    // pick share at random
    let secret = SigningKey::<C>::new(&mut rng).to_scalar();
    // call keyshare
    let keygen_output =
        do_keyshare::<C>(chan, participants, me, threshold, secret, None, &mut rng).await?;
    Ok(keygen_output)
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

**File:** src/lib.rs (L143-183)
```rust
/// Performs the refresh protocol
pub fn refresh<C: Ciphersuite>(
    old_signing_key: Option<SigningShare<C>>,
    old_public_key: VerifyingKey<C>,
    old_participants: &[Participant],
    old_threshold: impl Into<ReconstructionLowerBound> + Copy + Send + 'static,
    me: Participant,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = KeygenOutput<C>>, InitializationError>
where
    Element<C>: Send,
    Scalar<C>: Send,
{
    if old_signing_key.is_none() {
        return Err(InitializationError::BadParameters(format!(
            "The participant {me:?} is running refresh without an old share",
        )));
    }
    let comms = Comms::new();
    // NOTE: this equality must be kept, as changing the threshold during `key refresh`
    // might lead to insecure scenarios. For more information see https://github.com/ZcashFoundation/frost/security/advisories/GHSA-wgq8-vr6r-mqxm
    let threshold = old_threshold;
    let (participants, old_participants) = assert_reshare_keys_invariants::<C>(
        old_participants,
        me,
        threshold,
        old_signing_key,
        threshold,
        old_participants,
    )?;
    let fut = do_reshare(
        comms.shared_channel(),
        participants,
        me,
        threshold,
        old_signing_key,
        old_public_key,
        old_participants,
        rng,
    );
    Ok(make_protocol(comms, fut))
```
