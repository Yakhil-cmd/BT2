### Title
`MaxMalicious` BFT Invariant (`n ≥ 3f + 1`) Never Enforced in DKG, Reshare, and Refresh — (File: `src/dkg.rs`)

---

### Summary

The `MaxMalicious` type is defined and publicly exported from the library, representing the maximum number of Byzantine/malicious actors the protocol can tolerate. The DKG protocol uses Echo Broadcast (Byzantine Reliable Broadcast), which requires `n ≥ 3f + 1` for correctness. However, `assert_key_invariants` — the sole validation gate for all three DKG entry points (`keygen`, `reshare`, `refresh`) — never accepts a `MaxMalicious` parameter and never checks this invariant. Any caller can initiate a DKG session where the actual number of malicious participants exceeds what the echo broadcast can tolerate, with no error raised.

---

### Finding Description

`MaxMalicious` is defined in `src/thresholds.rs` and re-exported from `src/lib.rs`: [1](#0-0) [2](#0-1) 

The library's own documentation (wiki page 3.2) explicitly states:

> "For protocols requiring Byzantine fault tolerance (like DKG with Echo Broadcast), n ≥ 3f + 1."

Yet `assert_key_invariants`, which is the only validation function called before all three DKG entry points, has this signature: [3](#0-2) 

It accepts only `ReconstructionLowerBound` (the signing threshold `t`), not `MaxMalicious` (`f`). Its body checks only: [4](#0-3) 

- `n ≥ 2`
- `t ≤ n`
- `t ≥ 2`

The BFT invariant `n ≥ 3f + 1` is entirely absent. The same gap exists in `assert_reshare_keys_invariants`, which also takes no `MaxMalicious` parameter: [5](#0-4) 

All three public entry points (`keygen`, `reshare`, `refresh`) call through these validators and never touch `MaxMalicious`: [6](#0-5) [7](#0-6) [8](#0-7) 

By contrast, `MaxMalicious` **is** used in the Robust ECDSA path (`src/ecdsa/robust_ecdsa/`), confirming the type is intended for enforcement — it is simply missing from the DKG path.

---

### Impact Explanation

The DKG protocol uses Echo Broadcast (`do_broadcast`) in multiple rounds to ensure all honest participants agree on the same public commitments: [9](#0-8) [10](#0-9) 

Echo Broadcast (Byzantine Reliable Broadcast) only guarantees agreement when `n ≥ 3f + 1`. If this invariant is violated — which the library never prevents — malicious participants can equivocate: sending different commitment values to different honest participants during the broadcast rounds. Because the echo broadcast's consistency guarantee breaks down, honest parties can complete the DKG and each compute a **different** aggregate public key from the same session. This directly maps to:

**High: Corruption of DKG outputs so honest parties accept inconsistent public keys.**

---

### Likelihood Explanation

Any caller of `keygen`, `reshare`, or `refresh` can supply a participant list where `n < 3f + 1` for the actual number of colluding participants `f`. No error is raised. A malicious coordinator controlling `f` participants in a network of `n` nodes where `n < 3f + 1` can exploit this silently. This is a realistic scenario in permissioned MPC networks where the coordinator selects the participant set.

---

### Recommendation

Add `MaxMalicious` as a required parameter to `assert_key_invariants` and `assert_reshare_keys_invariants`, and enforce the BFT invariant before any DKG session begins:

```rust
pub fn assert_key_invariants(
    participants: &[Participant],
    me: Participant,
    threshold: impl Into<ReconstructionLowerBound>,
    max_malicious: impl Into<MaxMalicious>,  // add this
) -> Result<ParticipantList, InitializationError> {
    let f = max_malicious.into().value();
    let n = participants.len();
    // Enforce BFT invariant for Echo Broadcast
    if n < 3 * f + 1 {
        return Err(InitializationError::InsufficientParticipantsForBFT { n, f });
    }
    // ... existing checks ...
}
```

Propagate this parameter through `keygen`, `reshare`, and `refresh` in `src/lib.rs`.

---

### Proof of Concept

1. Call `keygen` with `n = 4` participants and `threshold = 2`, where `f = 2` participants are malicious (`n = 4 < 3*2+1 = 7`).
2. No error is returned from `assert_key_invariants` — the session proceeds.
3. The two malicious participants equivocate during `do_broadcast` rounds (sending different commitment hashes to different honest participants).
4. Because `n < 3f + 1`, the echo broadcast cannot guarantee all honest parties receive the same value.
5. Honest participants complete the protocol and each derive a different `verifying_key` from `public_key_from_commitments`, producing inconsistent DKG outputs. [11](#0-10)

### Citations

**File:** src/thresholds.rs (L4-7)
```rust
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, From, Into,
)]
pub struct MaxMalicious(usize);
```

**File:** src/lib.rs (L36-36)
```rust
pub use crate::thresholds::{MaxMalicious, ReconstructionLowerBound};
```

**File:** src/lib.rs (L88-101)
```rust
pub fn keygen<C: Ciphersuite>(
    participants: &[Participant],
    me: Participant,
    threshold: impl Into<ReconstructionLowerBound> + Send + Copy + 'static,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = KeygenOutput<C>>, InitializationError>
where
    Element<C>: Send,
    Scalar<C>: Send,
{
    let comms = Comms::new();
    let participants = assert_key_invariants(participants, me, threshold)?;
    let fut = do_keygen::<C>(comms.shared_channel(), participants, me, threshold, rng);
    Ok(make_protocol(comms, fut))
```

**File:** src/lib.rs (L106-141)
```rust
pub fn reshare<C: Ciphersuite>(
    old_participants: &[Participant],
    old_threshold: impl Into<ReconstructionLowerBound> + Send + 'static,
    old_signing_key: Option<SigningShare<C>>,
    old_public_key: VerifyingKey<C>,
    new_participants: &[Participant],
    new_threshold: impl Into<ReconstructionLowerBound> + Copy + Send + 'static,
    me: Participant,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = KeygenOutput<C>>, InitializationError>
where
    Element<C>: Send,
    Scalar<C>: Send,
{
    let comms = Comms::new();
    let threshold = new_threshold;
    let (participants, old_participants) = assert_reshare_keys_invariants::<C>(
        new_participants,
        me,
        threshold,
        old_signing_key,
        old_threshold,
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
}
```

**File:** src/lib.rs (L144-184)
```rust
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

**File:** src/dkg.rs (L481-485)
```rust
    let all_commitments_refs = all_full_commitments.to_refs_or_none().ok_or_else(|| {
        ProtocolError::AssertionFailed("all_full_commitments is empty".to_string())
    })?;
    // Step 4.5
    let verifying_key = public_key_from_commitments(all_commitments_refs)?;
```

**File:** src/dkg.rs (L558-562)
```rust
pub fn assert_key_invariants(
    participants: &[Participant],
    me: Participant,
    threshold: impl Into<ReconstructionLowerBound>,
) -> Result<ParticipantList, InitializationError> {
```

**File:** src/dkg.rs (L564-582)
```rust
    // need enough participants
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

**File:** src/dkg.rs (L638-645)
```rust
pub fn assert_reshare_keys_invariants<C: Ciphersuite>(
    participants: &[Participant],
    me: Participant,
    threshold: impl Into<ReconstructionLowerBound>,
    old_signing_key: Option<SigningShare<C>>,
    old_threshold: impl Into<ReconstructionLowerBound>,
    old_participants: &[Participant],
) -> Result<(ParticipantList, ParticipantList), InitializationError> {
```
