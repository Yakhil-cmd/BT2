### Title
CKD Coordinator Is an Unverifiable Single Point of Failure — Malicious Coordinator Can Permanently Corrupt or Withhold the CKD Output - (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The Confidential Key Derivation (CKD) protocol designates a single coordinator as the only entity that aggregates participant shares and produces the final `CKDOutput`. No participant can verify the coordinator's aggregation, and no participant other than the coordinator ever holds the output. A malicious coordinator — who is simply a normal participant assigned the coordinator role — can corrupt or withhold the `CKDOutput`, permanently denying the TEE application its confidential key for that protocol run, with no in-protocol recovery path.

---

### Finding Description

In `do_ckd_participant`, every non-coordinator participant computes its Lagrange-weighted ElGamal share `(norm_big_y, norm_big_c)` and sends it **exclusively and privately** to the coordinator, then returns `None`:

```rust
// src/confidential_key_derivation/protocol.rs:27-32
let (norm_big_y, norm_big_c) =
    compute_signature_share(participants, me, key_pair, app_id, app_pk, rng)?;
let waitpoint = chan.next_waitpoint();
chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;
Ok(None)
```

In `do_ckd_coordinator`, the coordinator is the sole aggregator and the sole producer of `Some(CKDOutput)`:

```rust
// src/confidential_key_derivation/protocol.rs:44-57
let (mut norm_big_y, mut norm_big_c) =
    compute_signature_share(&participants, me, key_pair, app_id, app_pk, rng)?;
let waitpoint = chan.next_waitpoint();
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
Ok(Some(ckd_output))
```

There is no zero-knowledge proof, commitment, or any other mechanism that allows honest participants to verify that the coordinator correctly summed the received shares. The coordinator is the only entity that ever holds the aggregated `(Y, C)` pair. All other participants return `None` and have no way to reconstruct or audit the output.

The `ckd()` entry point enforces that the coordinator must be a member of the participant list, meaning the coordinator role is reachable by any ordinary participant — no special key or privilege is required beyond being named coordinator at call time:

```rust
// src/confidential_key_derivation/protocol.rs:95-101
if !participants.contains(coordinator) {
    return Err(InitializationError::MissingParticipant {
        role: "coordinator",
        participant: coordinator,
    });
}
```

---

### Impact Explanation

A malicious coordinator can take one of two actions:

1. **Withhold the output**: The coordinator simply does not publish `(Y, C)` on-chain. The TEE application never receives the encrypted secret and cannot derive its confidential key. No other participant can substitute for the coordinator because all other participants returned `None`.

2. **Publish a corrupted output**: The coordinator publishes a modified `(Y', C')` that does not satisfy `C' − a·Y' = msk·H(pk, app_id)`. The TEE application's verification step (`verify_signature`) fails, and the application is again denied its key. Because the coordinator is the only entity that aggregated the shares, no honest participant can provide the correct `(Y, C)` as a substitute.

In both cases the TEE application is permanently denied its confidential key for that protocol invocation. The protocol provides no in-band mechanism for honest participants to detect the coordinator's misbehavior, replace the coordinator mid-run, or reconstruct the correct output from the `None` values they hold.

This matches the allowed impact: **High — Permanent denial of CKD for honest parties under valid protocol inputs.**

---

### Likelihood Explanation

The coordinator is an ordinary participant. No leaked key, no privileged access, and no external assumption is required. Any participant designated as coordinator at call time can execute this attack. The CKD protocol is specifically designed for high-value TEE applications where key availability is critical, making the coordinator's unilateral power over the output a realistic and consequential threat.

---

### Recommendation

**Short term:**
- Require the coordinator to publish a zero-knowledge proof of correct aggregation alongside `(Y, C)`, so honest participants (and the on-chain verifier) can reject a corrupted output without trusting the coordinator.
- Alternatively, have every participant independently broadcast its `(norm_big_y, norm_big_c)` share to all other participants (not only to the coordinator), so any participant can reconstruct the correct aggregate and detect coordinator equivocation.

**Long term:**
- Redesign the CKD output phase to use a Byzantine-reliable broadcast (already available in the codebase as `do_broadcast`) so that the aggregated output is agreed upon by all honest participants before being published, eliminating the coordinator as a single point of failure.
- Document the coordinator's trust assumption explicitly in the `ckd()` API and enforce a rotation or multi-coordinator scheme at the application layer.

---

### Proof of Concept

**Setup:** Three participants `P1`, `P2`, `P3`; `P1` is designated coordinator.

1. `P2` and `P3` each compute their shares `(norm_big_y_i, norm_big_c_i)` and send them privately to `P1` via `chan.send_private`. Both return `Ok(None)`.
2. `P1` (malicious) receives the shares but either:
   - Does not call `CKDOutput::new` and instead returns an error, or
   - Calls `CKDOutput::new` with arbitrary garbage values `(Y', C')` and publishes them on-chain.
3. The TEE application receives `(Y', C')`, computes `sig' = C' − a·Y'`, and calls `verify_signature(&public_key, &app_id, &sig')`. Verification fails.
4. `P2` and `P3` hold `Ok(None)` — they have no shares, no aggregate, and no recourse. The TEE application cannot obtain its confidential key from any other source in this protocol run.

The root cause is entirely within `src/confidential_key_derivation/protocol.rs` lines 17–57: the asymmetric output design where only the coordinator produces `Some(CKDOutput)` with no verifiability guarantee. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L17-33)
```rust
fn do_ckd_participant(
    mut chan: SharedChannel,
    participants: &ParticipantList,
    coordinator: Participant,
    me: Participant,
    key_pair: &KeygenOutput,
    app_id: &AppId,
    app_pk: PublicKey,
    rng: &mut impl CryptoRngCore,
) -> Result<CKDOutputOption, ProtocolError> {
    let (norm_big_y, norm_big_c) =
        compute_signature_share(participants, me, key_pair, app_id, app_pk, rng)?;
    let waitpoint = chan.next_waitpoint();
    chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;

    Ok(None)
}
```

**File:** src/confidential_key_derivation/protocol.rs (L35-57)
```rust
async fn do_ckd_coordinator(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    key_pair: &KeygenOutput,
    app_id: &AppId,
    app_pk: PublicKey,
    rng: &mut impl CryptoRngCore,
) -> Result<CKDOutputOption, ProtocolError> {
    let (mut norm_big_y, mut norm_big_c) =
        compute_signature_share(&participants, me, key_pair, app_id, app_pk, rng)?;

    // Receive everyone's inputs and add them together
    let waitpoint = chan.next_waitpoint();

    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
    Ok(Some(ckd_output))
```

**File:** src/confidential_key_derivation/protocol.rs (L66-101)
```rust
pub fn ckd(
    participants: &[Participant],
    coordinator: Participant,
    me: Participant,
    key_pair: KeygenOutput,
    app_id: impl Into<AppId>,
    app_pk: PublicKey,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = CKDOutputOption>, InitializationError> {
    // not enough participants
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }

    // kick out duplicates
    let Some(participants) = ParticipantList::new(participants) else {
        return Err(InitializationError::DuplicateParticipants);
    };

    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }

    // ensure the coordinator is a participant
    if !participants.contains(coordinator) {
        return Err(InitializationError::MissingParticipant {
            role: "coordinator",
            participant: coordinator,
        });
    }
```
