### Title
Malicious CKD Coordinator Can Produce Arbitrary Incorrect Confidential Derived Key Without Participant Detection — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The CKD protocol grants the coordinator unrestricted, unverifiable power to produce the final `CKDOutput`. Each participant sends their cryptographic share **privately** to the coordinator and then terminates with `None`, with no subsequent broadcast, commitment check, or output verification. A malicious coordinator can silently substitute, drop, or fabricate share contributions and return any `CKDOutput` it chooses. No honest participant can detect this.

---

### Finding Description

In `do_ckd_participant` (lines 17–33 of `src/confidential_key_derivation/protocol.rs`), each non-coordinator participant:

1. Computes `(norm_big_y, norm_big_c)` — their Lagrange-weighted ElGamal share.
2. Sends it **privately** to the coordinator via `chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))`.
3. Immediately returns `Ok(None)` — the protocol is over for them. [1](#0-0) 

In `do_ckd_coordinator` (lines 35–57), the coordinator:

1. Computes its own share.
2. Receives every participant's private share.
3. Sums them into a single `CKDOutput { big_y, big_c }`.
4. Returns it as the sole output of the entire protocol. [2](#0-1) 

There is **no broadcast of the aggregated result back to participants**, no commitment scheme binding the coordinator to a specific aggregation, and no mechanism for any participant to verify that their contribution `(norm_big_y_i, norm_big_c_i)` was faithfully included. The coordinator can:

- Drop one or more participants' shares entirely (reducing the effective secret to fewer than threshold shares).
- Replace a participant's share with an arbitrary group element.
- Return a completely fabricated `(big_y, big_c)` pair unrelated to any honest input.

The `unmask` function in `src/confidential_key_derivation/mod.rs` (lines 54–56) then computes `big_c − app_sk · big_y`. If `big_y` and `big_c` are attacker-chosen, the output is an attacker-chosen group element, not `msk · H(pk ∥ app_id)`. [3](#0-2) 

The `ckd` entry-point in `protocol.rs` (lines 66–117) performs no trust-level enforcement on the coordinator beyond confirming it is a member of the participant list. [4](#0-3) 

---

### Impact Explanation

**High — Corruption of CKD outputs so honest parties accept unusable or attacker-controlled cryptographic outputs.**

The confidential derived key `msk · H(pk ∥ app_id)` is the security-critical output of the CKD protocol. If the coordinator fabricates `CKDOutput`, the caller's `unmask(app_sk)` returns an arbitrary element. Any downstream use of this key (e.g., encrypting data, deriving sub-keys, authenticating to a service) silently operates on a wrong key. Because participants receive `None` and the coordinator is the only party that sees the aggregated result, the corruption is undetectable by any honest participant.

---

### Likelihood Explanation

**Medium.** The coordinator is a named, explicit protocol role chosen at call time via the `coordinator: Participant` parameter. In a real deployment the coordinator is a specific node (e.g., a TEE or a designated aggregator). A compromised or malicious coordinator — whether through key compromise, software bug, or insider threat — has a trivially exploitable, single-step path to corrupt every CKD invocation it handles. No cryptographic capability beyond normal protocol participation is required.

---

### Recommendation

Add a **broadcast-and-verify** round after aggregation:

1. The coordinator broadcasts the final `(big_y, big_c)` to all participants.
2. Each participant verifies that `big_y` and `big_c` are consistent with their own contribution: specifically, that `big_y − norm_big_y_i` and `big_c − norm_big_c_i` lie in the span of the remaining participants' public commitments (or use a simpler hash-commitment scheme where each participant commits to their share before sending it, and the coordinator opens all commitments publicly).

Alternatively, document explicitly that the coordinator is a **fully trusted** role (e.g., a TEE), and enforce this at the API level so callers cannot accidentally use an untrusted coordinator.

---

### Proof of Concept

```
Setup: participants = {A, B, C}, coordinator = C, threshold = 2

1. A computes (norm_big_y_A, norm_big_c_A) and sends privately to C.
2. B computes (norm_big_y_B, norm_big_c_B) and sends privately to C.
3. C (malicious) ignores B's share entirely.
   C computes its own (norm_big_y_C, norm_big_c_C).
   C returns CKDOutput {
       big_y: norm_big_y_A + norm_big_y_C,   // B's λ_B·y_B·G omitted
       big_c: norm_big_c_A + norm_big_c_C,   // B's λ_B·(x_B·H + y_B·app_pk) omitted
   }

4. Caller invokes ckd_output.unmask(app_sk):
   result = big_c - app_sk * big_y
          = λ_A·x_A·H + λ_C·x_C·H   ≠   msk·H(pk ∥ app_id)

5. A and B both returned Ok(None) and have no output to compare against.
   Neither can detect the omission of B's share.
```

The root cause is in `do_ckd_participant` returning immediately after `chan.send_private` with no subsequent verification waitpoint, and `do_ckd_coordinator` performing unchecked summation with no commitment opening broadcast. [5](#0-4) [6](#0-5)

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

**File:** src/confidential_key_derivation/mod.rs (L54-56)
```rust
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```
