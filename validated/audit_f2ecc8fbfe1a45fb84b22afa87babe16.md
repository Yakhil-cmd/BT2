The code is fully visible. Let me confirm there is no commitment or ZK-proof step anywhere in the protocol.

### Title
Malicious Participant Can Corrupt CKDOutput by Sending Arbitrary G1 Points — (`src/confidential_key_derivation/protocol.rs`)

---

### Summary

The CKD coordinator aggregates participant contributions with no cryptographic binding. A legitimately-enrolled participant can substitute arbitrary G1 points for its honest `(λ_i·Y_i, λ_i·C_i)` contribution, causing the coordinator to produce a `CKDOutput` that fails `verify_signature` and is therefore unusable.

---

### Finding Description

`do_ckd_coordinator` collects one `CKDOutput` per participant via `recv_from_others` and unconditionally adds the received `big_y` / `big_c` fields to its running sum: [1](#0-0) 

`recv_from_others` enforces only that the sender is a known participant (deduplication via `ParticipantCounter`); it performs no validation of message content: [2](#0-1) 

`compute_signature_share` produces the honest values `(λ_i·Y_i, λ_i·C_i)` on the participant side, but nothing prevents a participant from sending different points over the channel: [3](#0-2) 

There is no commitment, DLEQ proof, or Schnorr proof-of-knowledge anywhere in the CKD module to bind a participant to its honest computation. A grep for `proof|commit|verify|zkp|dleq|schnorr` in `src/confidential_key_derivation/` returns only `ciphersuite.rs` (the final `verify_signature` helper) and `scalar_wrapper.rs` — neither is invoked during aggregation.

---

### Impact Explanation

The invariant that must hold for the output to be useful is:

```
C = msk · H(pk ∥ app_id) + a · Y
```

If participant `i` sends `(P, Q)` instead of `(λ_i·Y_i, λ_i·C_i)`, the coordinator computes:

```
Y_out = Σ_{j≠i} λ_j·Y_j  +  P
C_out = Σ_{j≠i} λ_j·C_j  +  Q
```

`unmask(app_sk)` then returns `C_out − app_sk·Y_out`, which is not `msk·H(pk ∥ app_id)` for any attacker-chosen `(P, Q)` unless the attacker knows `msk` and `app_sk`. The resulting `CKDOutput` fails `verify_signature`, making the derived key permanently unusable for that session.

Impact: **High — Corruption of CKD output so honest parties accept an unusable cryptographic output.** [4](#0-3) 

---

### Likelihood Explanation

The attacker only needs to be a legitimately enrolled participant (already in the `participants` list). No key material needs to be leaked. The attack is a single-message substitution in a single-round protocol, executable by any participant node that has been compromised or is malicious. The entry point is the public `ckd()` API. [5](#0-4) 

---

### Recommendation

Add a **DLEQ (Discrete Log Equality) proof** or **Schnorr proof-of-knowledge** to each participant's message, proving that the sent `(big_y, big_c)` was computed honestly from the participant's committed share. Concretely, each participant should prove:

- Knowledge of `y_i` such that `Y_i = y_i · G1` and `y_i · A` is the blinding term in `C_i`.
- Knowledge of `x_i` (or equivalently that `S_i = x_i · H(pk ∥ app_id)`) consistent with the public verification key.

The coordinator must verify these proofs before aggregating. This is the standard fix for additive-share aggregation protocols without a broadcast-and-commit phase.

---

### Proof of Concept

```rust
// Attacker is participant[1]; coordinator is participant[0].
// Attacker calls ckd() normally but intercepts the channel and
// replaces its outgoing message with (G1::identity(), G1::identity()).

// In do_ckd_participant (attacker-controlled node):
let forged_big_y = ElementG1::identity();
let forged_big_c = ElementG1::identity();
chan.send_private(waitpoint, coordinator, &(forged_big_y, forged_big_c))?;

// Coordinator aggregates without complaint.
// ckd_output.unmask(app_sk) != msk * H(pk || app_id)
// verify_signature(&public_key, &app_id, &confidential_key) => Err(...)
```

The existing test at `tests/ckd.rs:74` already calls `verify_signature` and would catch this failure — confirming the invariant breaks. [6](#0-5)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L27-31)
```rust
    let (norm_big_y, norm_big_c) =
        compute_signature_share(participants, me, key_pair, app_id, app_pk, rng)?;
    let waitpoint = chan.next_waitpoint();
    chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;

```

**File:** src/confidential_key_derivation/protocol.rs (L50-56)
```rust
    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
```

**File:** src/confidential_key_derivation/protocol.rs (L66-117)
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

    let comms = Comms::new();
    let chan = comms.shared_channel();

    let fut = run_ckd_protocol(
        chan,
        coordinator,
        me,
        participants,
        key_pair,
        app_id.into(),
        app_pk,
        rng,
    );
    Ok(make_protocol(comms, fut))
}
```

**File:** src/protocol/helpers.rs (L19-24)
```rust
    while !seen.full() {
        let (from, msg) = chan.recv(waitpoint).await?;
        if seen.put(from) {
            messages.push((from, msg));
        }
    }
```

**File:** src/confidential_key_derivation/mod.rs (L54-56)
```rust
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```

**File:** tests/ckd.rs (L72-74)
```rust
    // compute msk . H(app_id)
    let confidential_key = ckd.unmask(app_sk);
    assert!(verify_signature(&public_key, &app_id, &confidential_key).is_ok());
```
