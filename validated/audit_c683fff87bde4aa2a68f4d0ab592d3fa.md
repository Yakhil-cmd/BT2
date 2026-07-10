### Title
Malicious Coordinator Can Extract Confidential Derived Secrets by Substituting Arbitrary `app_pk` in CKD Protocol - (File: src/confidential_key_derivation/protocol.rs)

---

### Summary

The CKD protocol never broadcasts or verifies the `app_pk` (the TEE application's ephemeral encryption key) among participants. A malicious coordinator can substitute their own controlled key for the legitimate `app_pk`, causing all participants to encrypt their secret shares towards the attacker's key. The coordinator then aggregates the output and unmasks it to extract the raw confidential derived secret `msk · H(mpc_pk ‖ app_id)` for any `app_id`.

---

### Finding Description

The CKD protocol is designed so that each participant computes an ElGamal-encrypted share of the BLS signature `msk · H(mpc_pk ‖ app_id)`, blinded towards the TEE application's ephemeral public key `app_pk`. The application then unmasks the aggregated output using its private key `app_sk`.

In `compute_signature_share`, the encryption is:

```
C = S + y · app_pk      (where S = x_i · H(mpc_pk ‖ app_id))
``` [1](#0-0) 

The `app_pk` is passed as a plain function argument to `ckd()` and flows directly into `do_ckd_participant` and `do_ckd_coordinator` without any inter-participant consistency check: [2](#0-1) [3](#0-2) 

There is **no broadcast round** where participants exchange and verify the `app_pk` they each received. Compare this to the DKG protocol, which uses `do_broadcast` to ensure all participants agree on commitments before proceeding: [4](#0-3) 

Because `app_pk` is never verified for consistency, a malicious coordinator can call `ckd()` with `app_pk = attacker_pk` while instructing all other participants to also use `attacker_pk`. Every participant's share is then encrypted towards `attacker_pk`. The coordinator aggregates the shares into a `CKDOutput` and calls `unmask(attacker_sk)` to recover `msk · H(mpc_pk ‖ app_id)` — the raw confidential derived secret. [5](#0-4) 

---

### Impact Explanation

The attacker recovers `msk · H(mpc_pk ‖ app_id)`, which is the exact BLS signature that constitutes the confidential derived secret for the targeted `app_id`. This is a **Critical** impact: **extraction and disclosure of a confidential derived secret**. The secret is deterministic and permanent — once extracted, it cannot be rotated without changing the MPC master key. The attacker can target any `app_id` of their choice by simply initiating a CKD session with that `app_id` and their own `app_pk`.

---

### Likelihood Explanation

The coordinator role is assigned per-session and rotates among MPC nodes. Any single compromised or malicious MPC node that acts as coordinator for a CKD session can execute this attack unilaterally, without requiring collusion. The attack requires no special cryptographic capability — only the ability to supply an `app_pk` of the attacker's choosing to the `ckd()` call, which is a normal protocol input.

---

### Recommendation

Add a broadcast round at the start of the CKD protocol where all participants exchange and verify the `app_pk` they received, aborting if any mismatch is detected. This mirrors the commitment-hash broadcast already used in DKG: [6](#0-5) 

Concretely, before `compute_signature_share` is called, each participant should broadcast `H(app_id ‖ app_pk)` and verify that all received hashes match their own. Only then should they proceed to compute and send their share to the coordinator.

---

### Proof of Concept

**Setup:** 3-of-3 CKD session. Participants: P1 (coordinator/attacker), P2, P3. Legitimate TEE application holds `(app_sk_legit, app_pk_legit)`. Attacker holds `(app_sk_attacker, app_pk_attacker)`.

**Attack steps:**

1. TEE application sends `(app_id, app_pk_legit)` to the MPC network.
2. Malicious coordinator P1 initiates the CKD protocol, passing `app_pk = app_pk_attacker` to P2, P3, and itself.
3. P2 calls `ckd(..., app_pk_attacker, ...)` → computes `(norm_big_y_2, norm_big_c_2)` with `C_2 = S_2 + y_2 · app_pk_attacker` and sends to P1.
4. P3 calls `ckd(..., app_pk_attacker, ...)` → computes `(norm_big_y_3, norm_big_c_3)` with `C_3 = S_3 + y_3 · app_pk_attacker` and sends to P1.
5. P1 computes its own share with `app_pk_attacker` and aggregates: `Y = Σ λ_i · y_i · G`, `C = Σ λ_i · (S_i + y_i · app_pk_attacker)`.
6. P1 calls `CKDOutput::unmask(app_sk_attacker)` → recovers `C - app_sk_attacker · Y = msk · H(mpc_pk ‖ app_id)`. [7](#0-6) 

The coordinator now holds the raw confidential derived secret for `app_id`, which the TEE application was supposed to be the sole recipient of. No honest participant detects the substitution because `app_pk` is never broadcast or verified within the protocol. [8](#0-7)

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

**File:** src/confidential_key_derivation/protocol.rs (L35-58)
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
}
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

**File:** src/confidential_key_derivation/protocol.rs (L170-174)
```rust
    // S <- x . H(app_id)
    let big_s = hash_point * private_share.to_scalar();

    // C <- S + y . A
    let big_c = big_s + app_pk * y.0;
```

**File:** src/dkg.rs (L413-426)
```rust
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

**File:** src/confidential_key_derivation/mod.rs (L52-56)
```rust
    /// Takes a secret scalar and returns
    /// s <- C − a ⋅ Y = msk ⋅ H ( `app_id` )
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```
