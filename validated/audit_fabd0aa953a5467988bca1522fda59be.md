### Title
Missing Cryptographic Validation of Participant Contributions in CKD Protocol Allows Output Corruption — (`src/confidential_key_derivation/protocol.rs`)

---

### Summary

The CKD coordinator blindly aggregates `(big_y, big_c)` shares received from participants with no proof of correctness, while the DKG protocol enforces proofs of knowledge and commitment verification for every participant contribution. A single malicious participant can send arbitrary group elements, permanently corrupting the derived confidential key output accepted by the coordinator.

---

### Finding Description

The vulnerability class from the external report is **asymmetric validation**: one phase of a two-phase operation enforces bounds/correctness checks while the related phase does not. The exact same pattern exists here between DKG and CKD.

**DKG (`src/dkg.rs`) — extensive per-participant validation:**

Every participant contribution is verified before being accepted:
- A commitment hash pre-image is checked against the hash broadcast in round 1 (`verify_commitment_hash`, lines 222–236).
- A Schnorr proof of knowledge of the secret coefficient is verified (`verify_proof_of_knowledge`, lines 172–218).
- Each secret share is verified against the public polynomial commitment (`validate_received_share`, lines 259–286). [1](#0-0) 

**CKD (`src/confidential_key_derivation/protocol.rs`) — zero validation:**

`do_ckd_coordinator` receives `(big_y, big_c)` from every participant and unconditionally adds them to the running sum:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [2](#0-1) 

There is no proof that `big_y = λ_i · y_i · G` for a known `y_i`, and no proof that `big_c = λ_i · (x_i · H(pk ‖ app_id) + y_i · A)` for the participant's actual signing share `x_i`. The `compute_signature_share` function that honest participants call is never cryptographically enforced on the receiver side. [3](#0-2) 

The `CKDOutput::unmask` function that the application calls to recover the derived key performs no integrity check either: [4](#0-3) 

---

### Impact Explanation

A malicious participant sends arbitrary `(big_y_M, big_c_M)` instead of their correctly computed share. The coordinator's final output becomes:

```
Y_final  = Σ_honest(λ_i · y_i · G)  +  big_y_M
C_final  = Σ_honest(λ_i · C_i)      +  big_c_M
```

When the application calls `unmask(app_sk)`:

```
C_final − app_sk · Y_final
  = msk · H(pk ‖ app_id)  +  (big_c_M − app_sk · big_y_M)
```

The result is the correct derived key **plus an attacker-controlled offset** (the offset depends on `app_sk`, which the attacker does not know, but the attacker can still make the output wrong by sending any non-zero `big_c_M` or `big_y_M`). The coordinator has no way to detect the corruption; it outputs a silently wrong `CKDOutput`. This matches the allowed impact: **Corruption of CKD outputs so honest parties accept unusable cryptographic outputs (High)**.

---

### Likelihood Explanation

Any participant in the CKD session is a reachable attacker-controlled entry point. The `ckd()` public API accepts an arbitrary `me` participant and routes to `do_ckd_participant`, which sends to the coordinator with no authentication of the payload content beyond transport-layer delivery. No special privilege, leaked key, or cryptographic break is required — only participation in the protocol. [5](#0-4) [6](#0-5) 

---

### Recommendation

Add a **Discrete Logarithm Equality (DLEQ) proof** to each participant's contribution, proving that the same secret scalar `y_i` was used to compute both `big_y = y_i · G` and the blinding term `y_i · A` inside `big_c`, and that `big_c` encodes the participant's actual signing share `x_i` (verifiable against the public key). This mirrors the proof-of-knowledge pattern already enforced in `do_keyshare` for DKG contributions. Alternatively, adopt a verifiable secret sharing approach where each participant's contribution can be checked against a public commitment to their share.

---

### Proof of Concept

1. Run a CKD session with `n` participants and one coordinator.
2. One participant (the attacker) replaces the call to `compute_signature_share` with a function that returns `(G1::generator(), G1::generator())` — two arbitrary non-zero points.
3. The attacker sends these values to the coordinator via `chan.send_private`.
4. The coordinator sums all contributions including the attacker's garbage values.
5. The coordinator outputs a `CKDOutput` whose `unmask(app_sk)` result differs from `msk · H(pk ‖ app_id)`.
6. The application receives a silently wrong derived key with no error or indication of failure, because neither `do_ckd_coordinator` nor `CKDOutput::unmask` performs any integrity check. [7](#0-6)

### Citations

**File:** src/dkg.rs (L452-469)
```rust
        verify_proof_of_knowledge(
            &session_id,
            &mut proof_domain_separator.clone(), // you want to have the same state
            threshold,
            p,
            old_participants.clone(),
            commitment_i,
            proof_i.as_ref(),
        )?;

        // verify that the commitment sent hashes to the received commitment_hash in round 1
        verify_commitment_hash(
            &session_id,
            p,
            &mut commit_domain_separator.clone(), // you want to have the same state
            commitment_i,
            &all_hash_commitments,
        )?;
```

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

**File:** src/confidential_key_derivation/protocol.rs (L148-182)
```rust
fn compute_signature_share(
    participants: &ParticipantList,
    me: Participant,
    key_pair: &KeygenOutput,
    app_id: &AppId,
    app_pk: PublicKey,
    rng: &mut impl CryptoRngCore,
) -> Result<(ElementG1, ElementG1), ProtocolError> {
    // Ensures the value is zeroized on drop
    let private_share = Zeroizing::new(key_pair.private_share);

    // y <- ZZq* , Y <- y * G
    let y = Scalar::random(rng);

    // Ensures the value is zeroized on drop
    let y = Zeroizing::new(super::scalar_wrapper::ScalarWrapper(y));

    let big_y = ElementG1::generator() * y.0;

    // H(pk || app_id) when H is a random oracle
    let hash_point = hash_app_id_with_pk(&key_pair.public_key, app_id);

    // S <- x . H(app_id)
    let big_s = hash_point * private_share.to_scalar();

    // C <- S + y . A
    let big_c = big_s + app_pk * y.0;

    // Compute  λi := λi(0)
    let lambda_i = participants.lagrange::<BLS12381SHA256>(me)?;
    // Normalize Y and C into  (λi . Y , λi . C)
    let norm_big_y = big_y * lambda_i;
    let norm_big_c = big_c * lambda_i;
    Ok((norm_big_y, norm_big_c))
}
```

**File:** src/confidential_key_derivation/mod.rs (L54-56)
```rust
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```
