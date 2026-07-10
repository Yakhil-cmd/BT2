### Title
Malicious Coordinator Can Extract Confidential Derived Key for Arbitrary `app_id` via Unchecked `app_pk` — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The `ckd()` function accepts `app_id` and `app_pk` as unchecked caller-supplied parameters with no cross-participant agreement step inside the protocol. A malicious coordinator who controls what `app_pk` is presented to each participant can substitute their own ephemeral public key, collect all Lagrange-weighted shares, and unmask the result to recover `msk · H(msk_pk ‖ victim_app_id)` — the confidential derived secret — for any `app_id` of their choosing.

---

### Finding Description

`ckd()` in `src/confidential_key_derivation/protocol.rs` initialises the protocol with two fully unchecked parameters:

```rust
pub fn ckd(
    participants: &[Participant],
    coordinator: Participant,
    me: Participant,
    key_pair: KeygenOutput,
    app_id: impl Into<AppId>,   // ← no ownership check
    app_pk: PublicKey,           // ← no ownership check
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = CKDOutputOption>, InitializationError>
``` [1](#0-0) 

Inside `compute_signature_share`, every participant blindly uses the caller-supplied `app_pk` to encrypt their share of the confidential key:

```rust
let big_c = big_s + app_pk * y.0;   // app_pk is never verified
``` [2](#0-1) 

The coordinator then sums all Lagrange-weighted contributions:

```
Y = Σ λᵢ · yᵢ · G₁
C = Σ λᵢ · (xᵢ · H(msk_pk ‖ app_id) + yᵢ · app_pk)
  = msk · H(msk_pk ‖ app_id) + Y_scalar · app_pk
```

and the `unmask` function recovers the confidential key as `C − app_sk · Y`:

```rust
pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
    self.big_c - self.big_y * secret_scalar
}
``` [3](#0-2) 

There is **no protocol round** in which participants broadcast and mutually verify the `app_id` and `app_pk` they were given before computing their shares. The DKG protocol, by contrast, includes a full echo-broadcast of commitments and proofs of knowledge before any secret material is exchanged. CKD has no equivalent safeguard. [4](#0-3) 

---

### Impact Explanation

If a malicious coordinator can present `app_pk = attacker_pk` (a key for which they hold `attacker_sk`) to all participants — possible in any deployment where the coordinator is the entity that distributes the per-session request rather than each node reading it independently from an authenticated on-chain source — the coordinator obtains:

```
C − attacker_sk · Y = msk · H(msk_pk ‖ victim_app_id)
```

This is the raw confidential derived secret for `victim_app_id`. It matches the **Critical** allowed impact: *"Extraction, reconstruction, or disclosure of … confidential derived secrets."*

---

### Likelihood Explanation

The coordinator role is filled by one of the MPC participants. The documented deployment model assumes each node reads `app_id` and `app_pk` independently from the blockchain, which prevents the substitution externally. However, the library itself provides **zero enforcement** of this assumption: no cross-participant agreement round, no binding of `app_pk` to `app_id`, and no check that the coordinator's own `app_pk` matches what other participants received. Any deployment where the coordinator distributes the session parameters (a common MPC pattern) is directly exploitable. The attack requires only that the coordinator be malicious — no cryptographic break, no key leakage, and no external dependency failure

### Citations

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

**File:** src/dkg.rs (L435-477)
```rust
    let commitments_and_proofs_map = do_broadcast(
        &mut chan,
        &participants,
        me,
        (commitment, proof_of_knowledge),
    )
    .await?;

    // Start Round 4
    let wait_round_3 = chan.next_waitpoint();
    // Step 4.2 4.3 and 4.4
    for p in participants.others(me) {
        let (commitment_i, proof_i) = commitments_and_proofs_map.index(p)?;

        // verify the proof of knowledge
        // if proof is none then make sure the participant is new
        // and performing a resharing not a DKG
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

        // in case the participant was new and it sent a polynomial of length
        // threshold -1 (because the zero term is not serializable)
        let full_commitment_i = insert_identity_if_missing(threshold, commitment_i);

        // add received full commitment
        all_full_commitments.put(p, full_commitment_i);
    }
```
