### Title
Missing Participant Contribution Verification in CKD Protocol Allows Malicious Participant to Corrupt Derived Keys — (`src/confidential_key_derivation/protocol.rs`)

---

### Summary

The DKG protocol rigorously verifies every participant's contribution (proof-of-knowledge, commitment hash, share validity). The CKD protocol, which also aggregates per-participant cryptographic material, implements **no analogous verification**. A single malicious participant can inject arbitrary `(big_y, big_c)` values; the coordinator blindly sums them, producing a corrupted `CKDOutput` that the client cannot unmask to the correct confidential key.

---

### Finding Description

**DKG — verification is present** (`src/dkg.rs`):

Every participant's broadcast is checked three ways before any share is accepted:

1. **Proof-of-knowledge** — `verify_proof_of_knowledge` confirms the sender knows the secret behind their polynomial commitment. [1](#0-0) 

2. **Commitment hash binding** — `verify_commitment_hash` confirms the commitment matches the hash broadcast in round 1, preventing equivocation. [2](#0-1) 

3. **Share validity** — `validate_received_share` checks the received scalar against the polynomial commitment. [3](#0-2) 

**CKD — verification is absent** (`src/confidential_key_derivation/protocol.rs`):

`do_ckd_coordinator` receives `CKDOutput` structs from every other participant and unconditionally accumulates them:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
``` [4](#0-3) 

There is no check that:
- `big_y` equals `y · G` for the `y` used in `big_c` (no DLOG-equality proof).
- `big_c` equals `x_i · H(pk ‖ app_id) + y · app_pk` (no BLS share verification).
- The participant used their actual registered private share `x_i`.

The honest computation each participant is supposed to perform is: [5](#0-4) 

None of these invariants are enforced on the coordinator side.

---

### Impact Explanation

The coordinator outputs `(Y, C)` where the client recovers the confidential key as `C − a·Y`. If any single participant substitutes arbitrary group elements for their `(norm_big_y, norm_big_c)`, the aggregate `(Y, C)` is wrong and `C − a·Y ≠ msk · H(pk ‖ app_id)`.

The client's `unmask` function performs no pairing-based verification: [6](#0-5) 

Consequently, honest parties either:
- Accept a silently wrong derived key (if they do not independently verify via a pairing check), or
- Detect the failure only after the fact, with no ability to identify the culprit.

This matches the allowed impact: **High — Corruption of CKD outputs so honest parties accept inconsistent or unusable cryptographic outputs**.

---

### Likelihood Explanation

Any single participant in the CKD session is an attacker-controlled entry point. The `ckd` public API accepts arbitrary `KeygenOutput` values; a participant with a legitimately obtained key share can still send malformed `(big_y, big_c)` over the channel. Because `recv_from_others` collects from **all** other participants (the protocol has no threshold tolerance for malicious contributors), one bad actor is sufficient to corrupt every CKD invocation they participate in. [7](#0-6) 

---

### Recommendation

Add a zero-knowledge proof that ties `big_y` and `big_c` together. Concretely, each participant should attach a DLOG-equality proof (the library already has `dlogeq` infrastructure in `src/crypto/proofs/dlogeq.rs`) demonstrating that the discrete log of `big_y` with respect to `G` equals the discrete log of `(big_c − big_s)` with respect to `app_pk`. The coordinator verifies this proof before accumulating each contribution, mirroring the `verify_proof_of_knowledge` pattern used in DKG.


---

### Proof of Concept

```
Setup: 3 participants (P1, P2, P3), P3 is malicious.

Honest P1, P2 compute:
  norm_big_y_i = λ_i · y_i · G
  norm_big_c_i = λ_i · (x_i · H(pk‖app_id) + y_i · app_pk)

Malicious P3 sends:
  norm_big_y_3 = identity (G1 zero)
  norm_big_c_3 = identity (G1 zero)

Coordinator accumulates:
  Y   = norm_big_y_1 + norm_big_y_2 + 0
  C   = norm_big_c_1 + norm_big_c_2 + 0

Expected result (all honest):
  C − a·Y = (λ_1·x_1 + λ_2·x_2 + λ_3·x_3) · H(pk‖app_id) = msk · H(pk‖app_id)

Actual result (P3 malicious):
  C − a·Y = (λ_1·x_1 + λ_2·x_2) · H(pk‖app_id) ≠ msk · H(pk‖app_id)

The client receives a wrong confidential key with no protocol-level error raised.
```

### Citations

**File:** src/dkg.rs (L452-460)
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
```

**File:** src/dkg.rs (L463-469)
```rust
        verify_commitment_hash(
            &session_id,
            p,
            &mut commit_domain_separator.clone(), // you want to have the same state
            commitment_i,
            &all_hash_commitments,
        )?;
```

**File:** src/dkg.rs (L519-522)
```rust
        // however it matches the FROST implementation of ZCash
        let full_commitment_from = all_full_commitments.index(from)?;
        // Step 5.2
        validate_received_share::<C>(me, from, &signing_share_from, full_commitment_from)?;
```

**File:** src/confidential_key_derivation/protocol.rs (L50-57)
```rust
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

**File:** src/confidential_key_derivation/protocol.rs (L159-181)
```rust
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
```

**File:** src/confidential_key_derivation/mod.rs (L54-56)
```rust
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```
