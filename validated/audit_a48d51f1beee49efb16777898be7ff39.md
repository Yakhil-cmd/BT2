### Title
Missing Proof of Correct Computation in CKD Coordinator Allows Malicious Participant to Corrupt Confidential Key Derivation Output - (File: src/confidential_key_derivation/protocol.rs)

### Summary
The CKD coordinator in `do_ckd_coordinator` aggregates participant contributions `(norm_big_y, norm_big_c)` without any proof of correct computation. A malicious participant can send arbitrary group elements in place of their honest share, corrupting the final `CKDOutput` and causing all honest parties to derive an incorrect confidential key.

### Finding Description
The ERC-6492 vulnerability class is **unverified arbitrary input accepted during an aggregation/validation step, whose side-effects are not isolated or reverted**. The direct analog here is the CKD coordinator blindly accepting and summing participant-supplied elliptic-curve points with no proof that those points were derived from the participant's actual key share.

In `do_ckd_coordinator` (lines 35–58 of `src/confidential_key_derivation/protocol.rs`):

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
``` [1](#0-0) 

Each honest participant is supposed to send:
- `norm_big_y = λ_i · y_i · G`
- `norm_big_c = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)`

as computed in `compute_signature_share` (lines 148–182): [2](#0-1) 

No zero-knowledge proof, commitment, or consistency check is attached to the message sent by `do_ckd_participant`:

```rust
chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;
``` [3](#0-2) 

The coordinator has no way to distinguish a correctly-formed contribution from an arbitrary pair of group elements. Contrast this with the DKG protocol, which enforces a Schnorr proof-of-knowledge (`verify_proof_of_knowledge`) and a commitment hash check (`verify_commitment_hash`) before accepting any participant's polynomial commitment: [4](#0-3) 

No equivalent safeguard exists in the CKD aggregation step.

### Impact Explanation
A single malicious participant can replace their honest `(norm_big_y, norm_big_c)` with arbitrary group elements `(Y_evil, C_evil)`. The coordinator sums all contributions, so the final output becomes:

```
Y_final  = Y_honest_sum + Y_evil   (instead of correct Y)
C_final  = C_honest_sum + C_evil   (instead of correct C)
```

The confidential key the requester derives (`C_final − app_sk · Y_final`) will be an incorrect, attacker-influenced value rather than `msk · H(pk ‖ app_id)`. Every honest party that trusts the coordinator's output will silently accept a corrupted confidential derived key. This matches the allowed **High** impact: *Corruption of CKD outputs so honest parties accept unusable or inconsistent cryptographic outputs*.

### Likelihood Explanation
Any single participant in the CKD protocol can mount this attack. The participant role is unprivileged — it only requires holding a valid key share and being listed in the participant set. No collusion, no leaked secrets, and no external assumptions are needed. The attacker simply deviates from the protocol by sending arbitrary bytes for their `CKDOutput` message.

### Recommendation
Each participant should accompany their `(norm_big_y, norm_big_c)` with a non-interactive zero-knowledge proof of correct computation — specifically a proof that:
1. `norm_big_y = λ_i · y_i · G` for a known `y_i` (a discrete-log proof, as already implemented in `src/crypto/proofs/dlog.rs`).
2. `norm_big_c` is consistent with the participant's public key share and the same `y_i` (a discrete-log-equality proof, as already implemented in `src/crypto/proofs/dlogeq.rs`).

The coordinator must verify both proofs before adding any contribution to the running sum, mirroring the pattern used in `do_keyshare` for DKG. [5](#0-4) [6](#0-5) 

### Proof of Concept
A malicious participant deviates from `compute_signature_share` and instead sends:

```rust
// Malicious participant: send identity points or arbitrary points
let evil_y = ElementG1::identity();          // or any arbitrary point
let evil_c = ElementG1::generator() * evil_scalar; // arbitrary
chan.send_private(waitpoint, coordinator, &(evil_y, evil_c))?;
```

The coordinator at lines 50–55 adds these without any check:

```rust
norm_big_y += participant_output.big_y();  // adds evil_y
norm_big_c += participant_output.big_c();  // adds evil_c
```

The resulting `CKDOutput` is corrupted. When the requester calls `ckd_output.unmask(app_sk)` to recover the confidential key, they obtain a value that is not `msk · H(pk ‖ app_id)`, silently breaking the security guarantee of the CKD protocol for all honest parties. [7](#0-6)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L29-31)
```rust
    let waitpoint = chan.next_waitpoint();
    chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;

```

**File:** src/confidential_key_derivation/protocol.rs (L44-57)
```rust
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

**File:** src/crypto/proofs/dlog.rs (L83-101)
```rust
pub fn verify<C: Ciphersuite>(
    transcript: &mut Transcript,
    statement: Statement<'_, C>,
    proof: &Proof<C>,
) -> Result<bool, ProtocolError> {
    transcript.message(NEAR_DLOG_STATEMENT_LABEL, &statement.encode()?);

    let big_k = C::Group::generator() * proof.s.0 - *statement.public * proof.e.0;

    // Create a serialization of big_k
    // Raises error if the big_k turned out to be the identity element
    let ser = C::Group::serialize(&big_k).map_err(|_| ProtocolError::IdentityElement)?;

    transcript.message(NEAR_DLOG_COMMITMENT_LABEL, ser.as_ref());
    let mut rng = transcript.challenge_then_build_rng(NEAR_DLOG_CHALLENGE_LABEL);
    let e = frost_core::random_nonzero::<C, TranscriptRng>(&mut rng);

    Ok(e == proof.e.0)
}
```

**File:** src/crypto/proofs/dlogeq.rs (L139-164)
```rust
pub fn verify<C: Ciphersuite>(
    transcript: &mut Transcript,
    statement: Statement<'_, C>,
    proof: &Proof<C>,
) -> Result<bool, ProtocolError>
where
    Element<C>: ConstantTimeEq,
{
    if statement.generator1.ct_eq(&C::Group::identity()).into() {
        return Err(ProtocolError::IdentityElement);
    }

    transcript.message(NEAR_DLOGEQ_STATEMENT_LABEL, &statement.encode()?);

    let (phi0, phi1) = statement.phi(&proof.s.0);
    let big_k0 = phi0 - *statement.public0 * proof.e.0;
    let big_k1 = phi1 - *statement.public1 * proof.e.0;

    let enc = encode_two_points::<C>(&big_k0, &big_k1)?;

    transcript.message(NEAR_DLOGEQ_COMMITMENT_LABEL, &enc);
    let mut rng = transcript.challenge_then_build_rng(NEAR_DLOGEQ_CHALLENGE_LABEL);
    let e = frost_core::random_nonzero::<C, _>(&mut rng);

    Ok(e == proof.e.0)
}
```
