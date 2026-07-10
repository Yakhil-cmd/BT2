### Title
Malicious Participant Can Corrupt CKD Output Without Detection — (File: `src/confidential_key_derivation/protocol.rs`)

### Summary
The CKD coordinator blindly aggregates participant-supplied `(Y, C)` pairs without any zero-knowledge proof or commitment verification. A single malicious participant can inject arbitrary curve points, silently corrupting the confidential derived key that the coordinator outputs, with no mechanism for detection or attribution.

### Finding Description
In `do_ckd_coordinator`, the coordinator collects each participant's `(norm_big_y, norm_big_c)` contribution and sums them directly:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [1](#0-0) 

Each participant's honest contribution is computed in `compute_signature_share` as:
- `Y_i = y_i · G` (ephemeral blinding point)
- `C_i = x_i · H(pk ‖ app_id) + y_i · app_pk` (masked private-share contribution) [2](#0-1) 

The coordinator then forms the final output `(Y, C)` whose unmasking property is `C − app_sk · Y = msk · H(pk ‖ app_id)`.

**There is no proof of correct computation attached to any participant's message.** Nothing binds the received `(Y_i, C_i)` to the participant's actual signing share `x_i` or to the agreed `app_pk`. The coordinator has no way to distinguish a correctly formed contribution from an arbitrary pair of group elements.

This is structurally analogous to the MaltDataLab finding: just as the Malt protocol consumed oracle values that an external party could manipulate without inline verification, the CKD coordinator consumes participant-supplied cryptographic values without inline verification. In both cases the trusted aggregation step is the attack surface.

Contrast this with the DKG protocol in `src/dkg.rs`, which protects every participant contribution with a Schnorr proof-of-knowledge and a hash commitment scheme before any share is accepted: [3](#0-2) 

The CKD protocol provides no equivalent protection.

### Impact Explanation
A malicious participant corrupts the coordinator's CKD output. The coordinator unmasks `(Y, C)` with `app_sk` and obtains a wrong confidential derived key — one that does not equal `msk · H(pk ‖ app_id)`. Any downstream consumer of that key (e.g., an application decrypting data or deriving child keys) silently operates on a wrong value. This matches:

> **High: Corruption of DKG, reshare, refresh, presign, sign, or CKD outputs so honest parties accept inconsistent public keys, participant sets, transcripts, or unusable cryptographic outputs.**

The coordinator is the sole recipient of the output; it has no independent means to detect the corruption after the fact.

### Likelihood Explanation
- The attacker need only be one of the `N` participants — no threshold collusion is required.
- The attack requires sending two arbitrary group elements instead of the correct ones; it is trivially executable with a modified client.
- There is no commitment round, no proof, and no post-hoc consistency check in the protocol, so the attack leaves no detectable trace.
- The `ckd` entry point performs only participant-list and coordinator-presence checks before launching the protocol: [4](#0-3) 

Any authenticated participant can immediately exploit this.

### Recommendation
Each participant should accompany their `(Y_i, C_i)` with a zero-knowledge proof of correct formation — specifically, a proof that `C_i − y_i · app_pk` lies on the line `x_i · H(pk ‖ app_id)` for the same `x_i` committed to during DKG (i.e., a proof of discrete-log equality between `C_i − y_i · app_pk` and the participant's public verification share). The coordinator must verify all proofs before aggregating. This mirrors the proof-of-knowledge pattern already used in `do_keyshare` for DKG contributions.

### Proof of Concept
1. Honest participants hold shares `x_1, …, x_N` with master key `msk = Σ λ_i x_i`.
2. Malicious participant `i` sends `(Y_i', C_i') = (G, G)` (arbitrary non-zero points) instead of their correct contribution.
3. The coordinator computes:
   - `Y = Σ_{j≠i} λ_j Y_j + λ_i · G`
   - `C = Σ_{j≠i} λ_j C_j + λ_i · G`
4. Unmasking: `C − app_sk · Y = (msk − λ_i x_i) · H(pk ‖ app_id) + λ_i · G − λ_i · app_sk · G`, which is not equal to `msk · H(pk ‖ app_id)`.
5. The coordinator outputs a wrong confidential key with no error or warning. [5](#0-4)

### Citations

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

**File:** src/confidential_key_derivation/protocol.rs (L76-101)
```rust
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
