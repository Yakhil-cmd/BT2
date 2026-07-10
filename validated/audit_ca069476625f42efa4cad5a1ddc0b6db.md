Looking at the CKD protocol in `src/confidential_key_derivation/protocol.rs`, I can identify a valid analog.

The external report's vulnerability class is: **accepting an operation's output without validating it meets a minimum correctness/security threshold** (hardcoded `amountOutMinimum = 1`). The analog here is the CKD coordinator accepting participant shares with **no cryptographic proof of correctness**, allowing a malicious participant to inject arbitrary values.

---

### Title
Missing Share Validity Proof in CKD Coordinator Allows Malicious Participant to Corrupt Confidential Key Derivation Output - (File: `src/confidential_key_derivation/protocol.rs`)

### Summary
The CKD coordinator in `do_ckd_coordinator` aggregates participant shares into the final `CKDOutput` without any cryptographic proof that each share was honestly computed from the participant's actual private key share. A single malicious participant can send arbitrary `(big_y, big_c)` group elements, causing the coordinator to produce a corrupted CKD output that the requester will silently accept as valid.

### Finding Description
In `do_ckd_coordinator`, the coordinator receives `CKDOutput` values from all other participants and unconditionally adds them together:

```rust
// src/confidential_key_derivation/protocol.rs lines 50-55
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [1](#0-0) 

There is no check that `participant_output.big_c()` is a valid ElGamal encryption of a BLS signature share derived from the participant's actual private key share, and no check that `participant_output.big_y()` is a valid randomness commitment.

The honest computation in `compute_signature_share` is:

```
big_s  = hash_point * private_share          // BLS signature share
big_c  = big_s + app_pk * y                  // ElGamal encryption
big_y  = y * G                               // randomness commitment
norm_big_y = lambda_i * big_y
norm_big_c = lambda_i * big_c
``` [2](#0-1) 

A malicious participant can substitute any pair `(norm_big_y', norm_big_c')` for their honest contribution. The coordinator has no mechanism to detect this substitution because no zero-knowledge proof of correct share formation is required or verified.

Contrast this with the DKG protocol, which requires every participant to supply a proof of knowledge of their secret coefficient and validates each received share against a public polynomial commitment before accepting it: [3](#0-2) 

The CKD protocol has no equivalent validation step.

### Impact Explanation
When the coordinator aggregates the corrupted share, the final output becomes:

```
Y_total = Y_honest + norm_big_y'
C_total = C_honest + norm_big_c'
```

The requester unmasks with their secret key `app_sk`:

```
C_total - app_sk * Y_total
  = msk * hash_point + (norm_big_c' - app_sk * norm_big_y')
```

The term `(norm_big_c' - app_sk * norm_big_y')` is an attacker-controlled additive offset that shifts the derived confidential key away from the correct value `msk * hash_point`. The requester receives and accepts this corrupted key with no indication that it is wrong, because the CKD protocol returns no proof of correctness for the final output.

This matches the allowed impact: **High — Corruption of CKD outputs so honest parties accept unusable or incorrect cryptographic outputs.**

### Likelihood Explanation
Any single participant in the CKD session can execute this attack. No special privilege beyond participation is required. The malicious participant simply sends arbitrary group elements instead of their honest share. The coordinator has no way to distinguish honest from malicious contributions. Likelihood is **High**.

### Recommendation
Require each participant to accompany their `(norm_big_y, norm_big_c)` contribution with a non-interactive zero-knowledge proof of correct formation — specifically, a proof that `norm_big_c - norm_big_y * app_pk = lambda_i * hash_point * private_share`, where `private_share` corresponds to the participant's public verification share (which is publicly known after DKG). The coordinator must verify all proofs before aggregating. This is the standard approach used in verifiable threshold BLS/ElGamal schemes and mirrors the proof-of-knowledge validation already present in the DKG protocol at `src/dkg.rs`.

### Proof of Concept
1. Run a CKD session with `n` participants, one of which is malicious.
2. The malicious participant, instead of calling `compute_signature_share`, sends `(norm_big_y', norm_big_c') = (G1::generator(), G1::generator())` to the coordinator.
3. The coordinator at lines 50–55 adds these values to the running sum without any check.
4. The coordinator returns `CKDOutput { big_y: Y_honest + G, big_c: C_honest + G }`.
5. The requester calls `ckd_output.unmask(app_sk)` and obtains `msk * hash_point + (G - app_sk * G)`, which is not the correct confidential key.
6. The requester has no way to detect the corruption; the protocol returns `Ok(Some(ckd_output))` with no error. [4](#0-3)

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

**File:** src/confidential_key_derivation/protocol.rs (L159-180)
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
```

**File:** src/dkg.rs (L452-476)
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

        // in case the participant was new and it sent a polynomial of length
        // threshold -1 (because the zero term is not serializable)
        let full_commitment_i = insert_identity_if_missing(threshold, commitment_i);

        // add received full commitment
        all_full_commitments.put(p, full_commitment_i);
```
