### Title
Malicious CKD Participant Can Corrupt Derived Key by Submitting Unverified Contributions Without Proof of Correct Private-Share Usage — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The CKD coordinator accumulates each participant's `(norm_big_y, norm_big_c)` contribution without any cryptographic proof that the contribution was computed from the participant's actual private share. Any single malicious participant can send arbitrary group elements, causing the coordinator and all honest parties to accept a corrupted, unusable CKD output. This is the direct analog of BAB-2: the NFT contract verified controller approval but not creator ownership; here the protocol verifies that a message arrived from a known participant (network authentication) but not that the participant's contribution is bound to their actual key share.

---

### Finding Description

In `do_ckd_coordinator` the coordinator collects one `CKDOutput` from every other participant and blindly sums the group elements:

```rust
// src/confidential_key_derivation/protocol.rs  L50-55
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [1](#0-0) 

The participant identity returned by `recv_from_others` is discarded (`_`), and no zero-knowledge proof or consistency check is performed on the received `(norm_big_y, norm_big_c)` pair. [2](#0-1) 

The correct computation each participant is supposed to perform is:

```
Y_i  = y_i · G
S_i  = x_i · H(pk ‖ app_id)
C_i  = S_i + y_i · app_pk
norm_big_y = λ_i · Y_i
norm_big_c = λ_i · C_i
```

where `x_i` is the participant's private share and `y_i` is a fresh random scalar. [3](#0-2) 

Nothing in the protocol forces a participant to use their actual `x_i`. A malicious participant can substitute any pair of group elements `(A, B)` for `(norm_big_y, norm_big_c)`. The coordinator sums all contributions and returns the result as a valid `CKDOutput`. [4](#0-3) 

Contrast this with the DKG, which requires every participant to supply a Schnorr proof-of-knowledge over their secret coefficient before any share is accepted:

```rust
// src/dkg.rs  L452-460
verify_proof_of_knowledge(
    &session_id,
    &mut proof_domain_separator.clone(),
    threshold,
    p,
    old_participants.clone(),
    commitment_i,
    proof_i.as_ref(),
)?;
``` [5](#0-4) 

No equivalent proof exists for CKD contributions.

---

### Impact Explanation

The final `CKDOutput` is the sum of all participants' `(norm_big_y, norm_big_c)` pairs. If even one participant substitutes arbitrary group elements, the aggregate is wrong. The coordinator returns this corrupted aggregate as `Some(ckd_output)`, and the application unmasks it with `app_sk` to obtain a derived key that does not equal `msk · H(pk ‖ app_id)`. [4](#0-3) 

This matches the allowed impact: **High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.** The honest coordinator and all downstream consumers of the derived key receive a silently wrong result with no error signal.

---

### Likelihood Explanation

Any single participant in the CKD session is sufficient to trigger the corruption. No privileged access, leaked keys, or external assumptions are required. The attacker only needs to be a legitimate (but malicious) participant — a role explicitly listed in `RESEARCHER.md` as an in-scope attacker profile. [6](#0-5) 

---

### Recommendation

Add a zero-knowledge proof of correct contribution to the CKD participant message, analogous to the DKG proof-of-knowledge. Specifically, each participant should prove in zero knowledge that:

- `norm_big_y = λ_i · y_i · G` for a known `y_i`, and  
- `norm_big_c = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)` for the same `y_i` and for `x_i` consistent with the participant's public verification share from the DKG output.

The coordinator must verify this proof before accumulating the contribution, mirroring the `verify_proof_of_knowledge` call in the DKG round. [7](#0-6) 

---

### Proof of Concept

1. Run the CKD protocol with `N = 3` participants, one of which is malicious.  
2. The malicious participant, instead of calling `compute_signature_share`, sends `(ElementG1::identity(), ElementG1::identity())` to the coordinator.  
3. The coordinator executes:
   ```rust
   norm_big_y += ElementG1::identity();  // no-op, silently accepted
   norm_big_c += ElementG1::identity();  // no-op, silently accepted
   ``` [8](#0-7) 
4. The returned `CKDOutput` omits the malicious participant's share of `msk · H(pk ‖ app_id)`.  
5. `ckd_output.unmask(app_sk)` yields a value that differs from `msk · H(pk ‖ app_id)`, silently breaking the confidential key derivation for all honest parties with no error returned.

### Citations

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

**File:** src/dkg.rs (L171-218)
```rust
/// performing reshare and does not exist in the set of old participants
fn verify_proof_of_knowledge<C: Ciphersuite>(
    session_id: &HashOutput,
    domain_separator: &mut DomainSeparator,
    threshold: ReconstructionLowerBound,
    participant: Participant,
    old_participants: Option<ParticipantList>,
    commitment: &VerifiableSecretSharingCommitment<C>,
    proof_of_knowledge: Option<&Signature<C>>,
) -> Result<(), ProtocolError> {
    let threshold = threshold.value();
    match proof_of_knowledge {
        // if participant did not send anything but he is actually an old participant
        None => {
            // if basic dkg or participant is old
            if old_participants.is_none_or(|p| p.contains(participant)) {
                return Err(ProtocolError::MaliciousParticipant(participant));
            }
            // since previous line did not abort, then we know participant is new indeed
            // check the commitment length is threshold - 1
            if commitment.coefficients().len() != threshold - 1 {
                return Err(ProtocolError::IncorrectNumberOfCommitments);
            }
            // nothing to verify
            Ok(())
        }
        // now we know the proof is not none
        Some(proof_of_knowledge) => {
            // if participant sent something but he is actually a new participant
            if old_participants.is_some_and(|p| !p.contains(participant)) {
                return Err(ProtocolError::MaliciousParticipant(participant));
            }
            // since the previous did not abort, we know the participant is old or we are dealing with a dkg
            if commitment.coefficients().len() != threshold {
                return Err(ProtocolError::IncorrectNumberOfCommitments);
            }

            // creating an identifier as required by the syntax of verify_proof_of_knowledge of frost_core
            internal_verify_proof_of_knowledge(
                session_id,
                domain_separator,
                participant,
                commitment,
                proof_of_knowledge,
            )
        }
    }
}
```

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

**File:** RESEARCHER.md (L36-42)
```markdown
## Attacker Profiles You Must Emulate

- External attacker with no privileged keys (default).
- Malicious normal user abusing valid product/protocol flows.
- Malicious API/RPC/web client submitting crafted inputs at scale.
- Malicious peer/integrator/oracle only where that role is reachable without
  privileged assumptions.
```
