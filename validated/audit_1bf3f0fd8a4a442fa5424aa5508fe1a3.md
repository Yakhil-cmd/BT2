### Title
Unvalidated Participant Outputs in CKD Coordinator Allow Any Malicious Participant to Corrupt the Derived Key — (File: `src/confidential_key_derivation/protocol.rs`)

### Summary
The `do_ckd_coordinator` function receives `CKDOutput` values (`big_y`, `big_c`) from every participant and aggregates them directly, with no proof or check that each participant's contribution was honestly computed. This is the precise structural analog of the Chainlink `latestRoundData` finding: data arriving from an external source is consumed without validating its integrity. A single malicious participant can silently corrupt the final CKD output, causing the application to unmask an incorrect derived key.

### Finding Description
In `src/confidential_key_derivation/protocol.rs`, `do_ckd_coordinator` (lines 50–55) performs:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

An honest participant computes their contribution in `compute_signature_share` (lines 148–182) as:

```
norm_big_y_i = λ_i · y_i · G
norm_big_c_i = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)
```

There is no zero-knowledge proof, commitment binding, or any other mechanism that forces a participant to submit values consistent with their actual signing share `x_i`. The coordinator blindly sums whatever group elements it receives. No existing check in `recv_from_others`, `CKDOutput::new`, or anywhere in the aggregation loop validates the content.

Compare with the DKG protocol (`src/dkg.rs`), which validates every received share against a published commitment (`validate_received_share`, line 259) and verifies a proof of knowledge (`verify_proof_of_knowledge`, line 172) before accepting any contribution. The CKD protocol has no equivalent safeguard.

The root cause is identical to the Chainlink analog: an external data source (here, a protocol participant) supplies a value that is used without checking whether it is valid or correctly formed.

### Impact Explanation
**High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

A malicious participant submits arbitrary `(big_y, big_c)` elements. The coordinator sums all contributions and produces a `CKDOutput` that does not equal `msk · H(pk ‖ app_id)`. When the application calls `CKDOutput::unmask(app_sk)` (line 54 of `mod.rs`):

```rust
pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
    self.big_c - self.big_y * secret_scalar
}
```

it silently receives an incorrect derived key. The application has no in-protocol mechanism to detect the corruption. This matches the allowed impact: *"Corruption of CKD outputs so honest parties accept unusable cryptographic outputs."*

### Likelihood Explanation
Any participant in the CKD protocol can mount this attack. No leaked keys, privileged access, or cryptographic breaks are required. The attacker simply deviates from `compute_signature_share` and sends arbitrary group elements. The attack is single-round, requires no coordination, and is undetectable by the coordinator or the application without an out-of-band check.

### Recommendation
Each participant should accompany their `(big_y, big_c)` submission with a zero-knowledge proof of correct computation — specifically a proof of discrete-log equality (dlogeq) demonstrating that the same witness `y_i` was used in both `big_y = y_i · G` and the `y_i · app_pk` term inside `big_c`, and that `big_c` encodes the correct share `x_i`. The codebase already contains a suitable primitive at `src/crypto/proofs/dlogeq.rs`. The coordinator must verify these proofs before aggregating any contribution, mirroring the share-validation pattern in `src/dkg.rs`.

### Proof of Concept
1. All participants except the attacker run `compute_signature_share` honestly.
2. The attacker, instead of computing their share, sends `CKDOutput::new(ElementG1::generator(), ElementG1::generator())` — two arbitrary non-identity points unrelated to their signing share.
3. `do_ckd_coordinator` receives this output at line 50–55 and adds it to `norm_big_y` and `norm_big_c` without any validation.
4. The final `CKDOutput` satisfies `big_c - a · big_y ≠ msk · H(pk ‖ app_id)` for any `a`.
5. The application calls `unmask(app_sk)` and receives a garbage key, silently accepting a corrupted CKD output with no error or warning. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

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

**File:** src/dkg.rs (L172-218)
```rust
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

**File:** src/dkg.rs (L259-286)
```rust
fn validate_received_share<C: Ciphersuite>(
    me: Participant,
    from: Participant,
    signing_share_from: &SigningShare<C>,
    commitment: &VerifiableSecretSharingCommitment<C>,
) -> Result<(), ProtocolError> {
    let id = me.to_identifier::<C>()?;

    // The verification is exactly the same as the regular SecretShare verification;
    // however the required components are in different places.
    // Build a temporary SecretShare so what we can call verify().
    let secret_share = SecretShare::new(id, *signing_share_from, commitment.clone());

    // Verify the share. We don't need the result.
    // Identify the culprit if an InvalidSecretShare error is returned.
    secret_share.verify().map_err(|e| {
        if let Error::InvalidSecretShare { .. } = e {
            ProtocolError::InvalidSecretShare(from)
        } else {
            ProtocolError::AssertionFailed(format!(
                "could not
            extract the verification key matching the secret
            share sent by {from:?}"
            ))
        }
    })?;
    Ok(())
}
```
