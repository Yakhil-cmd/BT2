### Title
Unverified Participant Contributions in CKD Coordinator Allow Malicious Participant to Corrupt Confidential Key Derivation Output — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The CKD coordinator in `do_ckd_coordinator` blindly accumulates `(norm_big_y, norm_big_c)` group elements received from every participant with no cryptographic verification. A single malicious participant can substitute arbitrary `ElementG1` values, causing the coordinator to produce a corrupted `CKDOutput`. The client then unmasks a wrong confidential key with no ability to detect the corruption. This is the direct analog of the ERC20 finding: just as `topupMarketBalance` updated `marketBalance` without checking whether the transfer succeeded, the CKD coordinator updates its running sums without checking whether each participant's contribution is honestly computed.

---

### Finding Description

In `do_ckd_coordinator`, after computing its own share, the coordinator loops over all other participants' messages and unconditionally adds each received pair into the accumulator:

```rust
// src/confidential_key_derivation/protocol.rs  lines 50-55
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [1](#0-0) 

No proof, commitment, or consistency check is applied to the received `big_y` / `big_c` values before they are folded into the output. The final `CKDOutput` is then returned directly:

```rust
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
Ok(Some(ckd_output))
``` [2](#0-1) 

Compare this with the DKG protocol, which applies three independent verification layers before accepting any participant contribution:

- `verify_proof_of_knowledge` — Schnorr ZK proof over the committed polynomial constant term [3](#0-2) 
- `verify_commitment_hash` — hash-binding of the broadcast commitment to the pre-committed hash [4](#0-3) 
- `validate_received_share` — algebraic consistency of the secret share against the commitment [5](#0-4) 

The CKD protocol has none of these guards. The `compute_signature_share` function that an honest participant calls produces:

```
norm_big_y = λᵢ · yᵢ · G
norm_big_c = λᵢ · (xᵢ · H(pk ‖ app_id) + yᵢ · app_pk)
``` [6](#0-5) 

A malicious participant can send any pair of `G1` points instead. The coordinator has no mechanism to distinguish a correct share from an arbitrary group element. The `KeygenOutput` type exposed to the coordinator contains only the master public key and the coordinator's own private share — individual per-participant public key shares are not stored — so even a pairing-based consistency check is not straightforwardly available. [7](#0-6) 

---

### Impact Explanation

The corrupted `CKDOutput` is returned to the caller as the authoritative result. When the client calls `unmask(app_sk)`:

```rust
pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
    self.big_c - self.big_y * secret_scalar
}
``` [8](#0-7) 

it obtains a wrong `Signature` (confidential derived key). The client has no reference value to check against; the protocol provides no output-validity proof. The derived key is silently wrong. This matches the allowed High impact: **Corruption of CKD outputs so honest parties accept unusable cryptographic outputs**.

---

### Likelihood Explanation

Any single participant in the CKD session is sufficient to corrupt the output. The attacker needs only to deviate from `compute_signature_share` and send arbitrary `ElementG1` bytes over the channel. No special privilege, no key material beyond their own share, and no coordination with other participants is required. The coordinator's receive loop processes all messages identically regardless of content.

---

### Recommendation

1. **Add a per-share consistency proof.** Each participant should accompany `(norm_big_y, norm_big_c)` with a Chaum–Pedersen DLEQ proof demonstrating that the discrete-log relationship between `norm_big_y` and `norm_big_c` is consistent with the participant's public key share. The coordinator verifies each proof before accumulating.

2. **Expose per-participant public key shares from DKG.** The `KeygenOutput` structure currently omits individual verification shares. Storing them enables the coordinator to check `norm_big_c − norm_big_y · app_pk =? λᵢ · vk_shareᵢ · H(pk ‖ app_id)` without a ZK proof.

3. **Mirror the DKG pattern.** Apply the same three-layer guard (commitment hash → broadcast → algebraic verification) that `do_keyshare` uses before folding any participant contribution into the running sum.

---

### Proof of Concept

1. Honest participants run `ckd(...)` normally; the malicious participant also calls `ckd(...)` but replaces the `chan.send_private` payload with two arbitrary `G1` points, e.g., `(G, G)` (the generator repeated).
2. The coordinator's loop at lines 50–55 adds these arbitrary points into `norm_big_y` and `norm_big_c` without error.
3. `CKDOutput::new(norm_big_y, norm_big_c)` is returned to the caller.
4. The client calls `unmask(app_sk)` and receives `big_c − big_y · app_sk`, which is not equal to `msk · H(pk ‖ app_id)`.
5. The client silently uses the wrong derived key; no error is raised at any layer of the protocol.

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L50-55)
```rust
    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
```

**File:** src/confidential_key_derivation/protocol.rs (L56-57)
```rust
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
    Ok(Some(ckd_output))
```

**File:** src/confidential_key_derivation/protocol.rs (L148-181)
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

**File:** src/dkg.rs (L222-236)
```rust
fn verify_commitment_hash<C: Ciphersuite>(
    session_id: &HashOutput,
    participant: Participant,
    domain_separator: &mut DomainSeparator,
    commitment: &VerifiableSecretSharingCommitment<C>,
    all_hash_commitments: &ParticipantMap<'_, HashOutput>,
) -> Result<(), ProtocolError> {
    let actual_commitment_hash = all_hash_commitments.index(participant)?;
    let commitment_hash =
        domain_separate_hash(domain_separator, &(&participant, &commitment, &session_id))?;
    if *actual_commitment_hash != commitment_hash {
        return Err(ProtocolError::InvalidCommitmentHash);
    }
    Ok(())
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

**File:** src/confidential_key_derivation/mod.rs (L27-28)
```rust
pub type KeygenOutput = crate::KeygenOutput<BLS12381SHA256>;
pub type SigningShare = crate::SigningShare<BLS12381SHA256>;
```

**File:** src/confidential_key_derivation/mod.rs (L54-56)
```rust
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```
