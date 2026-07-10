### Title
Missing Cryptographic Verification of Participant Contributions in CKD Protocol Allows Malicious Participant to Corrupt Derived Key Output - (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary
The Confidential Key Derivation (CKD) protocol's coordinator aggregates participant-supplied group elements without any zero-knowledge proof or cryptographic binding to each participant's actual secret share. A single malicious participant can send arbitrary `(big_y, big_c)` values to the coordinator, causing the final CKD output to be silently corrupted.

---

### Finding Description

In `compute_signature_share`, each participant computes:

```
big_s_i  = x_i · H(pk ‖ app_id)
big_c_i  = big_s_i + app_pk · y_i
norm_big_y_i = λ_i · big_y_i
norm_big_c_i = λ_i · big_c_i
```

and sends `(norm_big_y_i, norm_big_c_i)` privately to the coordinator. [1](#0-0) 

The coordinator in `do_ckd_coordinator` simply sums every received pair:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [2](#0-1) 

There is **no proof** that `big_s_i` was computed as `x_i · H(pk ‖ app_id)` using the participant's actual DKG secret share `x_i`. No Schnorr proof, no DLEQ proof, no commitment-and-reveal, and no echo-broadcast is used. The coordinator has no mechanism to detect or attribute a malformed contribution.

This is in direct contrast to the DKG protocol, which enforces a Schnorr proof-of-knowledge for every participant's polynomial constant term and verifies every received secret share against the public commitment before accepting it. [3](#0-2) [4](#0-3) 

---

### Impact Explanation

**High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

If participant A sends `(G1::identity(), G1::identity())` (the additive identity, i.e. a zero contribution), the coordinator computes:

```
big_y_final = Σ_{i≠A} λ_i · y_i · G
big_c_final = Σ_{i≠A} λ_i · (x_i · H + y_i · app_pk)
```

The client unmasks to:

```
big_c_final − a · big_y_final
  = Σ_{i≠A} λ_i · x_i · H(pk ‖ app_id)
  = (msk − λ_A · x_A) · H(pk ‖ app_id)
  ≠ msk · H(pk ‖ app_id)
```

The derived key is wrong. The client silently receives a corrupted confidential key with no error or indication of which participant misbehaved. More generally, a malicious participant can add any arbitrary `(δ_Y, δ_C)` offset to the final output, biasing the derived key to any value they choose (subject to not knowing `a`).

---

### Likelihood Explanation

**High.** Any single participant in the CKD protocol can execute this attack with zero cryptographic effort — they simply send the identity element or any arbitrary `ElementG1` pair instead of their correct contribution. The attack requires no special knowledge beyond participation in the protocol. The send is private (point-to-point to the coordinator), so other honest participants cannot observe or challenge it. [5](#0-4) 

---

### Recommendation

Add a DLEQ (Discrete Log Equality) zero-knowledge proof to each participant's contribution. Specifically, each participant should prove:

> "I know scalar `x_i` such that `x_i · G2 = vk_share_i` (the public verification share from DKG) **and** `x_i · H(pk ‖ app_id) = big_s_i`."

This is a standard two-base Schnorr proof (DLEQ proof) and is efficient. The coordinator must verify this proof before accepting any participant's `(norm_big_y_i, norm_big_c_i)`. This mirrors the proof-of-knowledge pattern already used in `proof_of_knowledge` / `internal_verify_proof_of_knowledge` in `src/dkg.rs`. [6](#0-5) 

---

### Proof of Concept

1. All `n` participants complete DKG, obtaining shares `x_i` and public key `msk · G2`.
2. A CKD session is initiated for `app_id` with `app_pk = a · G1`.
3. Malicious participant M, instead of calling `compute_signature_share` correctly, sends `(ElementG1::identity(), ElementG1::identity())` to the coordinator. [7](#0-6) 
4. The coordinator sums contributions; M's zero contribution silently drops `λ_M · x_M · H(pk ‖ app_id)` from the result. [2](#0-1) 
5. The client calls `ckd_output.unmask(app_sk)` and receives `(msk − λ_M · x_M) · H(pk ‖ app_id)` — a wrong key — with no error returned. [8](#0-7)

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

**File:** src/dkg.rs (L118-141)
```rust
fn proof_of_knowledge<C: Ciphersuite>(
    session_id: &HashOutput,
    domain_separator: &mut DomainSeparator,
    me: Participant,
    coefficients: &Polynomial<C>,
    coefficient_commitment: &PolynomialCommitment<C>,
    rng: &mut impl CryptoRngCore,
) -> Result<Signature<C>, ProtocolError> {
    // creates an identifier for the participant
    let id = me.scalar::<C>();
    let vk_share = coefficient_commitment.eval_at_zero()?;

    // pick a random k_i and compute R_id = g^{k_id},
    // Step 2.5
    let (k, big_r) = <C>::generate_nonce(rng);

    // Step 2.6
    // compute H(domain_separator, id, me, g^{a_0}, R_id) as a scalar
    let hash = challenge::<C>(domain_separator, session_id, id, &vk_share, &big_r)?;
    let a_0 = coefficients.eval_at_zero()?.0;
    // Step 2.7
    let mu = k + a_0 * hash.to_scalar();
    Ok(Signature::new(big_r, mu))
}
```

**File:** src/dkg.rs (L143-166)
```rust
/// Verifies the proof of knowledge of the secret coefficients used to generate the
/// public secret sharing commitment.
fn internal_verify_proof_of_knowledge<C: Ciphersuite>(
    session_id: &HashOutput,
    domain_separator: &mut DomainSeparator,
    participant: Participant,
    commitment: &VerifiableSecretSharingCommitment<C>,
    proof_of_knowledge: &Signature<C>,
) -> Result<(), ProtocolError> {
    // creates an identifier for the participant
    let id = participant.scalar::<C>();
    let vk_share = commitment
        .coefficients()
        .first()
        .ok_or_else(|| ProtocolError::AssertionFailed("Empty coefficient list".to_string()))?;

    let big_r = proof_of_knowledge.R();
    let z = proof_of_knowledge.z();
    let c = challenge::<C>(domain_separator, session_id, id, vk_share, big_r)?;
    if *big_r != <C::Group>::generator() * *z - vk_share.value() * c.to_scalar() {
        return Err(ProtocolError::InvalidProofOfKnowledge(participant));
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

**File:** src/confidential_key_derivation/mod.rs (L54-56)
```rust
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```
