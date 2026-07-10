### Title
Malicious CKD Participant Can Substitute Cryptographic Contribution With Arbitrary Values, Corrupting the Derived Key - (File: src/confidential_key_derivation/protocol.rs)

---

### Summary

The CKD protocol aggregates participant contributions `(big_y, big_c)` in the coordinator without any zero-knowledge proof or binding verification that each pair is correctly computed from the participant's actual secret share. A malicious participant — analogous to the external report's borrower who substitutes `repayFee` with a dust `issuanceValue` by routing through a self-controlled account — can send arbitrary group elements in place of their legitimate contribution. The coordinator blindly sums all received values and returns a `CKDOutput` that honest parties accept as valid, but which decrypts to an incorrect derived key.

---

### Finding Description

In `do_ckd_coordinator`, the coordinator receives `(big_y, big_c)` from every other participant and accumulates them with no integrity check:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [1](#0-0) 

Each honest participant is supposed to compute, inside `compute_signature_share`:

- `big_y = y · G` (random blinding point)
- `big_c = x_i · H(pk, app_id) + y · app_pk` (masked partial signature)
- then scale both by the Lagrange coefficient `λ_i` [2](#0-1) 

There is no ZK proof that `big_c` is correctly formed from the participant's actual `x_i`. The protocol simply trusts whatever bytes arrive over the channel.

**Attack path (single malicious participant):**

A participant `M` computes their correct values locally but instead sends `(big_y' = r·G, big_c' = r·app_pk)` for an attacker-chosen scalar `r`. This pair satisfies the structural form of a blinded share (it looks like a valid ElGamal ciphertext with `x_i = 0`), so no type-level or format check rejects it. The coordinator accumulates:

```
Y_total  = Σ_{j≠M} λ_j·Y_j  +  r·G
C_total  = Σ_{j≠M} λ_j·C_j  +  r·app_pk
```

When the TEE unmasks with `app_sk`:

```
C_total - app_sk · Y_total
  = Σ_{j≠M} λ_j·x_j·H  +  r·app_pk  -  app_sk·r·G
  = Σ_{j≠M} λ_j·x_j·H  +  r·(app_pk - app_sk·G)
  = Σ_{j≠M} λ_j·x_j·H          (since app_pk = app_sk·G)
  ≠ msk · H(pk, app_id)
```

The derived key is silently wrong. No honest party can detect the substitution because the coordinator returns a single `CKDOutput` with no per-participant attribution.

**Coordinator-as-attacker (self-dealing analog):**

The coordinator occupies a dual role: it computes its own `(norm_big_y, norm_big_c)` via `compute_signature_share` and then aggregates all other participants' shares. [3](#0-2) 

A malicious coordinator can:
1. Receive all honest participants' correct contributions.
2. Discard or replace one or more of them with attacker-chosen values.
3. Return a `CKDOutput` that appears structurally valid but decrypts to an incorrect key.

This is the direct analog of the external report's two-account self-dealing: just as Alice.1 exits to Alice.2 (which she controls) to substitute `repayFee` with a dust `issuanceValue`, a malicious coordinator uses its privileged aggregation role to substitute honest participants' `x_i · H` contributions with zero or arbitrary offsets — bypassing the security guarantee that the output equals `msk · H(pk, app_id)`.

The DKG protocol defends against this class of attack with Pedersen commitments and Schnorr proofs-of-knowledge verified by every participant: [4](#0-3) [5](#0-4) 

The CKD protocol has no equivalent binding mechanism.

---

### Impact Explanation

**Impact: High — Corruption of CKD output so honest parties accept an incorrect derived key.**

The `CKDOutput` returned by the coordinator is the sole result of the protocol. Honest participants (and the TEE that calls `unmask`) have no way to verify that the aggregated `(big_y, big_c)` reflects all participants' true shares. The TEE will derive and use a key that does not equal `msk · H(pk, app_id)`, silently breaking the confidential key derivation guarantee. Depending on the application, this can mean the TEE operates with a key that the attacker can predict or control.

---

### Likelihood Explanation

**Likelihood: High.**

Any participant in the protocol can execute this attack. No cryptographic prerequisites, leaked keys, or external assumptions are required. The attacker only needs to deviate from the honest protocol when sending their `(big_y, big_c)` message. The coordinator variant requires only that the attacker be selected as coordinator, which is an application-level decision with no cryptographic barrier.

---

### Recommendation

Add a non-interactive zero-knowledge proof of correct share contribution alongside each `(big_y, big_c)` message. Concretely, each participant should prove knowledge of `(x_i, y)` such that:

- `big_y = λ_i · y · G`
- `big_c = λ_i · (x_i · H + y · app_pk)`
- `x_i · G2 = vk_share_i` (binding to the committed verification share from DKG)

This is a standard Chaum-Pedersen / Sigma protocol and is consistent with the proof-of-knowledge infrastructure already present in `src/dkg.rs`. The coordinator should verify all proofs before aggregating, and reject any participant whose proof fails.

---

### Proof of Concept

**Setup:** 3-of-3 CKD with participants `{Alice, Bob, Mallory}`. Mallory is malicious.

1. All three participants run `compute_signature_share` locally.
2. Alice and Bob send their correct `(λ_A·Y_A, λ_A·C_A)` and `(λ_B·Y_B, λ_B·C_B)` to the coordinator.
3. Mallory, instead of sending `(λ_M·Y_M, λ_M·C_M)`, sends `(r·G, r·app_pk)` for a chosen `r` (e.g., `r = 1`, so she sends `(G, app_pk)`).
4. The coordinator (honest or Mallory herself) sums all three contributions.
5. The coordinator returns `CKDOutput { big_y: Y_A+Y_B+G, big_c: C_A+C_B+app_pk }`.
6. The TEE calls `unmask(app_sk)`:
   - Result = `(C_A+C_B+app_pk) - app_sk·(Y_A+Y_B+G)`
   - = `λ_A·x_A·H + λ_B·x_B·H + app_pk - app_sk·G`
   - = `λ_A·x_A·H + λ_B·x_B·H` (since `app_pk = app_sk·G`)
   - ≠ `msk·H` (missing `λ_M·x_M·H`)
7. The TEE silently uses the wrong derived key. No error is raised.

The attack requires no special privileges beyond being a protocol participant. [6](#0-5) [7](#0-6)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L17-58)
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

**File:** src/dkg.rs (L145-166)
```rust
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
