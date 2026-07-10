### Title
Malicious Participant Can Corrupt CKD Output Without Detection — (File: `src/confidential_key_derivation/protocol.rs`)

### Summary
The CKD coordinator aggregates participant contributions (`CKDOutput`) without any zero-knowledge proof or algebraic verification that each participant computed their share correctly. A single malicious participant can send an arbitrary `(big_y, big_c)` pair, silently corrupting the final confidential derived key accepted by all honest parties. No honest party can detect the corruption from the protocol output alone.

### Finding Description
The vulnerability class in the external report is **missing authorization/validation check**: an operation that should require a credential or proof proceeds without one. The direct analog here is that the CKD coordinator accepts participant contributions with no proof of correct computation.

**Root cause — `do_ckd_coordinator` (lines 35–57):**

```rust
async fn do_ckd_coordinator(...) -> Result<CKDOutputOption, ProtocolError> {
    let (mut norm_big_y, mut norm_big_c) =
        compute_signature_share(&participants, me, &key_pair, &app_id, app_pk, rng)?;

    let waitpoint = chan.next_waitpoint();
    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();   // ← no proof checked
        norm_big_c += participant_output.big_c();   // ← no proof checked
    }
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
    Ok(Some(ckd_output))
}
``` [1](#0-0) 

Each honest participant computes:

- `big_y = y·G` (random nonce)
- `big_s = private_share · H(pk ‖ app_id)`
- `big_c = big_s + y · app_pk`
- `norm_big_y = λᵢ · big_y`, `norm_big_c = λᵢ · big_c` [2](#0-1) 

The coordinator sums all `(norm_big_y, norm_big_c)` pairs. The application then recovers the confidential key as `sum_big_c − app_sk · sum_big_y = msk · H(pk ‖ app_id)`. This identity holds only if every participant contributed the correct values. There is no Chaum-Pedersen or equivalent ZK proof attached to each `CKDOutput`, and the coordinator performs no algebraic consistency check before summing.

A malicious participant `j` can instead send `(big_y', big_c')` of their choice. Because the coordinator blindly sums all contributions, the final output becomes:

```
sum_big_c − app_sk · sum_big_y
  = msk · H(pk ‖ app_id) + (big_c'_j − big_c_j) − app_sk · (big_y'_j − big_y_j)
```

which is an arbitrary offset from the correct key. The coordinator returns this corrupted `CKDOutput` as `Some(ckd_output)` with no error. [3](#0-2) 

Contrast this with the DKG protocol, which does verify every participant's contribution via `validate_received_share` and `verify_proof_of_knowledge` before accepting it: [4](#0-3) 

No equivalent verification exists in the CKD path.

### Impact Explanation
**High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

The coordinator and all honest participants accept the corrupted `CKDOutput` as the legitimate protocol result. The application-level `unmask(app_sk)` call will silently produce a wrong confidential key. Downstream consumers (e.g., TEE decryption, key derivation) will operate on an attacker-influenced value with no indication of failure. The correct key `msk · H(pk ‖ app_id)` is permanently unrecoverable from the corrupted output without re-running the protocol.

### Likelihood Explanation
**Medium.** The attacker must be a legitimate participant in the CKD session (i.e., hold a valid key share and be included in the `participants` list). No external capability is required beyond participation. The attack requires only sending a single malformed message at the correct waitpoint — a trivial deviation from the honest protocol. Because the library explicitly supports a "malicious participant" threat model (per `RESEARCHER.md` lines 38–43) and the CKD protocol is intended for multi-party TEE key derivation where participant compromise is a realistic scenario, this is reachable. [5](#0-4) 

### Recommendation
Add a zero-knowledge proof of correct share computation to each participant's `CKDOutput`. Specifically, each participant should attach a Chaum-Pedersen DLEQ proof demonstrating that `big_c − y · app_pk` lies on the correct subgroup relative to their public verification share. The coordinator must verify all proofs before summing. This is the standard mitigation for malicious-participant ElGamal threshold aggregation and is analogous to the `verify_proof_of_knowledge` + `validate_received_share` pattern already used in `do_keyshare`. [6](#0-5) 

### Proof of Concept
1. Run a 3-of-3 CKD session with participants `[P0, P1, P2]` and coordinator `P0`.
2. Participant `P1` (malicious) replaces their honest `(norm_big_y, norm_big_c)` with `(ElementG1::identity(), ElementG1::identity())` before calling `chan.send_private`.
3. The coordinator sums: `sum_big_y = norm_big_y_P0 + identity + norm_big_y_P2`, `sum_big_c = norm_big_c_P0 + identity + norm_big_c_P2`.
4. `ckd_output.unmask(app_sk)` returns `(norm_big_c_P0 + norm_big_c_P2) − app_sk · (norm_big_y_P0 + norm_big_y_P2)`, which equals `(λ₀·private_share₀ + λ₂·private_share₂) · H(pk ‖ app_id)` — a value that differs from the correct `msk · H(pk ‖ app_id)` by the missing `λ₁·private_share₁` term.
5. No error is raised anywhere in the protocol; the coordinator returns `Ok(Some(corrupted_ckd_output))`.

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

**File:** src/dkg.rs (L259-285)
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
```

**File:** src/dkg.rs (L514-522)
```rust
    for (from, signing_share_from) in
        recv_from_others(&chan, wait_round_3, &participants, me).await?
    {
        // Verify the share
        // this deviates from the original FROST DKG paper
        // however it matches the FROST implementation of ZCash
        let full_commitment_from = all_full_commitments.index(from)?;
        // Step 5.2
        validate_received_share::<C>(me, from, &signing_share_from, full_commitment_from)?;
```

**File:** RESEARCHER.md (L38-43)
```markdown
- External attacker with no privileged keys (default).
- Malicious normal user abusing valid product/protocol flows.
- Malicious API/RPC/web client submitting crafted inputs at scale.
- Malicious peer/integrator/oracle only where that role is reachable without
  privileged assumptions.

```
