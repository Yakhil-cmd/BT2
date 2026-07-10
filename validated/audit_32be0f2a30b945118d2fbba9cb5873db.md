### Title
Malicious Participant Can Corrupt CKD Output via Unverified Contribution Values — (File: src/confidential_key_derivation/protocol.rs)

---

### Summary

The CKD coordinator aggregates `(norm_big_y, norm_big_c)` contributions from every participant by simple addition, but performs **no verification** that each contribution was computed using the participant's actual signing share, the correct `app_id`, or the correct `app_pk`. This is the direct analog of the ERC-1155 refinance bug: participant identity is authenticated (the channel knows *who* sent the message), but the *content* of the contribution — the cryptographic values — is never checked. A single malicious participant can inject arbitrary group elements, causing the coordinator to output a structurally valid but cryptographically wrong CKD result that all honest parties accept.

---

### Finding Description

**Root cause — `do_ckd_coordinator`, lines 44–57:**

```rust
async fn do_ckd_coordinator(...) -> Result<CKDOutputOption, ProtocolError> {
    let (mut norm_big_y, mut norm_big_c) =
        compute_signature_share(&participants, me, key_pair, app_id, app_pk, rng)?;

    let waitpoint = chan.next_waitpoint();

    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();   // ← no verification
        norm_big_c += participant_output.big_c();   // ← no verification
    }
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
    Ok(Some(ckd_output))
}
``` [1](#0-0) 

The correct per-participant contribution is computed in `compute_signature_share` as:

```
norm_big_y = λ_i · y_i · G
norm_big_c = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)
``` [2](#0-1) 

The coordinator sums these to obtain `(Y, C)`. The app then recovers the confidential key as `K = C − app_sk · Y = msk · H(pk ‖ app_id)`. This identity holds **only if every participant contributed honestly**. There is no zero-knowledge proof, commitment check, or any other mechanism to enforce this.

**Checked field (analog to NFT address/ID):** Participant identity — `recv_from_others` authenticates *who* sent the message via the channel.

**Unchecked field (analog to ERC-1155 amount):** The actual values `big_y` and `big_c` inside the `CKDOutput` — these are accepted and summed unconditionally.

**Attack path:**

1. Malicious participant `P_m` is a valid member of the CKD participant list.
2. Instead of calling `compute_signature_share` honestly, `P_m` constructs arbitrary `(Y_m, C_m)` in G1 and sends them to the coordinator.
3. The coordinator adds `Y_m` and `C_m` to the running sums without any check.
4. The final output is `(Y_correct + Y_m, C_correct + C_m)`.
5. The app recovers `K_wrong = K_correct + (C_m − app_sk · Y_m)`, which is not `msk · H(pk ‖ app_id)`.
6. The coordinator returns `Some(ckd_output)` — a structurally valid result — and all honest parties accept it.

---

### Impact Explanation

**High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

The coordinator outputs a `CKDOutput` that is indistinguishable in structure from a correct one. No honest party detects the corruption. The app derives a confidential key `K_wrong` that does not equal `msk · H(pk ‖ app_id)`, making the derived key permanently wrong for that `(pk, app_id)` pair. Any downstream use of the confidential key (e.g., decryption, authentication) silently fails or produces incorrect results.

The malicious participant cannot *choose* the exact wrong key (that would require knowing `app_sk`), but they can guarantee the output is wrong, which is sufficient for a targeted denial-of-derivation or silent corruption attack.

---

### Likelihood Explanation

Any single participant in the CKD protocol can trigger this. No privileged access, no leaked keys, and no cryptographic break is required. The attacker only needs to be a valid member of the participant list — a role that is explicitly in scope per the library's trust model. The attack requires modifying one's own local protocol execution, which is trivially achievable by any library caller.

---

### Recommendation

Add a zero-knowledge proof of correct computation to each participant's contribution. Specifically, each participant should prove in zero knowledge that:

- `norm_big_y = λ_i · y_i · G` for some `y_i` they know, and
- `norm_big_c = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)` using the same `y_i` and their committed signing share `x_i`.

A standard `dleq`-style proof (discrete log equality) over the BLS12-381 G1 group suffices to bind `norm_big_y` and `norm_big_c` together and to the participant's public key share. The coordinator must verify each proof before adding the contribution to the running sum, analogous to how the DKG already verifies proofs of knowledge before accepting polynomial commitments. [3](#0-2) 

---

### Proof of Concept

**Setup:** 3-of-3 CKD with participants `{P1, P2, P3}`, coordinator = `P1`. `P3` is malicious.

**Honest execution:**
- Each `P_i` computes `(norm_big_y_i, norm_big_c_i)` using `compute_signature_share`.
- Coordinator sums all three; app recovers `K = msk · H(pk ‖ app_id)`. ✓

**Attack:**
- `P3` replaces its contribution with `(norm_big_y_3 = G, norm_big_c_3 = G)` (arbitrary non-zero points).
- Coordinator receives `(G, G)` from `P3` and adds them unconditionally.
- Final output: `Y_final = Y_P1 + Y_P2 + G`, `C_final = C_P1 + C_P2 + G`.
- App recovers `K_wrong = K_correct + (G − app_sk · G) = K_correct + (1 − app_sk) · G`.
- `K_wrong ≠ msk · H(pk ‖ app_id)` with overwhelming probability.
- Coordinator returns `Some(CKDOutput { norm_big_y: Y_final, norm_big_c: C_final })` — accepted as valid by all honest parties. [4](#0-3)

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
