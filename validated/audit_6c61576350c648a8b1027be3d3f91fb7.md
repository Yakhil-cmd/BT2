### Title
Missing Cryptographic Validation of Participant Shares in CKD Coordinator Allows Malicious Participant to Corrupt Confidential Key Derivation Output — (`src/confidential_key_derivation/protocol.rs`)

---

### Summary

The CKD coordinator in `do_ckd_coordinator` blindly accumulates `(big_y, big_c)` shares from participants with no cryptographic verification. A single malicious participant can send arbitrary group elements, causing the coordinator to assemble a corrupted `CKDOutput`. The TEE application that calls `unmask(app_sk)` on this output silently derives a wrong confidential key with no way to detect the corruption.

---

### Finding Description

In `do_ckd_coordinator` (lines 44–57 of `src/confidential_key_derivation/protocol.rs`), the coordinator receives each participant's `(norm_big_y, norm_big_c)` pair and sums them unconditionally:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
```

The correct share from participant `i` is computed in `compute_signature_share` as:

```
norm_big_y_i = λ_i · y_i · G
norm_big_c_i = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)
```

The invariant that makes the output useful is:

```
C_total − Y_total · app_sk  =  msk · H(pk ‖ app_id)
```

No ZK proof, commitment, or consistency check is attached to the shares sent by participants. A malicious participant `j` can send any pair `(big_y', big_c')` instead of their correct share. The coordinator will compute:

```
Y_total  = Y_honest + big_y'
C_total  = C_honest + big_c'
```

The TEE then calls `unmask(app_sk)` and obtains:

```
C_total − Y_total · app_sk
  = msk · H(pk ‖ app_id) − (correct_j_contribution) + big_c' − big_y' · app_sk
```

which is not `msk · H(pk ‖ app_id)` unless the malicious participant happens to send their correct share. The TEE has no way to detect the corruption; it simply uses whatever scalar emerges.

Contrast this with the OT-based ECDSA presign (`src/ecdsa/ot_based_ecdsa/presign.rs`, lines 125–131 and 159–168), which explicitly checks `E = e·G`, `α·G = K + A`, and `β·G = X + B` before accepting any aggregated value. The robust ECDSA presign (`src/ecdsa/robust_ecdsa/presign.rs`, lines 193–213 and 274–291) similarly performs exponent-interpolation consistency checks on every received share. The CKD protocol has no analogous guard.

---

### Impact Explanation

**High — Corruption of CKD outputs so honest parties accept incorrect cryptographic outputs.**

The TEE application receives a `CKDOutput` that does not encode `msk · H(pk ‖ app_id)`. When it calls `unmask(app_sk)` it derives a wrong confidential key and uses it as if it were correct. This breaks the core security guarantee of the CKD protocol: that the derived secret is the deterministic function of the master secret key and the application identifier. The corruption is silent — no error is raised anywhere in the protocol or in the TEE decryption path.

---

### Likelihood Explanation

Any single participant in the CKD signing set can trigger this. The attacker needs only to be a legitimately enrolled participant (i.e., hold a valid key share from DKG). No external assumptions, leaked keys, or cryptographic breaks are required. The attack is a single-round, one-message deviation: send a wrong `(big_y, big_c)` to the coordinator.

---

### Recommendation

Each participant should accompany their `(norm_big_y, norm_big_c)` with a non-interactive ZK proof of correct formation. Concretely, the participant must prove knowledge of `(y_i, x_i)` such that:

- `norm_big_y = λ_i · y_i · G`
- `norm_big_c = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)`
- `x_i` is consistent with the participant's public verification share (derivable from the DKG output)

A standard sigma protocol (DLEQ proof) over the BLS12-381 G1 group suffices for the `y_i` component; the `x_i` consistency can be checked against the public polynomial commitment from DKG. The coordinator must verify all proofs before summing any shares, mirroring the pattern already used in the OT-based and robust ECDSA presign protocols.

---

### Proof of Concept

1. Run DKG with participants `{P1, P2, P3}` and threshold 2.
2. Initiate a CKD session with all three participants; `P1` is coordinator.
3. `P2` (malicious) sends `(big_y' = G, big_c' = G)` instead of its correct share.
4. `P1` (coordinator) sums: `Y_total = Y_honest + G`, `C_total = C_honest + G`.
5. `P1` returns `CKDOutput::new(Y_total, C_total)` to the TEE.
6. TEE calls `ckd_output.unmask(app_sk)` and obtains `C_total − Y_total · app_sk`, which equals `msk · H(pk ‖ app_id) + G − G · app_sk` — a value that is not the intended confidential key and varies with `app_sk`.
7. No error is raised at any step; the TEE silently uses the wrong key.

**Root cause lines:** [1](#0-0) 

**Correct-share computation (no proof attached):** [2](#0-1) 

**Contrast — OT-based ECDSA presign share validation:** [3](#0-2) [4](#0-3) 

**Contrast — Robust ECDSA presign exponent-interpolation checks:** [5](#0-4)

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

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L125-131)
```rust
    // E =?= e*G
    // Spec 1.5
    if big_e != (ProjectivePoint::GENERATOR * e).to_affine() {
        return Err(ProtocolError::AssertionFailed(
            "received incorrect shares of kd".to_string(),
        ));
    }
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L159-168)
```rust
    // alpha*G =?= K + A
    // beta*G =?= X + B
    // Spec 2.5
    if (ProjectivePoint::GENERATOR * alpha != big_k + big_a)
        || (ProjectivePoint::GENERATOR * beta != big_x + big_b)
    {
        return Err(ProtocolError::AssertionFailed(
            "received incorrect shares of additive triple phase.".to_string(),
        ));
    }
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L193-213)
```rust
    // check that the exponent interpolations match what has been received
    for (identifier, verifying_share) in identifiers
        .iter()
        .skip(threshold + 1)
        .zip(verifying_shares.iter().skip(threshold + 1))
    {
        // Step 3.2
        // exponent interpolation for (R0, .., Rt; i)
        let big_r_i = PolynomialCommitment::eval_exponent_interpolation(
            threshold_plus1_identifiers,
            threshold_plus1_verifying_shares,
            Some(identifier),
        )?;

        // check the interpolated R values match the received ones
        if big_r_i != *verifying_share {
            return Err(ProtocolError::AssertionFailed(
                "Exponent interpolation check failed.".to_string(),
            ));
        }
    }
```
