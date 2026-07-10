### Title
Malicious CKD Participant Sends Unverified Contribution, Corrupting Derived Confidential Key - (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The Confidential Key Derivation (CKD) coordinator accumulates `(big_y, big_c)` shares from every participant with no cryptographic proof that each share was correctly computed from the participant's actual private signing share. A malicious participant can send arbitrary group elements, causing the coordinator to output a CKD result that does not correspond to the true master secret key applied to the application hash. All honest parties accept this corrupted output without any means of detection.

---

### Finding Description

**Root cause:** In `do_ckd_coordinator` (`src/confidential_key_derivation/protocol.rs`, lines 50–55), the coordinator receives a `CKDOutput` from every other participant and blindly adds the two group elements together:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

The correct per-participant computation (performed in `compute_signature_share`, lines 148–181) is:

```
big_y  = y_i * G                          (random blinding)
big_s  = x_i * H(pk || app_id)            (private share contribution)
big_c  = big_s + y_i * app_pk             (ElGamal encryption of big_s)
norm_big_y = lambda_i * big_y
norm_big_c = lambda_i * big_c
```

There is **no zero-knowledge proof, no commitment, and no consistency check** that the received `(norm_big_y, norm_big_c)` pair was produced using the participant's actual private share `x_i`. The coordinator simply trusts whatever group elements arrive over the channel.

**Exploit path:**

1. A malicious participant `P_m` participates in a legitimate CKD session.
2. Instead of calling `compute_signature_share` honestly, `P_m` sends `(G1::identity(), G1::identity())` (or any arbitrary pair) to the coordinator.
3. The coordinator accumulates these values alongside the honest contributions and produces a `CKDOutput`.
4. The final output is:

```
Y_final = sum_{i ≠ m}(lambda_i * y_i * G)  +  0
C_final = sum_{i ≠ m}(lambda_i * (x_i * H + y_i * app_pk))  +  0
```

5. When the application unmasks: `C_final - app_sk * Y_final = (msk - lambda_m * x_m) * H(pk, app_id)`, which is **not** the correct derived key `msk * H(pk, app_id)`.

The coordinator returns this corrupted `CKDOutput` as `Some(ckd_output)` with no error, and all honest parties accept it.

**Analog to the external report:** Just as the escrow contract stores `amount = X` without verifying that `X` was actually paid (because `msg.value == 0` skips the check), the CKD coordinator stores `norm_big_y += participant_output.big_y()` without verifying that `big_y` and `big_c` were actually derived from the participant's private share. In both cases, the system records a claimed contribution as genuine and produces outputs based on that false premise.

---

### Impact Explanation

**High — Corruption of CKD outputs so honest parties accept an incorrect derived confidential key.**

The derived key output by the coordinator will not equal `msk * H(pk || app_id)`. Any downstream use of this key (e.g., decryption, authentication, secret derivation in a TEE) will silently fail or produce incorrect results. Because the coordinator returns `Ok(Some(ckd_output))` with no error, honest parties have no signal that the output is invalid. The corruption is permanent for that CKD session.

---

### Likelihood Explanation

Any participant in a CKD session can trigger this. The attacker needs only:
- A valid key share from a prior DKG (a normal participant role, no privilege required).
- The ability to send a crafted message to the coordinator — which is the standard protocol message path.

No cryptographic primitive needs to be broken. The attack is a single-round deviation from the protocol.

---

### Recommendation

Each participant must accompany their `(norm_big_y, norm_big_c)` with a non-interactive zero-knowledge proof of correct formation — specifically, a proof that `big_c - y_i * app_pk` lies on the line `x_i * H(pk || app_id)` for the committed public verification share of `P_i`. A standard approach is a Chaum–Pedersen DLEQ proof showing that the discrete log of `big_y` with respect to `G` equals the discrete log of `(big_c - big_s_claimed)` with respect to `app_pk`, combined with a proof that `big_s_claimed = x_i * H(pk || app_id)` using the participant's public verification share.

Alternatively, the coordinator can verify each contribution against the participant's public verification share `X_i = x_i * G2` (available from the DKG output) by checking `e(big_s_claimed, G2) == e(H(pk || app_id), X_i)` using the BLS12-381 pairing, which is already available in this ciphersuite.

---

### Proof of Concept

**Setup:** 3 participants `{P1, P2, P3}`, threshold 2. `P3` is malicious.

**Step 1:** All participants complete DKG and hold valid shares `x_1, x_2, x_3` with public key `pk`.

**Step 2:** CKD session begins. `P1` is coordinator.

**Step 3:** `P3` overrides `compute_signature_share` and sends `(G1::identity(), G1::identity())` to `P1` instead of the correct `(lambda_3 * y_3 * G, lambda_3 * (x_3 * H + y_3 * app_pk))`.

**Step 4:** Coordinator `P1` accumulates:
```
norm_big_y = lambda_1*y_1*G + lambda_2*y_2*G + 0
norm_big_c = lambda_1*(x_1*H + y_1*app_pk) + lambda_2*(x_2*H + y_2*app_pk) + 0
```

**Step 5:** App unmasks: `norm_big_c - app_sk * norm_big_y = (lambda_1*x_1 + lambda_2*x_2) * H`

**Expected:** `(lambda_1*x_1 + lambda_2*x_2 + lambda_3*x_3) * H = msk * H`

**Actual:** `(msk - lambda_3*x_3) * H` — a wrong key, silently accepted.

The coordinator returns `Ok(Some(ckd_output))` with no error. No honest party detects the corruption. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L35-58)
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
