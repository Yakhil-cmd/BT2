### Title
Missing Correctness Verification of Participant CKD Contributions Allows Malicious Participant to Corrupt CKD Output - (File: src/confidential_key_derivation/protocol.rs)

### Summary

In the Confidential Key Derivation (CKD) protocol, the coordinator aggregates cryptographic contributions `(norm_big_y, norm_big_c)` from each participant without any proof of correctness. A malicious participant can send arbitrary group elements, causing the coordinator to output a corrupted `CKDOutput`. This is the direct analog to the GMX slippage bypass: just as GMX sends tokens without checking the slippage constraint when the swap fallback path is taken, the CKD coordinator aggregates participant shares without checking that each share is correctly formed from the participant's actual key material.

### Finding Description

In `do_ckd_coordinator` (`src/confidential_key_derivation/protocol.rs`, lines 50–55), the coordinator receives `(norm_big_y, norm_big_c)` from every participant and blindly adds them into the running aggregate:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

No zero-knowledge proof, commitment, or consistency check is performed on the received values. The protocol specification requires each participant to compute:

- `big_y = y_i · G` (random blinding point)
- `big_s = x_i · H(pk ‖ app_id)` (key-share contribution)
- `big_c = big_s + y_i · app_pk`
- `norm_big_y = λ_i · big_y`, `norm_big_c = λ_i · big_c`

A malicious participant can instead send any arbitrary `(norm_big_y', norm_big_c')` ∈ G1 × G1. Because the coordinator performs no verification, these values are incorporated directly into the final `CKDOutput`.

The root cause is the absence of a proof-of-correct-computation (e.g., a Schnorr-style DLEQ proof or a commitment-then-reveal binding the participant's contribution to their public key share) before the coordinator aggregates the values. [1](#0-0) 

The `compute_signature_share` function that honest participants call is: [2](#0-1) 

There is no corresponding `verify_signature_share` call anywhere in `do_ckd_coordinator`. [3](#0-2) 

### Impact Explanation

**High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

When a malicious participant sends crafted `(norm_big_y', norm_big_c')`, the coordinator's final `CKDOutput` is:

```
Y  = Σ_{honest i} λ_i · y_i · G  +  norm_big_y'
C  = Σ_{honest i} λ_i · (x_i · H + y_i · app_pk)  +  norm_big_c'
```

The client's `unmask(app_sk)` then computes `C − app_sk · Y`, which no longer equals `msk · H(pk ‖ app_id)`. The derived confidential key is silently wrong. The client has no way to detect this without an independent oracle for the correct key. Every downstream operation that depends on the derived key (e.g., decryption, authentication inside a TEE) will fail or produce incorrect results.

### Likelihood Explanation

Any single participant in the CKD session is a sufficient attacker. The attacker needs only to be a legitimate protocol participant (no privileged access required). The malicious message is a valid serialized `CKDOutput` struct containing arbitrary G1 elements — it passes all deserialization checks. The attack is deterministic and requires no cryptographic breaks.

### Recommendation

Each participant must accompany their `(norm_big_y, norm_big_c)` with a DLEQ (Discrete Log Equality) proof demonstrating that:

1. `norm_big_y = λ_i · y_i · G` for the same `y_i` used in `norm_big_c`.
2. `norm_big_c − norm_big_y · (app_pk / G) = λ_i · x_i · H(pk ‖ app_id)`, binding the contribution to the participant's public key share (which is publicly known from DKG).

The coordinator must verify all such proofs before aggregating. Alternatively, a commitment-then-reveal scheme can be used: participants first broadcast a hash commitment to their contribution, then reveal the value and proof, and the coordinator verifies consistency before aggregating.

### Proof of Concept

1. Run a CKD session with participants `[P0, P1, P2]` and coordinator `P0`.
2. Participant `P1` (malicious) sends `norm_big_y' = G1::identity()` and `norm_big_c' = G1::identity()` instead of its honest contribution.
3. The coordinator at line 53–54 adds these identity elements into `norm_big_y` and `norm_big_c` without error.
4. The coordinator outputs `CKDOutput { big_y: Y_corrupted, big_c: C_corrupted }`.
5. The client calls `ckd_output.unmask(app_sk)` and obtains a value that differs from `msk · H(pk ‖ app_id)`.
6. Any TEE or application relying on the derived key receives a silently wrong key with no error signal. [4](#0-3) [5](#0-4)

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

**File:** src/confidential_key_derivation/mod.rs (L52-56)
```rust
    /// Takes a secret scalar and returns
    /// s <- C − a ⋅ Y = msk ⋅ H ( `app_id` )
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```
