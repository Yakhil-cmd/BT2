### Title
Malicious Participant Can Corrupt CKD Output Without Detection — (`src/confidential_key_derivation/protocol.rs`)

### Summary
In `do_ckd_coordinator`, the coordinator aggregates each participant's `(norm_big_y, norm_big_c)` contributions by direct addition with no cryptographic verification. A single malicious participant can submit arbitrary group elements, causing the coordinator to output a corrupted confidential key that honest parties will silently accept as valid.

### Finding Description

In `do_ckd_coordinator`, the coordinator collects and sums every participant's share:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
Ok(Some(ckd_output))
``` [1](#0-0) 

The correct per-participant computation (in `compute_signature_share`) is:

- `norm_big_y_i = λ_i · y_i · G₁`
- `norm_big_c_i = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)`

where `x_i` is the participant's secret signing share and `y_i` is a fresh random nonce. [2](#0-1) 

There is **no validation** that:
1. The received `big_y` is consistent with any known public commitment to `y_i`.
2. The received `big_c` was formed using the participant's actual secret share `x_i` (whose public counterpart `X_i = x_i · G₂` is known from the keygen output).
3. The two components are internally consistent (i.e., that the same `y_i` was used in both).

No zero-knowledge proof, commitment, or consistency check is performed before the values are folded into the aggregate. This is structurally identical to the external report's pattern: an intermediate output from an untrusted step is consumed unconditionally, with no check that it was produced correctly.

### Impact Explanation

The coordinator outputs `(big_Y, big_C)` and the client calls `unmask(app_sk)` to recover the confidential key:

```rust
pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
    self.big_c - self.big_y * secret_scalar
}
``` [3](#0-2) 

If any participant injects a malicious `(big_y', big_c')`, the aggregated `big_C - app_sk · big_Y` will not equal `msk · H(pk ‖ app_id)`. The client receives a wrong derived key with no indication of failure. There is no final verification step analogous to the signature check in `do_sign_coordinator`. [4](#0-3) 

This matches the allowed impact: **High — Corruption of CKD outputs so honest parties accept an incorrect derived key**.

### Likelihood Explanation

Any single participant in the `participants` list can trigger this. The attacker only needs to send a malformed `CKDOutput` message during the single-round protocol. No special privilege, leaked key, or external assumption is required — the attack is reachable by any unprivileged protocol participant.

### Recommendation

Add a zero-knowledge proof of correct share formation. Each participant should prove, alongside `(norm_big_y, norm_big_c)`, that:
- `norm_big_y = λ_i · y_i · G₁` for some `y_i`
- `norm_big_c = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)` using the same `y_i` and the participant's committed secret share `x_i`

This can be realized as a standard Schnorr-style DLEQ proof over the BLS12-381 G₁ curve, binding `norm_big_y`, `norm_big_c`, and the participant's public key share `X_i = x_i · G₂` (available from the keygen output). The coordinator must verify all proofs before aggregating.

### Proof of Concept

1. All `n` participants begin the CKD protocol for `(app_id, app_pk)`.
2. Malicious participant `P_m` intercepts the send step and instead of the correct `(norm_big_y_m, norm_big_c_m)` sends `(G₁, G₁)` (the generator point for both fields).
3. The coordinator receives all contributions and sums them:
   - `big_Y = Σ_{i≠m} norm_big_y_i + G₁`
   - `big_C = Σ_{i≠m} norm_big_c_i + G₁`
4. The coordinator returns `CKDOutput { big_y: big_Y, big_c: big_C }` with no error.
5. The client calls `ckd_output.unmask(app_sk)` and obtains `big_C - app_sk · big_Y`, which is not equal to `msk · H(pk ‖ app_id)`.
6. The client silently accepts the corrupted key — there is no verification path that would detect the deviation. [5](#0-4)

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

**File:** src/confidential_key_derivation/mod.rs (L54-56)
```rust
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```

**File:** src/ecdsa/robust_ecdsa/sign.rs (L159-163)
```rust
    if !sig.verify(&public_key, &msg_hash) {
        return Err(ProtocolError::AssertionFailed(
            "signature failed to verify".to_string(),
        ));
    }
```
