### Title
Malicious Participant Can Corrupt CKD Output via Zero `private_share` — (`src/confidential_key_derivation/protocol.rs`)

---

### Summary

The `ckd()` public API accepts a caller-supplied `KeygenOutput` with no validation that `private_share` is non-zero. A malicious participant can pass `SigningShare::new(Scalar::ZERO)`, causing their contribution to carry zero secret material. The coordinator blindly aggregates all contributions, producing a `CKDOutput` that unmasks to a value different from `msk * H(pk || app_id)`. Honest parties accept this silently corrupted output.

---

### Finding Description

In `compute_signature_share`, the participant's secret share is used directly with no non-zero guard:

```rust
// S <- x . H(app_id)
let big_s = hash_point * private_share.to_scalar();  // = identity if share = 0
// C <- S + y . A
let big_c = big_s + app_pk * y.0;                    // = app_pk * y only
``` [1](#0-0) 

If `private_share = Scalar::ZERO`, then `big_s = G1::identity()` and `norm_big_c = lambda_i * app_pk * y_i` — the participant's secret share contributes nothing to the derived key.

The coordinator aggregates without any proof-of-correctness check:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
``` [2](#0-1) 

The resulting `CKDOutput` unmasks to `sum_{j≠i} lambda_j * x_j * H(pk||app_id)` instead of `msk * H(pk||app_id)`, silently producing a wrong derived key.

**Contrast with DKG**, which explicitly rejects zero shares:

```rust
if is_zero_secret {
    return Err(ProtocolError::AssertionFailed(format!(
        "{me:?} is running DKG with a zero share"
    )));
}
``` [3](#0-2) 

No equivalent guard exists anywhere in the CKD path.

---

### Impact Explanation

**Actual impact: High** — not Critical as claimed in the question.

The corrupted `CKDOutput` is accepted by the coordinator as valid. The `unmask()` result is a wrong group element, not `msk * H(pk || app_id)`. Any downstream use of the derived key (e.g., TEE application key derivation) silently fails or produces an attacker-influenced value.

The claimed Critical sub-impact — "reconstruction with fewer than threshold honest participants" — is **not supported**. A zero share does not reduce the threshold needed to reconstruct `msk`; it only corrupts the CKD output. The attacker gains no ability to reconstruct the master secret key. [4](#0-3) 

---

### Likelihood Explanation

Any participant in the CKD protocol can trivially trigger this. `KeygenOutput` is a public struct with public fields; constructing one with `private_share = SigningShare::new(Scalar::ZERO)` requires no special access. The `ckd()` function performs no share validation before use. [5](#0-4) 

---

### Recommendation

Add a non-zero check on `private_share` at the start of `compute_signature_share` (or in `ckd()` before the protocol runs), mirroring the existing guard in `assert_keyshare_inputs` in `dkg.rs`:

```rust
if private_share.to_scalar() == Scalar::ZERO {
    return Err(ProtocolError::AssertionFailed(
        "private_share must not be zero in CKD".to_string(),
    ));
}
```

Additionally, consider adding a ZK proof of correct share usage (a Schnorr-style proof that `norm_big_c` is consistent with the participant's public key share) so the coordinator can reject malformed contributions even when the share is non-zero but incorrect.

---

### Proof of Concept

```rust
// Participant 0 uses zero share; participants 1 and 2 use correct shares.
// After running ckd(), ckd_output.unmask(app_sk) != msk * H(pk || app_id).
let zero_key_pair = KeygenOutput {
    private_share: SigningShare::new(Scalar::ZERO),
    public_key: pk,  // correct aggregate public key
};
// Pass zero_key_pair for participant 0, correct key_pairs for others.
// Assert: ckd_output.unmask(app_sk) != hash_app_id_with_pk(&pk, &app_id) * msk
``` [6](#0-5)

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

**File:** src/confidential_key_derivation/protocol.rs (L66-74)
```rust
pub fn ckd(
    participants: &[Participant],
    coordinator: Participant,
    me: Participant,
    key_pair: KeygenOutput,
    app_id: impl Into<AppId>,
    app_pk: PublicKey,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = CKDOutputOption>, InitializationError> {
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

**File:** src/dkg.rs (L48-52)
```rust
        if is_zero_secret {
            return Err(ProtocolError::AssertionFailed(format!(
                "{me:?} is running DKG with a zero share"
            )));
        }
```

**File:** src/confidential_key_derivation/mod.rs (L54-56)
```rust
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```
