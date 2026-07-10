### Title
Missing Zero-Check on Ephemeral Scalar `y` Allows Participant to Expose Secret Share Contribution to Coordinator — (`src/confidential_key_derivation/protocol.rs`)

---

### Summary

In `compute_signature_share`, the ephemeral blinding scalar `y` is sampled from a caller-supplied RNG with no subsequent non-zero check. A malicious participant can supply an RNG that returns all-zero bytes, causing `y = 0`. With `y = 0`, the blinding term `y * app_pk` vanishes and the participant's `norm_big_c` sent to the coordinator equals `λ_i * x_i * H(pk ‖ app_id)` in the clear — the exact secret share contribution the protocol is designed to hide.

---

### Finding Description

`compute_signature_share` in `src/confidential_key_derivation/protocol.rs` samples the ephemeral scalar at line 160:

```rust
let y = Scalar::random(rng);
```

`Scalar` is `blstrs::Scalar` (defined in `mod.rs` line 24). `Scalar::random` simply reduces the RNG output modulo the field order; if the RNG returns all zeros, `y = 0` with no error or retry.

The public entry point `ckd()` accepts the RNG as a fully caller-controlled parameter:

```rust
pub fn ckd(
    ...
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = CKDOutputOption>, InitializationError>
``` [1](#0-0) 

With `y = 0`, the computation at lines 165–180 degenerates:

```
big_y  = G * 0          = G1::identity()
big_c  = x_i*H(pk‖id) + app_pk*0  = x_i * H(pk‖app_id)
norm_big_y = identity * λ_i = identity
norm_big_c = λ_i * x_i * H(pk‖app_id)   ← secret share, unblinded
``` [2](#0-1) 

The coordinator in `do_ckd_coordinator` performs no validation on the received `(norm_big_y, norm_big_c)` — it blindly accumulates them:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [3](#0-2) 

There is no:
- check that `y != 0` or `big_y != G1::identity()` after sampling,
- zero-knowledge proof of knowledge of `y` binding `big_y` to `big_c`,
- identity-point rejection on received `norm_big_y`. [4](#0-3) 

---

### Impact Explanation

The coordinator receives `norm_big_c = λ_i * x_i * H(pk ‖ app_id)` directly. Since `λ_i` is a public Lagrange coefficient (computable from the participant list) and `H(pk ‖ app_id)` is a deterministic hash, the coordinator can isolate `x_i * H(pk ‖ app_id)` — participant `i`'s secret share contribution to the CKD output — by multiplying by `λ_i^{-1}`. This is a **Critical** disclosure: it reveals the participant's BLS secret share contribution, which the CKD protocol is specifically designed to keep hidden from the coordinator. It also breaks the app_id confidentiality guarantee: across multiple CKD calls, the coordinator can correlate the leaked group elements to identify when the same `app_id` is reused.

---

### Likelihood Explanation

The attack requires only that a participant supply a custom `CryptoRngCore` implementation that returns zero bytes. This is trivially achievable by any participant who controls their own process. The precondition (being a valid member of the participant list) is the only gate, and it is satisfied by construction. No cryptographic assumption needs to be broken.

---

### Recommendation

1. **Reject zero `y`**: After sampling, check `y.is_zero()` and either return an error or resample:
   ```rust
   let y = loop {
       let candidate = Scalar::random(rng);
       if !bool::from(candidate.is_zero()) { break candidate; }
   };
   ```
2. **Require a ZK proof of knowledge of `y`**: The participant should send a Schnorr proof `(norm_big_y, π)` proving knowledge of the discrete log of `norm_big_y` with respect to `G`, binding it to `norm_big_c`. The coordinator must verify this proof before accepting the contribution.
3. **Reject identity points**: The coordinator should reject any received `norm_big_y` that is the group identity.

---

### Proof of Concept

```rust
use rand_core::{CryptoRng, RngCore};

struct ZeroRng;
impl RngCore for ZeroRng {
    fn next_u32(&mut self) -> u32 { 0 }
    fn next_u64(&mut self) -> u64 { 0 }
    fn fill_bytes(&mut self, dest: &mut [u8]) { dest.fill(0); }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        dest.fill(0); Ok(())
    }
}
impl CryptoRng for ZeroRng {}

// Malicious participant calls ckd() with ZeroRng.
// Their norm_big_c sent to coordinator equals λ_i * x_i * H(pk ‖ app_id).
// Coordinator receives it unblinded; assert norm_big_c == lambda_i * x_i * hash_point.
```

The coordinator can then compute `x_i * H(pk ‖ app_id) = norm_big_c * λ_i^{-1}`, confirming the secret share contribution is fully exposed.

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

**File:** src/confidential_key_derivation/protocol.rs (L155-182)
```rust
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
