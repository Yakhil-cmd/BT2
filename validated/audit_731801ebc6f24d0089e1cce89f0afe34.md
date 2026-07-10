### Title
Malicious CKD Participant Can Corrupt Derived Key Output Without Detection — (`src/confidential_key_derivation/protocol.rs`)

---

### Summary

The CKD coordinator blindly sums `(norm_big_y, norm_big_c)` values received from participants with no proof of correct computation. A single malicious participant can substitute arbitrary group elements, causing the coordinator to output a silently corrupted confidential derived key. This is the direct analog of the LP pricing manipulation: just as the LP formula consumed unverified spot-price data that an attacker could inflate, the CKD aggregation consumes unverified participant shares that a malicious party can freely craft.

---

### Finding Description

In `do_ckd_coordinator`, the coordinator collects each participant's `CKDOutput` and accumulates it unconditionally:

```rust
// src/confidential_key_derivation/protocol.rs, lines 50–55
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
``` [1](#0-0) 

The protocol specification requires each participant `i` to send:

- `norm_big_y_i = λ_i · y_i · G`
- `norm_big_c_i = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)`

where `y_i` is a fresh random scalar and `x_i` is the participant's private share. The coordinator has no way to verify either component because `y_i` is secret and there is no accompanying zero-knowledge proof or commitment. [2](#0-1) 

The `unmask` function recovers the derived key as `big_C − app_sk · big_Y`:

```rust
// src/confidential_key_derivation/mod.rs, line 54–56
pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
    self.big_c - self.big_y * secret_scalar
}
``` [3](#0-2) 

If malicious participant `i` sends `norm_big_y_i' = 0` and `norm_big_c_i' = δ · H(pk ‖ app_id)` for any chosen scalar `δ`, the unmasked result becomes:

```
(msk − λ_i · x_i + δ) · H(pk ‖ app_id)
```

instead of the correct `msk · H(pk ‖ app_id)`. Because the malicious participant knows their own Lagrange-weighted share `λ_i · x_i`, they can choose `δ` to shift the derived key by any desired additive offset in the exponent, producing a deterministically wrong but internally consistent-looking `CKDOutput`. The coordinator performs no final correctness check on the aggregated result.

Contrast this with both ECDSA signing paths, which do perform a final `sig.verify(...)` check that catches malicious share contributions: [4](#0-3) [5](#0-4) 

No equivalent guard exists in the CKD coordinator path.

---

### Impact Explanation

**High — Corruption of CKD output so honest parties accept an unusable or wrong derived key.**

The coordinator outputs a `CKDOutput` that is structurally valid (two non-identity G1 points) but encodes a derived key that differs from `msk · H(pk ‖ app_id)`. Any downstream consumer that calls `unmask` will silently obtain the wrong confidential key with no indication of failure. Because the corruption is additive in the exponent and the malicious participant controls the offset, the attack is deterministic and repeatable, not merely a random fault.

---

### Likelihood Explanation

Any single participant in a CKD session is a sufficient attacker. The participant list is caller-supplied and the protocol makes no assumption that all participants are honest. The attack requires only that the malicious participant substitute two group elements in a single protocol message — no cryptographic capability, no colluding parties, and no special network position are needed. [6](#0-5) 

---

### Recommendation

Require each participant to accompany their `(norm_big_y, norm_big_c)` with a non-interactive zero-knowledge proof of correct formation — specifically a proof that `norm_big_c` is a correctly scaled ElGamal ciphertext relative to the participant's committed public share `λ_i · x_i · G2` (already available from the DKG output). A Chaum–Pedersen-style DLEQ proof over the pair `(norm_big_y, norm_big_c − λ_i · x_i · H(pk ‖ app_id))` would suffice: it proves knowledge of `λ_i · y_i` such that `norm_big_y = (λ_i · y_i) · G` and `norm_big_c − λ_i · x_i · H(pk ‖ app_id) = (λ_i · y_i) · app_pk`, without revealing `y_i`. The coordinator must verify all proofs before accumulating any share.

---

### Proof of Concept

**Setup:** 3 participants, threshold 2. Participant 3 is malicious.

1. DKG completes normally. Each participant holds `x_i` and the group holds `msk = Σ λ_i · x_i`.
2. CKD is initiated for `app_id = "target_app"`. Participants 1 and 2 compute and send correct `(norm_big_y_i, norm_big_c_i)`.
3. Malicious participant 3 computes `λ_3 · x_3` (their own share, known to them). They choose `δ = 42` (arbitrary scalar). They send:
   - `norm_big_y_3' = G1::identity()` (zero element)
   - `norm_big_c_3' = 42 · H(pk ‖ app_id)` (instead of the correct value)
4. The coordinator accumulates all three contributions without verification and outputs `CKDOutput { big_y, big_c }`.
5. The application calls `ckd_output.unmask(app_sk)` and obtains `(msk − λ_3 · x_3 + 42) · H(pk ‖ app_id)` — a wrong key — with no error returned.
6. Any operation using this derived key (e.g., decryption, re-encryption) silently fails or produces attacker-influenced output. [7](#0-6)

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

**File:** src/confidential_key_derivation/protocol.rs (L66-101)
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
    // not enough participants
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }

    // kick out duplicates
    let Some(participants) = ParticipantList::new(participants) else {
        return Err(InitializationError::DuplicateParticipants);
    };

    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }

    // ensure the coordinator is a participant
    if !participants.contains(coordinator) {
        return Err(InitializationError::MissingParticipant {
            role: "coordinator",
            participant: coordinator,
        });
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

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L129-133)
```rust
    if !sig.verify(&public_key, &msg_hash) {
        return Err(ProtocolError::AssertionFailed(
            "signature failed to verify".to_string(),
        ));
    }
```
