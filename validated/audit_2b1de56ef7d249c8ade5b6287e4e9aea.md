### Title
Missing Identity-Element Validation for `app_pk` Allows Coordinator to Recover Confidential Derived Key — (File: src/confidential_key_derivation/protocol.rs)

---

### Summary

The `ckd()` entry-point in `src/confidential_key_derivation/protocol.rs` validates participant membership and duplicate detection but never checks whether the caller-supplied `app_pk` (the application's ElGamal public key) is the G1 identity element. When `app_pk = G1Projective::identity()`, the per-participant masking term `y_i · A` collapses to the identity, stripping the blinding from every share. The coordinator then receives the unmasked aggregate `msk · H(pk ∥ app_id)` — the confidential derived key — in the clear.

---

### Finding Description

**Root cause — `ckd()` performs no identity check on `app_pk`:** [1](#0-0) 

The function validates participant counts, duplicates, self-membership, and coordinator membership, but `app_pk: PublicKey` (alias for `blstrs::G1Projective`) is forwarded without any check.

**How the masking collapses — `compute_signature_share`:** [2](#0-1) 

Each participant computes:

```
big_c = big_s + app_pk * y
      = x_i · H(pk ∥ app_id) + app_pk · y
```

When `app_pk = G1Projective::identity()`:

```
app_pk * y  =  identity * y  =  identity   (additive identity absorbs scalar mult)
big_c       =  x_i · H(pk ∥ app_id)        (masking term vanishes)
norm_big_c  =  λ_i · x_i · H(pk ∥ app_id)
```

**Coordinator aggregation — `do_ckd_coordinator`:** [3](#0-2) 

The coordinator sums all `norm_big_c` values:

```
C_total = Σ λ_i · x_i · H(pk ∥ app_id)
        = msk · H(pk ∥ app_id)
```

This is exactly the confidential derived key, delivered to the coordinator in plaintext.

**`CKDOutput::unmask` confirms the key is exposed:** [4](#0-3) 

With `app_pk = identity`, the corresponding secret is `a = 0`, so `unmask(0)` returns `C_total − 0·Y_total = C_total = msk · H(pk ∥ app_id)` — the coordinator already holds this value without needing to call `unmask` at all.

**`PublicKey` type alias — no type-level guard exists:** [5](#0-4) 

`PublicKey = ElementG1 = blstrs::G1Projective`. `G1Projective::identity()` is a fully valid Rust value of this type; nothing prevents it from being passed.

---

### Impact Explanation

The entire confidentiality guarantee of the CKD protocol rests on the masking term `y · A`. When `A = identity`, that guarantee is unconditionally broken: the coordinator obtains `msk · H(pk ∥ app_id)` — the confidential derived secret — without possessing the application's secret key `a`. This matches the allowed Critical impact: *disclosure of confidential derived secrets*.

---

### Likelihood Explanation

The `app_pk` parameter is caller-supplied and flows directly into the protocol without sanitisation. A malicious coordinator who controls the channel through which `app_pk` is distributed to participants can substitute `G1Proj

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

**File:** src/confidential_key_derivation/mod.rs (L54-56)
```rust
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```

**File:** src/confidential_key_derivation/mod.rs (L62-63)
```rust
pub type PublicKey = ElementG1;
pub type Signature = ElementG1;
```
