### Title
Malicious Participant Can Silently Corrupt CKD Output via Unvalidated `public_key` in `key_pair` — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The `ckd()` function accepts a `key_pair: KeygenOutput` from each participant without validating that `key_pair.public_key` matches the agreed-upon master public key established during DKG. A malicious participant can supply a wrong `public_key`, causing their ElGamal contribution to be computed over a different hash point, silently corrupting the coordinator's aggregated `CKDOutput` with no error or detectable signal.

---

### Finding Description

In `src/confidential_key_derivation/protocol.rs`, the public entry point `ckd()` accepts `key_pair: KeygenOutput` from each participant. [1](#0-0) 

The function validates the participant list, coordinator membership, and duplicate participants, but performs **no validation** on `key_pair.public_key`. The `public_key` field is then consumed inside `compute_signature_share`: [2](#0-1) 

Specifically, `key_pair.public_key` is used to compute the hash base point:

```rust
let hash_point = hash_app_id_with_pk(&key_pair.public_key, app_id);
let big_s = hash_point * private_share.to_scalar();
let big_c = big_s + app_pk * y.0;
``` [3](#0-2) 

If a malicious participant substitutes `public_key = PK'` (any value other than the true master public key `PK`), they compute `H(PK' || app_id)` instead of `H(PK || app_id)`, producing a wrong `big_s` and `big_c`. The coordinator then blindly aggregates all contributions with no cross-participant consistency check:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [4](#0-3) 

There is no zero-knowledge proof, commitment scheme, or broadcast-and-compare step on `key_pair.public_key`. The analog to H-02 is exact: just as `slashStore` was accepted without being checked against `assetSlashingHandlers[ETH]`, `key_pair.public_key` is accepted without being checked against the canonical master public key that all participants agreed on during DKG.

The `hash_app_id_with_pk` function that consumes this unvalidated field: [5](#0-4) 

---

### Impact Explanation

The coordinator returns a `CKDOutput` whose `big_c` is offset by `λ_M · (H(PK'||app_id) − H(PK||app_id)) · x_M`, where `λ_M` is the malicious participant's Lagrange coefficient and `x_M` is their private share. When the application calls `unmask(app_sk)`:

```rust
pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
    self.big_c - self.big_y * secret_scalar
}
``` [6](#0-5) 

it receives a wrong confidential derived key with no error, no panic, and no indication of corruption. This matches **High: Corruption of CKD outputs so honest parties accept unusable cryptographic outputs**.

---

### Likelihood Explanation

Any participant holding a valid `private_share` from DKG can deliberately pass a wrong `public_key` in their `key_pair`. The CKD protocol requires **all** participants to contribute (there is no threshold-based exclusion of a minority); a single malicious participant is sufficient to corrupt the output. No special privileges beyond participation in the CKD session are required.

---

### Recommendation

Add a cross-participant consistency check on `key_pair.public_key`. Two concrete options:

1. **Broadcast-and-compare:** At the start of `

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

**File:** src/confidential_key_derivation/mod.rs (L67-71)
```rust
pub fn hash_app_id_with_pk(pk: &VerifyingKey, app_id: &[u8]) -> ElementG1 {
    let compressed_pk = pk.to_element().to_compressed();
    let input = [compressed_pk.as_slice(), app_id].concat();
    ciphersuite::hash_to_curve(&input)
}
```
