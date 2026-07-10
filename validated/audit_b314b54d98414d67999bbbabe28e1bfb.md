### Title
Unvalidated Caller-Supplied `app_pk` in CKD Protocol Allows Confidential Derived Key Disclosure - (`File: src/confidential_key_derivation/protocol.rs`)

### Summary
The `ckd()` function accepts a caller-supplied ElGamal public key `app_pk` with no validation. Supplying the G1 identity point as `app_pk` causes the ElGamal encryption layer to collapse, exposing the confidential derived key `msk · H(pk, app_id)` in plaintext inside `CKDOutput.big_c`.

### Finding Description

The CKD protocol is designed so that each node computes:

```
C_i = S_i + y_i · A
```

where `A = app_pk` is the caller-supplied ElGamal public key, `S_i = x_i · H(pk, app_id)` is the node's BLS signature share, and `y_i` is a fresh random blinding scalar. The coordinator aggregates to produce:

```
C = msk · H(pk, app_id) + a · Y
```

The confidentiality of the derived key depends entirely on `a` (the discrete log of `A`) being known only to the legitimate app. The `unmask` operation recovers the secret as `C − a · Y`.

However, `ckd()` performs no validation on `app_pk`:

```rust
pub fn ckd(
    participants: &[Participant],
    coordinator: Participant,
    me: Participant,
    key_pair: KeygenOutput,
    app_id: impl Into<AppId>,
    app_pk: PublicKey,          // ← no validation whatsoever
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = CKDOutputOption>, InitializationError> {
    // only checks: participant count, duplicates, membership
    ...
}
```

And `compute_signature_share` uses `app_pk` directly in the encryption step:

```rust
// C <- S + y . A
let big_c = big_s + app_pk * y.0;   // ← app_pk is used without any check
```

**Attack:** A malicious caller supplies `app_pk = G1::identity()` (the additive identity of G1). Then for every node `i`:

```
C_i = S_i + y_i · identity = S_i + identity = S_i = x_i · H(pk, app_id)
```

After Lagrange aggregation by the coordinator:

```
C = Σ λ_i · C_i = Σ λ_i · x_i · H(pk, app_id) = msk · H(pk, app_id)
```

The `CKDOutput.big_c` field now contains the raw BLS signature `msk · H(pk, app_id)` — the confidential derived key — in plaintext. This value is returned on-chain and visible to all observers. The blinding term `a · Y` is entirely absent because `y_i · identity = identity` for all `i`.

The `verify_signature` function in `ciphersuite.rs` does check for identity, but it is only called by the app after receiving the output — it is not called inside `ckd()` or `compute_signature_share`.

### Impact Explanation

The confidential derived key `msk · H(pk, app_id)` — the secret `s` that the CKD protocol is designed to protect — is disclosed in plaintext in `CKDOutput.big_c`. This maps directly to:

> **Critical: Extraction, reconstruction, or disclosure of … confidential derived secrets**

The secret is exposed to anyone who can observe the on-chain `CKDOutput`, including the malicious caller, blockchain observers, and the coordinator itself.

### Likelihood Explanation

The `app_pk` parameter is a caller-supplied `blstrs::G1Projective` value. The identity element is a valid, constructible value (`G1Projective::identity()` or `G1Projective::generator() * Scalar::ZERO`). The library imposes no constraint on this parameter. Any caller who can invoke `ckd()` — including a malicious app or a compromised developer contract — can trigger this with a single crafted call. No cryptographic break, leaked key, or trusted-party compromise is required.

### Recommendation

Validate `app_pk` at the entry point of `ckd()` before the protocol begins. Reject the identity element and optionally verify the point is in the correct prime-order subgroup:

```rust
use blstrs::G1Affine;

pub fn ckd(
    ...
    app_pk: PublicKey,
    ...
) -> Result<impl Protocol<Output = CKDOutputOption>, InitializationError> {
    // Validate app_pk: must not be the identity and must be on the curve / in the subgroup
    let app_pk_affine: G1Affine = app_pk.into();
    if app_pk_affine.is_identity().into()
        || !app_pk_affine.is_on_curve().into()
        || !app_pk_affine.is_torsion_free().into()
    {
        return Err(InitializationError::BadParameters(
            "app_pk must be a valid non-identity G1 point".to_string(),
        ));
    }
    ...
}
```

This mirrors the validation already present in `verify_signature` in `ciphersuite.rs` and should be applied defensively at the protocol entry point.

### Proof of Concept

The following pseudocode demonstrates the attack:

```rust
// Attacker supplies the G1 identity as app_pk
let malicious_app_pk = G1Projective::identity(); // additive identity

let protocol = ckd(
    &participants,
    coordinator,
    me,
    key_pair,
    app_id.clone(),
    malicious_app_pk,   // ← identity point
    rng,
).unwrap();

// After running the protocol, the coordinator's CKDOutput contains:
//   big_c = msk · H(pk, app_id)   ← confidential derived key in plaintext
//   big_y = Σ λ_i · y_i · G       ← random, irrelevant
//
// The attacker reads big_c directly from the on-chain response.
// No private key 'a' is needed to unmask — the secret is already unmasked.
```

The root cause is in `compute_signature_share` at line 174:

```rust
let big_c = big_s + app_pk * y.0;
```

When `app_pk = identity`, `app_pk * y.0 = identity`, so `big_c = big_s = x_i · H(pk, app_id)`, and the aggregated `C` equals `msk · H(pk, app_id)` — the confidential derived key — with no encryption applied. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

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

**File:** src/confidential_key_derivation/mod.rs (L52-56)
```rust
    /// Takes a secret scalar and returns
    /// s <- C − a ⋅ Y = msk ⋅ H ( `app_id` )
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```

**File:** src/confidential_key_derivation/ciphersuite.rs (L216-244)
```rust
/// BLS signature verification
/// following the standard in <https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-coreverify>
pub fn verify_signature(
    verifying_key: &VerifyingKey,
    msg: &[u8],
    signature: &Signature,
) -> Result<(), frost_core::Error<BLS12381SHA256>> {
    let element1: G1Affine = signature.into();
    if (!element1.is_on_curve() | !element1.is_torsion_free() | element1.is_identity()).into() {
        return Err(frost_core::Error::InvalidSignature);
    }
    let element2: G2Affine = verifying_key.to_element().into();
    if (!element2.is_on_curve() | !element2.is_torsion_free() | element2.is_identity()).into() {
        return Err(frost_core::Error::MalformedVerifyingKey);
    }

    // Concatenate the master public key (96 bytes) in the hash computation
    // H(pk || app_id) when H is a random oracle
    let base1 = hash_app_id_with_pk(verifying_key, msg).into();
    let base2 =
        <<BLS12381SHA256 as frost_core::Ciphersuite>::Group as frost_core::Group>::generator()
            .into();

    if blstrs::pairing(&base1, &element2).eq(&blstrs::pairing(&element1, &base2)) {
        Ok(())
    } else {
        Err(frost_core::Error::InvalidSignature)
    }
}
```
