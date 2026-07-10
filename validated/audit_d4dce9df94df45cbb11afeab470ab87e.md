### Title
Missing `app_pk` Identity-Element Validation in CKD Allows Coordinator to Directly Extract Confidential Derived Key — (`File: src/confidential_key_derivation/protocol.rs`)

### Summary

The `ckd()` function accepts an `app_pk` (`PublicKey = blstrs::G1Projective`) from the caller without validating that it is not the group identity element. When `app_pk` is the identity, the ElGamal masking term `app_pk * y` collapses to the identity, stripping the randomness mask from every participant's share. The coordinator then directly receives the unmasked confidential derived key `msk · H(pk ‖ app_id)` in the clear, defeating the entire confidentiality guarantee of the CKD protocol.

### Finding Description

In `src/confidential_key_derivation/protocol.rs`, the public entry point `ckd()` validates participant counts, duplicates, and membership, but performs **no check** that `app_pk` is a valid, non-identity group element: [1](#0-0) 

The masking computation inside `compute_signature_share` is:

```
big_c = big_s + app_pk * y
```

where `big_s = x_i · H(pk ‖ app_id)` is the participant's BLS signature share and `y` is a fresh random scalar. [2](#0-1) 

When `app_pk = G1::identity()`:

- `app_pk * y = identity * y = identity` (the group identity absorbs any scalar)
- `big_c = big_s + identity = big_s = x_i · H(pk ‖ app_id)`

The coordinator then aggregates all shares: [3](#0-2) 

```
norm_big_c = Σ λ_i · big_c_i = Σ λ_i · x_i · H(pk ‖ app_id) = msk · H(pk ‖ app_id)
```

This is exactly the confidential derived key, returned directly in `CKDOutput::big_c` to the coordinator — with no masking whatsoever.

The `CKDOutput::unmask` method is designed to require the application's secret scalar `a` to recover the key: [4](#0-3) 

With `app_pk = identity`, the coordinator bypasses this requirement entirely and reads `msk · H(pk ‖ app_id)` directly from `big_c`.

### Impact Explanation

**Critical — Extraction/disclosure of a confidential derived secret.**

The CKD protocol's security guarantee is that no MPC node (including the coordinator) learns the derived key `msk · H(pk ‖ app_id)`. Passing `app_pk = G1::identity()` completely breaks this guarantee: the coordinator's `CKDOutputOption` contains the plaintext derived key. This matches the allowed critical impact: *"Extraction, reconstruction, or disclosure of … confidential derived secrets."*

### Likelihood Explanation

The `app_pk` is an externally supplied parameter. Any of the following realistic scenarios triggers the bug:

1. **Misconfigured caller** — an integrator that does not properly initialize `app_pk` (e.g., leaves it as the default zero/identity value of `G1Projective`) before calling `ckd()`.
2. **Malicious application** — a caller that deliberately passes `app_pk = G1::identity()` to extract the derived key without possessing the corresponding secret `a`.
3. **Malicious coordinator** — a coordinator that coerces or replaces the `app_pk` value before invoking `ckd()` on behalf of participants.

No privileged access is required; `ckd()` is a public library function.

### Recommendation

Add an explicit identity-element check for `app_pk` inside `ckd()` before the protocol is started, analogous to the existing identity checks elsewhere in the codebase:

```rust
// In ckd(), after the coordinator membership check:
if app_pk == ElementG1::identity() {
    return Err(InitializationError::BadParameters(
        "app_pk must not be the identity element".to_string(),
    ));
}
```

This mirrors the pattern already used in `src/ecdsa/robust_ecdsa/presign.rs` where the identity element is explicitly rejected: [5](#0-4) 

### Proof of Concept

```rust
// Attacker passes app_pk = G1::identity()
let app_pk = ElementG1::identity(); // zero/uninitialized public key

let protocol = ckd(
    &participants,
    coordinator,
    me,
    key_pair,
    app_id,
    app_pk,   // <-- identity element, no validation rejects this
    rng,
).unwrap(); // succeeds — no check exists

// After running the protocol, the coordinator's output contains:
// ckd_output.big_c == msk * H(pk || app_id)  (unmasked derived key)
// The coordinator reads the confidential derived key directly,
// without needing the application's secret scalar `a`.
```

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

**File:** src/confidential_key_derivation/protocol.rs (L160-181)
```rust
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

**File:** src/confidential_key_derivation/mod.rs (L52-57)
```rust
    /// Takes a secret scalar and returns
    /// s <- C − a ⋅ Y = msk ⋅ H ( `app_id` )
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
}
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L226-232)
```rust
    if big_r
        .value()
        .ct_eq(&<Secp256K1Group as Group>::identity())
        .into()
    {
        return Err(ProtocolError::IdentityElement);
    }
```
