### Title
Unvalidated `app_pk` Identity-Point Bypass Exposes Confidential Derived Key in CKD Protocol - (File: src/confidential_key_derivation/protocol.rs)

---

### Summary

The `ckd()` function accepts a caller-controlled `app_pk: PublicKey` (an `ElementG1` point) with no validation that it is a non-identity (non-zero) group element. When `app_pk` is the G1 identity element, the ElGamal encryption layer collapses entirely: each participant's ciphertext component `big_c` reduces to the raw secret contribution `big_s = x_i * H(pk || app_id)`, and the coordinator's aggregated output `CKDOutput.big_c` equals `msk * H(pk || app_id)` — the confidential derived key — in plaintext. Any party that controls the `app_pk` input can extract the derived secret without possessing `app_sk`.

---

### Finding Description

In `src/confidential_key_derivation/protocol.rs`, the public entry point `ckd()` (lines 66–117) validates participant membership and deduplication but performs **no check** on `app_pk`:

```rust
pub fn ckd(
    participants: &[Participant],
    coordinator: Participant,
    me: Participant,
    key_pair: KeygenOutput,
    app_id: impl Into<AppId>,
    app_pk: PublicKey,          // ← no validation
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = CKDOutputOption>, InitializationError>
```

The cryptographic computation in `compute_signature_share()` (lines 148–182) is:

```rust
let big_s = hash_point * private_share.to_scalar();  // x_i * H(pk||app_id)
let big_c = big_s + app_pk * y.0;                    // ElGamal ciphertext
```

When `app_pk = G1Projective::identity()`:

- `app_pk * y.0 = identity` (the zero element)
- `big_c = big_s = x_i * H(pk || app_id)`

After Lagrange normalization and coordinator aggregation (lines 44–57):

```rust
norm_big_c += participant_output.big_c();
```

The final `CKDOutput.big_c = Σ λ_i · x_i · H(pk||app_id) = msk · H(pk||app_id)` — the confidential derived key — is directly present in the output struct, unencrypted.

The `unmask` function in `src/confidential_key_derivation/mod.rs` (line 54):

```rust
pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
    self.big_c - self.big_y * secret_scalar
}
```

Calling `unmask(Scalar::ZERO)` returns `big_c` directly, yielding `msk * H(pk || app_id)` without any knowledge of a legitimate `app_sk`.

---

### Impact Explanation

The CKD protocol's security guarantee is that the confidential derived key `msk * H(pk || app_id)` is produced only in ElGamal-encrypted form, so MPC nodes (including the coordinator) never learn it in plaintext. When `app_pk` is the identity element, this guarantee is completely broken:

1. The coordinator, which aggregates all shares, directly observes `CKDOutput.big_c = msk * H(pk || app_id)` in plaintext.
2. Any caller who receives the `CKDOutput` can call `unmask(Scalar::ZERO)` to extract the derived secret.

This matches the allowed impact: **Critical — Extraction or disclosure of confidential derived secrets**.

---

### Likelihood Explanation

The `app_pk` parameter is fully caller-controlled with no type-level or runtime constraint preventing the identity element. A malicious library caller (e.g., a compromised application node, a malicious integrator, or a participant running a crafted client) can trivially pass `ElementG1::identity()` (the zero point in blstrs `G1Projective`). No privileged access, leaked keys, or cryptographic breaks are required — only the ability to call the public `ckd()` API with an attacker-chosen `app_pk`.

---

### Recommendation

Add an explicit check in `ckd()` that `app_pk` is not the identity element before the protocol proceeds:

```rust
if app_pk.is_identity().into() {
    return Err(InitializationError::BadParameters(
        "app_pk must not be the identity element".to_string(),
    ));
}
```

This mirrors the pattern already used elsewhere in the codebase (e.g., `msg_hash.is_zero()` check in `src/ecdsa/robust_ecdsa/sign.rs` lines 91–95) to reject degenerate inputs that break cryptographic security properties.

---

### Proof of Concept

1. Caller invokes `ckd()` with `app_pk = blstrs::G1Projective::identity()`.
2. Each participant's `compute_signature_share()` computes `big_c = big_s + identity * y = big_s = x_i * H(pk || app_id)`.
3. Coordinator aggregates: `CKDOutput.big_c = Σ λ_i · x_i · H(pk||app_id) = msk · H(pk||app_id)`.
4. Caller calls `ckd_output.unmask(Scalar::ZERO)` → returns `big_c` directly = `msk * H(pk || app_id)`.
5. The confidential derived key is extracted with zero knowledge of `app_sk`.

**Relevant code locations:**

- `ckd()` entry point with missing `app_pk` validation: [1](#0-0) 
- `compute_signature_share()` where `big_c = big_s + app_pk * y` collapses when `app_pk = identity`: [2](#0-1) 
- `unmask()` which returns `big_c` directly when called with `Scalar::ZERO`: [3](#0-2) 
- Analogous degenerate-input guard already present in robust ECDSA sign (pattern to follow): [4](#0-3)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L66-117)
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

    let comms = Comms::new();
    let chan = comms.shared_channel();

    let fut = run_ckd_protocol(
        chan,
        coordinator,
        me,
        participants,
        key_pair,
        app_id.into(),
        app_pk,
        rng,
    );
    Ok(make_protocol(comms, fut))
}
```

**File:** src/confidential_key_derivation/protocol.rs (L172-175)
```rust

    // C <- S + y . A
    let big_c = big_s + app_pk * y.0;

```

**File:** src/confidential_key_derivation/mod.rs (L54-56)
```rust
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```

**File:** src/ecdsa/robust_ecdsa/sign.rs (L91-95)
```rust
    if bool::from(msg_hash.is_zero()) {
        return Err(InitializationError::BadParameters(
            "msg_hash cannot be 0 to avoid potential split view attacks".to_string(),
        ));
    }
```
