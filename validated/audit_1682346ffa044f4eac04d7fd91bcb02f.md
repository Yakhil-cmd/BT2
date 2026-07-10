### Title
Missing `app_pk` Identity/Subgroup Validation in `ckd()` Collapses ElGamal Blinding, Exposing Confidential Derived Key to Coordinator — (`src/confidential_key_derivation/protocol.rs`)

---

### Summary

`ckd()` accepts `app_pk: PublicKey` (`blstrs::G1Projective`) with no validation. A malicious coordinator/participant can pass `G1Projective::identity()` as `app_pk`, which collapses the ElGamal blinding term `y * app_pk` to the group identity, causing `big_c` to equal `msk * H(pk||app_id)` in the clear. The coordinator receives this unblinded value directly in `CKDOutput`, breaking the core privacy guarantee of the CKD protocol.

---

### Finding Description

`compute_signature_share` computes the blinded share as:

```
big_c = big_s + app_pk * y   // line 174
```

where `big_s = x_i * H(pk||app_id)` and `y` is a fresh random scalar. The blinding relies entirely on `app_pk` being a non-degenerate point in the prime-order subgroup. [1](#0-0) 

`ckd()` performs no validation on `app_pk` — no identity check, no `is_torsion_free()` check, no subgroup membership check. [2](#0-1) 

By contrast, `verify_signature` in the same module explicitly guards against both conditions on every G1 element it processes:

```rust
if (!element1.is_on_curve() | !element1.is_torsion_free() | element1.is_identity()).into() {
    return Err(frost_core::Error::InvalidSignature);
}
``` [3](#0-2) 

This confirms the `blstrs::G1Projective` type can represent points outside the prime-order subgroup, and the library authors are aware of the need to check — but the check is absent from `ckd()`.

**Identity attack (concrete, zero-effort):**

If `app_pk = G1Projective::identity()`:
- `y * identity = identity` for any scalar `y`
- `big_c = big_s + identity = big_s = x_i * H(pk||app_id)`
- After Lagrange aggregation across all participants: `big_C = msk * H(pk||app_id)` — completely unblinded
- `big_Y = y_total * G` is irrelevant; the coordinator reads `big_C` directly from `CKDOutput` [4](#0-3) [5](#0-4) 

**Small-subgroup attack (requires non-identity low-order point):**

`blstrs` exposes `G1Affine::from_uncompressed_unchecked()` (a safe, non-`unsafe` function) which skips the torsion check. If the BLS12-381 G1 cofactor `h = 0x396c8c005555e1568c00aaab0000aaab` has small prime factors, a caller can construct a point of small order `d | h`, causing `y * app_pk` to cycle through only `d` values. Across `d` CKD invocations with the same `(pk, app_id)`, the attacker can cancel the blinding and recover `msk * H(pk||app_id)`. The identity attack is sufficient on its own and requires no factoring.

---

### Impact Explanation

The CKD protocol's stated purpose is to allow a client to derive `msk * H(pk||app_id)` **without revealing it to the key derivation service (coordinator)**. [6](#0-5) 

When `app_pk = identity`, the coordinator receives `CKDOutput.big_c = msk * H(pk||app_id)` in the clear. This is the confidential derived secret. The coordinator can read it directly without knowing `app_sk`, breaking the protocol's privacy guarantee entirely.

This matches: **Critical — Extraction, reconstruction, or disclosure of confidential derived secrets.**

---

### Likelihood Explanation

A malicious coordinator (a participant who calls `ckd()`) can trivially substitute `G1Projective::identity()` for the legitimate `app_pk` received from the client. `G1Projective::identity()` is a standard public API call in `blstrs` — no cryptographic knowledge, unsafe code, or external assumptions are required. The attack is local, deterministic, and single-invocation.

---

### Recommendation

Add explicit validation of `app_pk` at the entry of `ckd()` (or at the top of `compute_signature_share`):

```rust
// In ckd() or compute_signature_share():
let app_pk_affine: G1Affine = app_pk.into();
if app_pk_affine.is_identity().into()
    || !app_pk_affine.is_on_curve().into()
    || !app_pk_affine.is_torsion_free().into()
{
    return Err(InitializationError::InvalidAppPublicKey);
}
```

This mirrors the existing validation pattern already used in `verify_signature`. [7](#0-6) 

---

### Proof of Concept

```rust
use blstrs::G1Projective;
use elliptic_curve::Group;

// Attacker (malicious coordinator) passes identity as app_pk
let app_pk_malicious = G1Projective::identity(); // trivially available

let protocol = ckd(
    &participants,
    coordinator,   // attacker is the coordinator
    coordinator,
    key_pair,
    app_id,
    app_pk_malicious,  // <-- no validation rejects this
    rng,
).unwrap();

// After running the protocol, coordinator obtains CKDOutput
// CKDOutput.big_c == msk * H(pk || app_id)  (unblinded)
// Coordinator reads the confidential derived key directly from big_c
// without needing app_sk
```

The `ckd()` entry point accepts this input without error. [8](#0-7)  The blinding collapses at line 174. [9](#0-8)

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

**File:** src/confidential_key_derivation/protocol.rs (L170-174)
```rust
    // S <- x . H(app_id)
    let big_s = hash_point * private_share.to_scalar();

    // C <- S + y . A
    let big_c = big_s + app_pk * y.0;
```

**File:** src/confidential_key_derivation/ciphersuite.rs (L223-230)
```rust
    let element1: G1Affine = signature.into();
    if (!element1.is_on_curve() | !element1.is_torsion_free() | element1.is_identity()).into() {
        return Err(frost_core::Error::InvalidSignature);
    }
    let element2: G2Affine = verifying_key.to_element().into();
    if (!element2.is_on_curve() | !element2.is_torsion_free() | element2.is_identity()).into() {
        return Err(frost_core::Error::MalformedVerifyingKey);
    }
```

**File:** src/confidential_key_derivation/mod.rs (L1-10)
```rust
//! Confidential Key Derivation (CKD) protocol.
//!
//! This module provides the implementation of the Confidential Key Derivation (CKD) protocol,
//! which allows a client to derive a unique key for a specific application without revealing
//! the application identifier to the key derivation service.
//!
//! The protocol is based on a combination of Oblivious Transfer (OT) and Diffie-Hellman key exchange.
//!
//! For more details, refer to the `confidential-key-derivation.md` document in the `docs` folder.

```

**File:** src/confidential_key_derivation/mod.rs (L52-56)
```rust
    /// Takes a secret scalar and returns
    /// s <- C − a ⋅ Y = msk ⋅ H ( `app_id` )
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```
