### Title
Missing Identity-Element Validation on `app_pk` Discloses Confidential Derived Key to Coordinator — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The `ckd()` entry-point in `src/confidential_key_derivation/protocol.rs` accepts an `app_pk: PublicKey` (a `blstrs::G1Projective` point) without checking that it is not the group identity element. When `app_pk` is the identity, the ElGamal blinding term vanishes entirely, and the coordinator receives the confidential derived key `msk · H(pk ∥ app_id)` in plaintext inside `CKDOutput.big_c`. This breaks the core confidentiality guarantee of the CKD protocol: that the coordinator must not learn the derived key.

---

### Finding Description

**Protocol design.** The CKD protocol is an ElGamal-based scheme. Each participant `i` computes:

```
big_y_i = y_i · G
big_c_i = (x_i · H(pk ∥ app_id)) + (app_pk · y_i)
```

The coordinator aggregates Lagrange-weighted shares to obtain:

```
Y = Σ λ_i · big_y_i
C = msk · H(pk ∥ app_id) + app_pk · Y_sum
```

The client unmasks with `C − a · Y = msk · H(pk ∥ app_id)` using the application secret key `a` (where `app_pk = a · G`). The coordinator never learns `a`, so it cannot recover the derived key.

**Root cause.** `ckd()` validates participant membership and deduplication but performs no check that `app_pk` is not the identity element: [1](#0-0) 

The blinding computation in `compute_signature_share` is: [2](#0-1) 

When `app_pk = G1Projective::identity()`:

```
app_pk · y_i  =  identity · y_i  =  identity
big_c_i       =  x_i · H(pk ∥ app_id)   (blinding term is zero)
C             =  msk · H(pk ∥ app_id)   (the derived key, unencrypted)
```

The coordinator receives `CKDOutput { big_y: Y, big_c: msk·H(pk∥app_id) }`. `big_c` is the confidential derived key in the clear. [3](#0-2) 

The `unmask` function confirms the coordinator is not supposed to see this value without the application secret `a`: [4](#0-3) 

No validation of `app_pk` exists anywhere in the call chain (`ckd` → `run_ckd_protocol` → `do_ckd_coordinator` / `do_ckd_participant` → `compute_signature_share`). [5](#0-4) 

---

### Impact Explanation

**Category**: Critical — Disclosure of a confidential derived secret.

The coordinator, who is explicitly not trusted with the derived key, receives `msk · H(pk ∥ app_id)` in plaintext in `CKDOutput.big_c`. This is the exact value the ElGamal layer is designed to hide. The confidentiality guarantee of the entire CKD protocol is nullified for any invocation where `app_pk` is the identity element.

---

### Likelihood Explanation

`app_pk` is a caller-supplied `blstrs::G1Projective` value with no library-enforced constraint. An application that:
- fails to initialize the key pair before calling `ckd()`,
- deserializes a zeroed buffer as a point, or
- is itself malicious and wishes to expose the derived key to the coordinator

can trivially trigger this path. The library provides no guard. The `blstrs` crate's `G1Projective::identity()` is a valid, constructible value.

---

### Recommendation

Add an identity-element guard at the top of `ckd()`, analogous to the existing checks for participant membership:

```rust
// In ckd(), after existing participant checks:
if app_pk.is_identity().into() {
    return Err(InitializationError::BadParameters(
        "app_pk must not be the identity element".to_string(),
    ));
}
```

The `blstrs::G1Projective` type exposes `is_identity()` returning a `subtle::Choice`, consistent with the pattern already used in the BLS ciphersuite serialization: [6](#0-5) 

---

### Proof of Concept

```rust
use threshold_signatures::confidential_key_derivation::{
    ckd, AppId, ElementG1, KeygenOutput,
};
use threshold_signatures::participants::Participant;
use elliptic_curve::Group; // for ::identity()

let participants = vec![Participant::from(0u32), Participant::from(1u32)];
let coordinator = Participant::from(0u32);
let me = Participant::from(0u32);
let key_pair: KeygenOutput = /* ... valid keygen output ... */;
let app_id = AppId::try_from(b"test-app").unwrap();

// Attacker / accidental caller supplies the identity point
let app_pk = ElementG1::identity();

// No InitializationError is returned — protocol proceeds
let protocol = ckd(&participants, coordinator, me, key_pair, app_id, app_pk, rng).unwrap();

// After running the protocol, the coordinator's CKDOutput.big_c
// equals msk · H(pk ∥ app_id) in plaintext.
// The coordinator can read the confidential derived key directly
// without knowing the application secret key `a`.
```

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

**File:** src/confidential_key_derivation/mod.rs (L32-57)
```rust
pub struct CKDOutput {
    big_y: ElementG1,
    big_c: ElementG1,
}

impl CKDOutput {
    pub fn new(big_y: ElementG1, big_c: ElementG1) -> Self {
        Self { big_y, big_c }
    }

    /// Outputs `big_y`
    pub fn big_y(&self) -> ElementG1 {
        self.big_y
    }

    /// Outputs `big_c`
    pub fn big_c(&self) -> ElementG1 {
        self.big_c
    }

    /// Takes a secret scalar and returns
    /// s <- C − a ⋅ Y = msk ⋅ H ( `app_id` )
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
}
```

**File:** src/confidential_key_derivation/ciphersuite.rs (L194-200)
```rust
    fn serialize(element: &Self::Element) -> Result<Self::Serialization, frost_core::GroupError> {
        if element.is_identity().into() {
            Err(frost_core::GroupError::InvalidIdentityElement)
        } else {
            Ok(element.to_compressed())
        }
    }
```
