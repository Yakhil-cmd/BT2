### Title
Missing Validation of `app_pk` Allows Caller to Bypass ElGamal Blinding and Directly Expose Confidential Derived Key - (File: `src/confidential_key_derivation/protocol.rs`)

### Summary

The `ckd()` function in `src/confidential_key_derivation/protocol.rs` accepts an `app_pk` parameter (the TEE application's ElGamal public key `A`) without validating that it is not the group identity element. If a caller passes `app_pk = G1::identity()`, the ElGamal blinding term `y * A` collapses to zero, causing the ciphertext component `C` to directly equal the unblinded BLS signature `msk * H(pk, app_id)` — the confidential derived key — in the protocol output. Any party who can invoke `ckd()` with a crafted identity-point `app_pk` receives the confidential derived secret without possessing the corresponding private scalar `a`.

### Finding Description

The CKD protocol is designed so that each MPC node computes:

```
S_i = x_i * H(pk, app_id)
C_i = S_i + y_i * A          // ElGamal encryption with app's public key A
```

The coordinator aggregates:

```
C = Σ λ_i * C_i = msk * H(pk, app_id) + (Σ λ_i * y_i) * A
```

Only the TEE app holding the secret scalar `a` (where `A = a * G1`) can recover the BLS signature `s = C - a * Y`. This ElGamal blinding is the sole confidentiality mechanism.

In `compute_signature_share` at line 174:

```rust
// C <- S + y . A
let big_c = big_s + app_pk * y.0;
```

`app_pk` is of type `PublicKey = blstrs::G1Projective`. The identity element of `G1Projective` is a valid Rust value. If `app_pk` is the identity point `O`:

```
C_i = S_i + y_i * O = S_i + O = S_i = x_i * H(pk, app_id)
```

After aggregation:

```
C = Σ λ_i * S_i = msk * H(pk, app_id)
```

The `CKDOutput.big_c` field now directly contains the BLS signature `msk * H(pk, app_id)`, which is the confidential derived key, with no blinding whatsoever.

The `ckd()` entry point performs no validation on `app_pk`:

```rust
pub fn ckd(
    participants: &[Participant],
    coordinator: Participant,
    me: Participant,
    key_pair: KeygenOutput,
    app_id: impl Into<AppId>,
    app_pk: PublicKey,   // ← no identity check, no subgroup check
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = CKDOutputOption>, InitializationError> {
    // only checks: participant count, duplicates, self-presence, coordinator-presence
``` [1](#0-0) [2](#0-1) 

### Impact Explanation

The confidentiality guarantee of CKD is entirely provided by the ElGamal blinding: `C = msk * H(pk, app_id) + a * Y`. When `app_pk = O`, this reduces to `C = msk * H(pk, app_id)`, which is the confidential derived key itself. The attacker reads `ckd_output.big_c` directly to obtain the secret. This constitutes **extraction/disclosure of a confidential derived secret** — the exact secret the protocol is designed to protect.

Per the protocol specification, `s = msk * H(pk, app_id)` is then used to derive the application key via `HKDF(s)`. Disclosure of `s` means the attacker can derive the same application key as the legitimate TEE app, breaking the confidentiality guarantee entirely for the targeted `(app_id, pk)` pair. [3](#0-2) [4](#0-3) 

### Likelihood Explanation

The `ckd()` function is a public library API. Any caller who can invoke it — including a malicious MPC node operator, a malicious coordinator, or any integrator of the library — can supply `app_pk = ElementG1::identity()`. The `blstrs::G1Projective::identity()` value is trivially constructible. No privileged access, leaked keys, or cryptographic breaks are required. The attacker only needs to be able to call `ckd()` with a crafted argument, which is the normal usage pattern of the library. [5](#0-4) 

### Recommendation

Add an explicit check in `ckd()` (or at the top of `compute_signature_share`) that rejects `app_pk` if it is the identity element of G1:

```rust
if app_pk.is_identity().into() {
    return Err(InitializationError::BadParameters(
        "app_pk must not be the identity element".to_string(),
    ));
}
```

Additionally, consider verifying that `app_pk` is torsion-free (i.e., in the prime-order subgroup of G1), consistent with the validation already performed on signatures in `verify_signature`:

```rust
let app_pk_affine: G1Affine = app_pk.into();
if (!app_pk_affine.is_on_curve() | !app_pk_affine.is_torsion_free() | app_pk_affine.is_identity()).into() {
    return Err(InitializationError::BadParameters("invalid app_pk".to_string()));
}
``` [6](#0-5) 

### Proof of Concept

```rust
use blstrs::{G1Projective, G2Projective, Scalar};
use elliptic_curve::Group;
use threshold_signatures::confidential_key_derivation::{
    protocol::ckd, AppId, CKDOutputOption, KeygenOutput, SigningShare, VerifyingKey,
};
use threshold_signatures::participants::Participant;

// Attacker passes the G1 identity point as app_pk
let app_pk_malicious = G1Projective::identity(); // <-- crafted input

// Attacker invokes ckd() with a legitimate app_id targeting a victim app
let app_id = AppId::try_from(b"victim_app_id").unwrap();

// ... (setup participants, key_pair as normal) ...

let protocol = ckd(
    &participants,
    coordinator,
    me,
    key_pair,
    app_id,
    app_pk_malicious, // identity point — no blinding
    rng,
).unwrap();

// After running the protocol, the coordinator's output contains:
// ckd_output.big_c == msk * H(pk, app_id)  ← confidential derived key, unblinded
// The attacker reads big_c directly without knowing any secret scalar.
let ckd_output = /* run protocol and collect coordinator output */;
let confidential_key_exposed = ckd_output.big_c(); // == msk * H(pk, app_id)
```

The `big_c` field of the `CKDOutput` directly equals `msk * H(pk, app_id)` — the BLS signature that is the confidential derived key — because the ElGamal blinding term `y * A` vanishes when `A = O`. [7](#0-6) [8](#0-7)

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

**File:** src/confidential_key_derivation/mod.rs (L30-57)
```rust
/// The output of the confidential key derivation protocol when run by the coordinator
#[derive(Debug, Clone, Deserialize, Serialize)]
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

**File:** docs/confidential_key_derivation/confidential-key-derivation.md (L171-176)
```markdown
- *app* obtains $`\texttt{es} = (Y, C)`$ and computes the BLS signature
  $`\texttt{sig} \gets C + (- a) \cdot  Y`$ and checks its correctness with
  respect to the MPC network public key $`\texttt{pk}`$. If correct, the app can
  use the computed $`\texttt{sig} = \texttt{msk} \cdot H(\texttt{pk},\, \texttt{app\_id})`$ to
  compute the key $`s = \texttt{HKDF}(\texttt{sig})`$, using a
  [HKDF](https://en.wikipedia.org/wiki/HKDF) function.
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
