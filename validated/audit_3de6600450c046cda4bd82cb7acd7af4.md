### Title
Missing G1 Point Validation on Caller-Supplied `app_pk` Breaks ElGamal Confidentiality in CKD Protocol — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The `ckd()` function accepts a caller-supplied `app_pk: PublicKey` (a `blstrs::G1Projective` point) and uses it directly as the ElGamal encryption key without any validation — no identity check, no on-curve check, no subgroup/torsion-free check. If an attacker submits `app_pk = G1Projective::identity()`, the ElGamal blinding term `y * app_pk` collapses to the identity element, causing each node's ciphertext share `C_i` to equal the unblinded secret share `S_i = x_i * H(pk, app_id)`. The coordinator aggregates these into `C = msk * H(pk, app_id)` — the confidential derived key — in plaintext, directly disclosing it to MPC nodes and any on-chain observer.

---

### Finding Description

The CKD protocol uses ElGamal encryption to protect the derived BLS signature `s = msk * H(pk, app_id)`. Each node computes:

```
S_i = x_i * H(pk, app_id)       // secret share of the derived key
C_i = S_i + y_i * A             // ElGamal ciphertext; A = app_pk
Y_i = y_i * G1                  // ephemeral public key share
```

The blinding term `y_i * A` is the only mechanism hiding `S_i`. The app recovers `s = C - a*Y` using its private scalar `a` where `A = a * G1`.

In `compute_signature_share()`, `app_pk` is used at line 174 with no prior validation:

```rust
// C <- S + y . A
let big_c = big_s + app_pk * y.0;
``` [1](#0-0) 

The public entry point `ckd()` performs only participant-list structural checks and passes `app_pk` through unchanged: [2](#0-1) 

By contrast, `verify_signature()` in `ciphersuite.rs` correctly validates both G1 and G2 points before any pairing operation:

```rust
let element1: G1Affine = signature.into();
if (!element1.is_on_curve() | !element1.is_torsion_free() | element1.is_identity()).into() {
    return Err(frost_core::Error::InvalidSignature);
}
``` [3](#0-2) 

No equivalent guard exists for `app_pk` in the `ckd()` path.

---

### Impact Explanation

**Critical — Disclosure of confidential derived secrets.**

If `app_pk = G1Projective::identity()`:

- `y_i * app_pk = identity` for any scalar `y_i`
- `C_i = S_i + identity = S_i = x_i * H(pk, app_id)`
- Coordinator aggregates: `C = Σ(λ_i * C_i) = msk * H(pk, app_id) = s`

The `CKDOutput` returned is `(Y, C)` where `C = s` is the confidential derived key in plaintext. The core security requirement — *"s must be deterministic as a function of app_id and only known by app"* — is completely violated: [4](#0-3) 

Every MPC node that processes the request computes `C_i = S_i` and transmits it. The coordinator sees `C = s` directly. The value is then posted on-chain as part of the CKD response, making it visible to any blockchain observer. The attacker calls `unmask(Scalar::ZERO)` = `C - 0*Y = C = s` to recover the secret trivially. [5](#0-4) 

---

### Likelihood Explanation

**High.** The attacker is the TEE app itself — the entity that generates `(a, A)` and submits `A` as `app_pk` to the MPC network. This is a direct, single-step attack requiring no special privileges beyond the ability to submit a CKD request. `G1Projective::identity()` is a valid Rust value constructible with no cryptographic knowledge. The `ckd()` API is public and the `app_pk` parameter is fully attacker-controlled with no upstream sanitization enforced by the library. [6](#0-5) 

---

### Recommendation

Add an explicit validation of `app_pk` at the top of `ckd()` before the protocol is initialized, mirroring the checks already present in `verify_signature()`:

```rust
// In ckd(), after participant list checks:
let app_pk_affine: blstrs::G1Affine = app_pk.into();
if (!app_pk_affine.is_on_curve()
    | !app_pk_affine.is_torsion_free()
    | app_pk_affine.is_identity()).into()
{
    return Err(InitializationError::InvalidPublicKey);
}
```

This mirrors the existing pattern in `verify_signature()` at lines 223–226 of `ciphersuite.rs` and should be added to `ckd()` in `protocol.rs` before `run_ckd_protocol` is called. [7](#0-6) 

---

### Proof of Concept

```rust
use blstrs::{G1Projective, Scalar};
use elliptic_curve::Group;
use threshold_signatures::confidential_key_derivation::{
    ciphersuite::verify_signature,
    protocol::ckd,
    AppId, CKDOutputOption, ElementG1, VerifyingKey,
};

// Attacker submits the identity element as app_pk
let malicious_app_pk = G1Projective::identity(); // A = O
let malicious_app_sk = Scalar::ZERO;             // a = 0, so A = 0*G1 = O

// ... (set up participants, key_pair, app_id as normal) ...

let protocol = ckd(
    &participants,
    coordinator,
    me,
    key_pair,
    app_id.clone(),
    malicious_app_pk,  // <-- identity point, no validation triggered
    rng,
).unwrap();

// After running the protocol, coordinator receives CKDOutput (Y, C)
// C = msk * H(pk, app_id) = s  (plaintext, no blinding)
// Y = random G1 point (irrelevant)

let ckd_output = /* run protocol and collect coordinator output */;

// Attacker recovers s directly:
let s = ckd_output.unmask(Scalar::ZERO); // C - 0*Y = C = s

// Verify s is the real derived key:
assert!(verify_signature(&public_key, &app_id, &s).is_ok());
// => s is the confidential derived key, obtained without knowing msk
```

The `ckd()` call at line 66 of `protocol.rs` accepts `malicious_app_pk` without error. `compute_signature_share()` at line 174 computes `big_c = big_s + identity = big_s`, transmitting the unblinded secret share. The coordinator aggregates to `C = msk * H(pk, app_id)` and returns it in `CKDOutput`. [8](#0-7)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L66-116)
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

**File:** src/confidential_key_derivation/ciphersuite.rs (L223-229)
```rust
    let element1: G1Affine = signature.into();
    if (!element1.is_on_curve() | !element1.is_torsion_free() | element1.is_identity()).into() {
        return Err(frost_core::Error::InvalidSignature);
    }
    let element2: G2Affine = verifying_key.to_element().into();
    if (!element2.is_on_curve() | !element2.is_torsion_free() | element2.is_identity()).into() {
        return Err(frost_core::Error::MalformedVerifyingKey);
```

**File:** docs/confidential_key_derivation/confidential-key-derivation.md (L101-104)
```markdown
- $`s`$ must be deterministic as a function of $`\texttt{app\_id}`$ and only
  known by *app*
- No single node in the *MPC network* should be capable of computing $`s`$. This
avoids key leakage in the case a single TEE is compromised
```

**File:** src/confidential_key_derivation/mod.rs (L54-56)
```rust
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```
