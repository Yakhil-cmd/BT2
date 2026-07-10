I have all the information needed. Let me trace the exact exploit path through the code.

**Key facts from the code:**

1. `ckd()` in `protocol.rs` performs only participant-list checks — no validation of `app_pk`: [1](#0-0) 

2. `compute_signature_share()` computes `big_c = big_s + app_pk * y.0` with no identity check on `app_pk`: [2](#0-1) 

3. `PublicKey` is a raw `ElementG1` alias with no invariant enforcement: [3](#0-2) 

4. `CKDOutput.unmask` shows the intended invariant: `C - a*Y = msk*H(pk||app_id)`, which only holds when `C` is blinded: [4](#0-3) 

---

### Title
Missing `app_pk` identity-point validation in `ckd()` exposes confidential derived secret in plaintext — (`src/confidential_key_derivation/protocol.rs`)

### Summary
`ckd()` and `compute_signature_share()` accept `app_pk = G1Projective::identity()` without any guard. When `app_pk` is the identity point, the ElGamal blinding term `y_i * A` collapses to the identity, so each participant's `big_c` equals the unblinded share `x_i * H(pk||app_id)`. After Lagrange aggregation the coordinator's `CKDOutput.big_c` equals `msk * H(pk||app_id)` — the confidential derived secret — in plaintext, published on-chain.

### Finding Description
In `compute_signature_share` (line 174):

```rust
let big_c = big_s + app_pk * y.0;
```

If `app_pk = G1Projective::identity()`, then `app_pk * y.0 = identity` for any scalar `y.0`, so:

```
big_c_i = x_i * H(pk||app_id) + identity = x_i * H(pk||app_id)
```

After Lagrange normalization and coordinator aggregation (`do_ckd_coordinator`, lines 50–55):

```
C = Σ λ_i * big_c_i = Σ λ_i * x_i * H(pk||app_id) = msk * H(pk||app_id)
``` [5](#0-4) 

This is exactly the confidential derived secret `s` that the entire CKD protocol is designed to keep hidden. It is stored in `CKDOutput.big_c` and transmitted on-chain as part of `es = (Y, C)`, readable by any observer. [6](#0-5) 

Neither `ckd()` nor `compute_signature_share()` check `app_pk.is_identity()`. The `BLS12381G1Group::serialize` does reject identity for FROST group elements, but this path is never invoked for `app_pk`: [7](#0-6) 

### Impact Explanation
**Critical — disclosure of confidential derived secrets.** The invariant `C = msk*H + a*Y` (blinded) is broken; `C` becomes `msk*H` (unblinded). Any on-chain observer reads the raw BLS signature `msk * H(pk||app_id)`, which is the secret `s` the app was supposed to receive confidentially. The master secret key `msk` itself is not directly exposed, but the per-app derived secret is fully disclosed for every `(app_id, app_pk=identity)` request.

### Likelihood Explanation
The `app_pk` value originates from the requesting application and is forwarded by the developer contract to the MPC contract, then to the MPC nodes calling `ckd()`. The developer contract is documented as responsible for verifying attestation, but the docs do not explicitly require it to reject `app_pk = identity`. A malicious app, a buggy developer contract, or a developer who omits this check can trivially trigger the path. The library provides no defense-in-depth. [8](#0-7) 

### Recommendation
Add an identity-point check at the start of `ckd()` (or at the top of `compute_signature_share()`):

```rust
if app_pk.is_identity().into() {
    return Err(InitializationError::InvalidPublicKey);
}
```

This mirrors the existing pattern used in `BLS12381G1Group::serialize` and `verify_signature` for other G1 points. [9](#0-8) 

### Proof of Concept
```rust
// In a unit test, replace app_pk with the identity point:
let app_pk = G1Projective::identity(); // attacker-controlled input

// Run full ckd protocol with honest participants...
let ckd_output = /* run protocol */;

// big_c is now the raw confidential derived secret:
let expected = hash_app_id_with_pk(&pk, &app_id) * msk;
assert_eq!(ckd_output.big_c(), expected); // passes — secret exposed

// unmask with Scalar::ZERO also yields the same value:
assert_eq!(ckd_output.unmask(Scalar::ZERO), expected);

// verify_signature passes, confirming big_c IS the BLS signature:
assert!(verify_signature(&pk, &app_id, &ckd_output.big_c()).is_ok());
``` [10](#0-9)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L50-56)
```rust
    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
```

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

**File:** src/confidential_key_derivation/mod.rs (L32-56)
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
```

**File:** src/confidential_key_derivation/mod.rs (L62-62)
```rust
pub type PublicKey = ElementG1;
```

**File:** src/confidential_key_derivation/ciphersuite.rs (L194-199)
```rust
    fn serialize(element: &Self::Element) -> Result<Self::Serialization, frost_core::GroupError> {
        if element.is_identity().into() {
            Err(frost_core::GroupError::InvalidIdentityElement)
        } else {
            Ok(element.to_compressed())
        }
```

**File:** src/confidential_key_derivation/ciphersuite.rs (L218-230)
```rust
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
```
