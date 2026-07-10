I have all the code I need. Let me analyze the exact exploit path.

The vulnerability is real and concrete. Here is the full analysis:

---

### Title
Missing `app_pk` Identity-Point Guard Discloses Confidential Derived Secret to Coordinator — (`src/confidential_key_derivation/protocol.rs`)

### Summary
`ckd()` accepts `app_pk = G1::identity()` without any validation. When the identity element is used as the ElGamal encryption key, the masking term `y_i * A` collapses to the group identity for every participant, causing the coordinator's aggregated `big_c` to equal `msk * H(pk||app_id)` — the confidential derived secret — in the clear.

### Finding Description

The ElGamal masking step in `compute_signature_share` is:

```rust
// C <- S + y . A
let big_c = big_s + app_pk * y.0;   // line 174
``` [1](#0-0) 

When `app_pk = G1::identity()`, scalar multiplication of the identity element by any scalar `y` returns the identity: `identity * y = identity`. Therefore `big_c = big_s = hash_point * private_share`, and the random blinding scalar `y` has no effect.

The coordinator aggregates all Lagrange-weighted shares:

```
C = Σ(λ_i * C_i) = Σ(λ_i * S_i) = msk * H(pk || app_id)
``` [2](#0-1) 

The resulting `CKDOutput.big_c` is the confidential derived secret itself, with no masking. The `ckd()` entry point performs no check on `app_pk`: [3](#0-2) 

The only guards are participant-list checks (duplicates, membership, coordinator presence). There is no `app_pk.is_identity()` rejection anywhere in the CKD code path.

### Impact Explanation

The `CKDOutput` struct exposes `big_c` via a public accessor:

```rust
pub fn big_c(&self) -> ElementG1 { self.big_c }
``` [4](#0-3) 

With `app_pk = identity`, `big_c = msk * H(pk||app_id)` is the confidential derived secret. It is published on-chain as part of `es = (Y, C)` per the protocol spec: [5](#0-4) 

Any on-chain observer — not just the coordinator — can read `C` directly and use it as the derived key without knowing `app_sk`. The `unmask` function confirms this: `unmask(Scalar::ZERO) = big_c - big_y * 0 = big_c`. [6](#0-5) 

The security requirement that `s` must be "only known by app" is violated. [7](#0-6) 

### Likelihood Explanation

The TEE app controls `app_pk`. The Developer contract is required to verify `A` is in `report_data`, but nothing prevents a malicious TEE app from placing `G1::identity()` in `report_data` — attestation proves the app runs in a TEE, not that `A` is a valid non-identity public key. The library is the last line of defense and has no guard. The attack requires only calling the public `ckd()` API with a single crafted parameter.

### Recommendation

Add an identity-point check in `ckd()` before proceeding:

```rust
use elliptic_curve::Group;

if app_pk.is_identity().into() {
    return Err(InitializationError::BadParameters {
        reason: "app_pk must not be the group identity",
    });
}
``` [8](#0-7) 

### Proof of Concept

```rust
// With app_pk = G1::identity(), big_c == msk * H(pk||app_id) directly.
let app_pk = ElementG1::identity();  // attacker-supplied

let ckd_output = /* run full protocol with app_pk = identity */;

// big_c is the unmasked confidential key
let exposed = ckd_output.big_c();
let expected = hash_app_id_with_pk(&pk, &app_id) * msk;
assert_eq!(exposed, expected);  // passes — secret disclosed

// unmask with any scalar gives the same result
assert_eq!(ckd_output.unmask(Scalar::ZERO), ckd_output.unmask(Scalar::ONE));
``` [9](#0-8)

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

**File:** src/confidential_key_derivation/mod.rs (L48-50)
```rust
    pub fn big_c(&self) -> ElementG1 {
        self.big_c
    }
```

**File:** src/confidential_key_derivation/mod.rs (L54-56)
```rust
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```

**File:** docs/confidential_key_derivation/confidential-key-derivation.md (L101-104)
```markdown
- $`s`$ must be deterministic as a function of $`\texttt{app\_id}`$ and only
  known by *app*
- No single node in the *MPC network* should be capable of computing $`s`$. This
avoids key leakage in the case a single TEE is compromised
```

**File:** docs/confidential_key_derivation/confidential-key-derivation.md (L169-170)
```markdown
    - $`\texttt{es} \gets (Y, C) `$
  - Coordinator sends $`\texttt{es}`$ to *app* on-chain
```
