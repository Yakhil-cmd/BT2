### Title
Unvalidated `app_pk` Identity Element in CKD Protocol Discloses Confidential Derived Secret - (File: src/confidential_key_derivation/protocol.rs)

### Summary
The Confidential Key Derivation (CKD) protocol accepts an arbitrary `app_pk: PublicKey` (an `ElementG1`) without validating that it is not the group identity element. If `app_pk` is the identity, the ElGamal encryption layer is silently bypassed, and the coordinator's output `CKDOutput.big_c` directly contains the unencrypted derived secret `msk · H(pk ∥ app_id)`. A malicious coordinator can exploit this by supplying the identity element as `app_pk` to all participants, then reading the derived key directly from the protocol output.

### Finding Description
The `ckd()` entry point in `src/confidential_key_derivation/protocol.rs` validates participant membership and coordinator presence, but performs **no validation on `app_pk`**:

```rust
pub fn ckd(
    participants: &[Participant],
    coordinator: Participant,
    me: Participant,
    key_pair: KeygenOutput,
    app_id: impl Into<AppId>,
    app_pk: PublicKey,   // ← accepted without any check
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = CKDOutputOption>, InitializationError>
``` [1](#0-0) 

Inside `compute_signature_share`, each participant computes:

```
big_c = big_s + app_pk * y
      = (x_i · H(pk ∥ app_id)) + app_pk · y
``` [2](#0-1) 

When `app_pk = O` (the identity element of `G1`), `app_pk * y = O`, so:

```
big_c = big_s = x_i · H(pk ∥ app_id)
```

After the coordinator sums all Lagrange-weighted shares:

```
total_big_c = Σ λ_i · x_i · H(pk ∥ app_id) = msk · H(pk ∥ app_id)
```

This is the raw derived secret — completely unencrypted. The `CKDOutput.unmask(0)` call then trivially returns it:

```rust
pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
    self.big_c - self.big_y * secret_scalar  // big_c - O*0 = big_c = derived key
}
``` [3](#0-2) 

No error is raised at any point. The `blstrs` library silently treats multiplication by the identity as a no-op, so the insecure path is completely invisible to callers.

### Impact Explanation
The entire security guarantee of CKD is that MPC nodes never learn the derived secret — it is encrypted under `app_pk` so only the holder of the corresponding private key can recover it. When `app_pk = O`, this guarantee is completely destroyed: the coordinator receives `CKDOutput` where `big_c` **is** the derived secret in plaintext. The coordinator can extract `msk · H(pk ∥ app_id)` without possessing any application private key. This is a direct, complete disclosure of the confidential derived secret.

Allowed impact matched: **Critical — Extraction, reconstruction, or disclosure of confidential derived secrets.**

### Likelihood Explanation
In a real deployment, `app_pk` originates from the requesting application and is relayed to each participant by the coordinator. A malicious coordinator can substitute the identity element for the legitimate `app_pk` before forwarding the request. Participants have no way to detect this substitution because the library performs no validation and the protocol produces no observable error. The attack requires only that the coordinator be malicious — a documented trust assumption boundary in threshold MPC systems — and is trivially executable with a single-line change.

### Recommendation
Add an explicit check in `ckd()` (and defensively in `compute_signature_share`) that `app_pk` is not the group identity element before proceeding:

```rust
if app_pk == ElementG1::identity() {
    return Err(InitializationError::BadParameters(
        "app_pk must not be the identity element".to_string(),
    ));
}
```

Additionally, consider whether participants should receive a commitment to `app_pk` via the echo-broadcast layer so that all honest participants can verify they are computing with the same application public key, preventing a malicious coordinator from supplying different values to different participants.

### Proof of Concept
1. Honest participants hold shares `x_i` of master secret key `msk`.
2. Malicious coordinator calls `ckd(..., app_pk = ElementG1::identity(), ...)` on behalf of all participants.
3. Each participant computes `big_c_i = λ_i · x_i · H(pk ∥ app_id) + O · y_i = λ_i · x_i · H(pk ∥ app_id)` and sends it to the coordinator.
4. Coordinator sums: `total_big_c = Σ λ_i · x_i · H(pk ∥ app_id) = msk · H(pk ∥ app_id)`.
5. Coordinator reads `ckd_output.big_c()` directly — this is the derived secret `msk · H(pk ∥ app_id)` with no decryption step required.
6. No error is returned; all participants believe the protocol succeeded normally. [2](#0-1) [4](#0-3)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L35-57)
```rust
async fn do_ckd_coordinator(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    key_pair: &KeygenOutput,
    app_id: &AppId,
    app_pk: PublicKey,
    rng: &mut impl CryptoRngCore,
) -> Result<CKDOutputOption, ProtocolError> {
    let (mut norm_big_y, mut norm_big_c) =
        compute_signature_share(&participants, me, key_pair, app_id, app_pk, rng)?;

    // Receive everyone's inputs and add them together
    let waitpoint = chan.next_waitpoint();

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
