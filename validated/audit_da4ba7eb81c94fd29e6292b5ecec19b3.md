### Title
Unvalidated `app_pk` Identity Element in CKD Protocol Discloses Confidential Derived Secret to Coordinator - (File: `src/confidential_key_derivation/protocol.rs`)

### Summary
The `ckd()` function in `src/confidential_key_derivation/protocol.rs` accepts the caller-supplied `app_pk` (the app's ElGamal public key `A`) without checking whether it is the G1 identity element. A malicious app that submits `app_pk = G1Projective::identity()` eliminates the ElGamal blinding entirely, causing the coordinator to receive the raw BLS signature `msk · H(pk, app_id)` in plaintext. This allows a single MPC node (the coordinator) to reconstruct the confidential derived secret `s`, directly violating the stated security requirement that no single node should be capable of computing `s`.

### Finding Description

The CKD protocol is designed so that each participant node `i` computes:

```
C_i = S_i + y_i · A    where S_i = x_i · H(pk, app_id)
Y_i = y_i · G1
```

The coordinator aggregates the Lagrange-weighted shares to obtain:

```
C = Σ λ_i · C_i = msk · H(pk, app_id) + (Σ λ_i · y_i) · A
Y = Σ λ_i · Y_i
```

The app then recovers the BLS signature via `unmask(a) = C − a · Y`. The blinding term `(Σ λ_i · y_i) · A` is what prevents the coordinator from reading `C` directly.

In `compute_signature_share`, the blinding is computed as:

```rust
// C <- S + y . A
let big_c = big_s + app_pk * y.0;
``` [1](#0-0) 

If `app_pk = G1Projective::identity()`, then `app_pk * y.0 = identity`, so `big_c = big_s = x_i · H(pk, app_id)`. After Lagrange normalization and aggregation by the coordinator:

```
C = Σ λ_i · x_i · H(pk, app_id) = msk · H(pk, app_id)
```

The coordinator's `CKDOutput.big_c` field now directly contains the unblinded BLS signature. The `ckd()` entry point performs no validation of `app_pk`: [2](#0-1) 

The only checks performed are participant-list structural checks (duplicate detection, self-membership, coordinator-membership). There is no `app_pk.is_identity()` guard anywhere in the protocol initialization or computation path.

Notably, the ciphersuite layer does define identity-element rejection, but only inside `serialize()` / `deserialize()` for group elements used in the DKG — not for the `app_pk` parameter passed to `ckd()`: [3](#0-2) 

### Impact Explanation

The stated security requirement is:

> "No single node in the MPC network should be capable of computing `s`. This avoids key leakage in the case a single TEE is compromised." [4](#0-3) 

When `app_pk = identity`, the coordinator — a single MPC node — directly observes `msk · H(pk, app_id)` in `CKDOutput.big_c` and can compute `s = HKDF(msk · H(pk, app_id))` without any additional information. This is a **Critical** disclosure of a confidential derived secret to a single node, matching the allowed impact: *"Extraction, reconstruction, or disclosure of … confidential derived secrets."*

### Likelihood Explanation

The `app_pk` value originates from the app (TEE application) and is passed through the MPC contract to each node, which then calls `ckd()` with it. A malicious app — or any caller that controls the `app_pk` argument — can trivially supply `G1Projective::identity()`. The `blstrs` crate represents the identity element as a valid, constructible `G1Projective` value, so no special capability is required. The attack requires only that the caller invoke `ckd()` with a crafted `app_pk`.

### Recommendation

Add an explicit identity-element check on `app_pk` at the start of `ckd()`, before the protocol is initialized:

```rust
if app_pk.is_identity().into() {
    return Err(InitializationError::BadParameters(
        "app_pk must not be the identity element".to_string(),
    ));
}
```

This mirrors the pattern already used in `BLS12381G1Group::serialize()` and `BLS12381G2Group::serialize()` for other group elements in the codebase. [5](#0-4) 

### Proof of Concept

```rust
// Attacker-controlled app supplies the G1 identity as app_pk
let app_pk = blstrs::G1Projective::identity(); // A = 0·G1

// All nodes run ckd() with this app_pk — no error is returned
let protocol = ckd(&participants, coordinator, me, key_pair, app_id, app_pk, rng).unwrap();

// After protocol completes, coordinator's output:
// big_c = msk · H(pk, app_id)   <-- raw BLS signature, no blinding
// big_y = Σ λ_i · y_i · G1     <-- random but irrelevant

// Coordinator reads the confidential derived secret directly:
let bls_sig = ckd_output.big_c(); // == msk · H(pk, app_id)
// s = HKDF(bls_sig) is now known to the coordinator alone
```

The coordinator can verify correctness by calling `verify_signature(&public_key, &app_id, &bls_sig)`, which will return `Ok(())`, confirming the extracted secret is valid. [6](#0-5) [7](#0-6)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L44-57)
```rust
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

**File:** src/confidential_key_derivation/protocol.rs (L173-174)
```rust
    // C <- S + y . A
    let big_c = big_s + app_pk * y.0;
```

**File:** src/confidential_key_derivation/ciphersuite.rs (L194-213)
```rust
    fn serialize(element: &Self::Element) -> Result<Self::Serialization, frost_core::GroupError> {
        if element.is_identity().into() {
            Err(frost_core::GroupError::InvalidIdentityElement)
        } else {
            Ok(element.to_compressed())
        }
    }

    fn deserialize(buf: &Self::Serialization) -> Result<Self::Element, frost_core::GroupError> {
        Self::Element::from_compressed(buf).into_option().map_or(
            Err(frost_core::GroupError::MalformedElement),
            |point| {
                if point.is_identity().into() {
                    Err(frost_core::GroupError::InvalidIdentityElement)
                } else {
                    Ok(point)
                }
            },
        )
    }
```

**File:** src/confidential_key_derivation/README.md (L5-5)
```markdown
The intended use case is providing deterministic secrets to applications running inside a TEE (Trusted Execution Environment), where the application can derive a key without any single MPC node learning the derived secret.
```

**File:** src/confidential_key_derivation/mod.rs (L54-56)
```rust
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```
