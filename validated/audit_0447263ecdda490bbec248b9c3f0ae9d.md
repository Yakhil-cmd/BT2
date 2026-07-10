### Title
Missing Identity-Point Validation on `app_pk` in `ckd()` Allows Coordinator to Learn Confidential Derived Secret - (File: src/confidential_key_derivation/protocol.rs)

### Summary

The `ckd()` entry point in `src/confidential_key_derivation/protocol.rs` accepts the caller-supplied `app_pk` (the TEE app's ElGamal public key `A`) without validating that it is not the group identity element. When `app_pk = G1::identity()`, the ElGamal blinding term `y * A` collapses to zero, causing every participant's `C_i` share to equal `x_i * H(pk, app_id)` in the clear. The coordinator then aggregates these into `C = msk * H(pk, app_id)` — the confidential derived secret — directly visible in its output buffer, violating the protocol's core secrecy guarantee that no single MPC node can compute `s`.

### Finding Description

**Root cause — missing validation in `ckd()`:**

`app_pk: PublicKey` (alias for `blstrs::G1Projective`) is accepted without any check that it is a valid, non-identity group element. [1](#0-0) 

Inside `compute_signature_share`, the blinding step is:

```rust
// C <- S + y . A
let big_c = big_s + app_pk * y.0;
``` [2](#0-1) 

When `app_pk = G1Projective::identity()`, scalar multiplication of the identity yields the identity, so `big_c = big_s = x_i * H(pk, app_id)`. The random blinding scalar `y` has no effect.

The coordinator then aggregates all Lagrange-weighted shares:

```
C = Σ λ_i · C_i = Σ λ_i · x_i · H(pk, app_id) = msk · H(pk, app_id) = s
``` [3](#0-2) 

`s` is the confidential derived secret. It is now fully reconstructed and visible to the coordinator — a single MPC node — in `norm_big_c` before the output is returned.

**Contrast with `AppId` validation:** `AppId::try_new` enforces a maximum-length bound, showing the codebase is aware of the need to validate CKD inputs. No analogous guard exists for `app_pk`. [4](#0-3) 

### Impact Explanation

The CKD protocol's stated security requirement is explicit:

> "No single node in the MPC network should be capable of computing `s`. This avoids key leakage in the case a single TEE is compromised." [5](#0-4) 

When `app_pk = identity`, the coordinator — a single MPC node — receives `C = s = msk · H(pk, app_id)` in the clear. This is a direct disclosure of a confidential derived secret to a single node, violating the above requirement. Any subsequent compromise of the coordinator node exposes `s` to an attacker. **Impact: Critical** (disclosure of confidential derived secret).

### Likelihood Explanation

The `app_pk` value originates from the TEE app and travels through the developer contract and MPC contract before reaching the MPC network. The library performs zero validation on it. A malicious TEE app (or any caller of the `ckd()` API) can trivially supply `G1Projective::identity()` as `app_pk`. The developer contract specification does not mandate a non-identity check on `A`. The attack requires no cryptographic capability — only the ability to call `ckd()` with a crafted input.

### Recommendation

Add an identity-point check on `app_pk` at the start of `ckd()`, analogous to the existing `msg_hash != 0` guard in the robust ECDSA `sign()` function:

```rust
if bool::from(app_pk.is_identity()) {
    return Err(InitializationError::BadParameters(
        "app_pk must not be the identity element".to_string(),
    ));
}
``` [6](#0-5) 

Additionally, enforce a minimum length of 1 byte on `AppId::try_new` to prevent two distinct apps from colliding on an empty identifier.

### Proof of Concept

```rust
// Attacker-controlled TEE app passes identity as app_pk
let app_pk = blstrs::G1Projective::identity(); // A = O

// Each participant computes:
//   big_c = x_i * H(pk, app_id) + y_i * O
//         = x_i * H(pk, app_id)          ← blinding removed
//
// Coordinator aggregates:
//   C = Σ λ_i * C_i = msk * H(pk, app_id) = s
//
// s is now visible to the coordinator in norm_big_c,
// violating "no single node can compute s".

let protocol = ckd(
    &participants,
    coordinator,
    me,
    key_pair,
    app_id,
    app_pk,   // identity — accepted without error
    rng,
).unwrap();
// coordinator's CKDOutput.big_c == msk * H(pk, app_id)
``` [7](#0-6)

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

**File:** src/confidential_key_derivation/app_id.rs (L58-68)
```rust
    pub fn try_new(id: impl AsRef<[u8]>) -> Result<Self, ProtocolError> {
        let id = id.as_ref();
        if id.len() > MAX_APP_ID_LEN {
            let err_msg = format!(
                "AppId length ({}) exceeds maximum allowed length ({})",
                id.len(),
                MAX_APP_ID_LEN
            );
            return Err(ProtocolError::InvalidInput(err_msg));
        }
        Ok(Self(Arc::from(id)))
```

**File:** docs/confidential_key_derivation/confidential-key-derivation.md (L101-107)
```markdown
- $`s`$ must be deterministic as a function of $`\texttt{app\_id}`$ and only
  known by *app*
- No single node in the *MPC network* should be capable of computing $`s`$. This
avoids key leakage in the case a single TEE is compromised
- $`\texttt{app\_id}`$ must be a unique deterministic value tied to *app* and
the attestation runtime measurements. It should not be forgeable by any other
app
```

**File:** src/ecdsa/robust_ecdsa/sign.rs (L91-95)
```rust
    if bool::from(msg_hash.is_zero()) {
        return Err(InitializationError::BadParameters(
            "msg_hash cannot be 0 to avoid potential split view attacks".to_string(),
        ));
    }
```
