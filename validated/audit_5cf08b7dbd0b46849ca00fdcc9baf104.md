### Title
Missing Identity-Point Guard on `app_pk` Allows ElGamal Masking Bypass in CKD — (`src/confidential_key_derivation/protocol.rs`)

### Summary

The `ckd()` entry-point accepts an arbitrary `app_pk: PublicKey` (`G1Projective`) with no check that it is a valid, non-identity group element. Supplying the identity point causes the ElGamal blinding term to vanish, so the coordinator's aggregated output `C` equals `msk · H(pk ‖ app_id)` in the clear — the confidential derived secret — without requiring knowledge of `app_sk`.

---

### Finding Description

`compute_signature_share` computes the masked share as:

```
C_i = S_i + y_i · A      (A = app_pk)
``` [1](#0-0) 

When `A = G1Projective::identity()`, scalar multiplication of the identity element yields the identity for any scalar, so `y_i · A = identity`, and:

```
C_i = S_i + identity = S_i = x_i · H(pk ‖ app_id)
```

The coordinator then aggregates:

```
C = Σ λ_i · C_i = Σ λ_i · x_i · H(pk ‖ app_id) = msk · H(pk ‖ app_id)
``` [2](#0-1) 

This is the confidential derived secret, fully unmasked in the coordinator's output.

The `ckd()` initializer performs only participant-list checks; there is **no** guard on `app_pk`: [3](#0-2) 

`AppId::try_new` validates only byte-length, not the public key: [4](#0-3) 

---

### Impact Explanation

The protocol's confidentiality invariant — stated explicitly in the spec — is that `(Y, C)` is semantically hidden from the coordinator without knowledge of `app_sk`:

> *"No single node in the MPC network should be capable of computing s."* [5](#0-4) 

With `app_pk = identity`, the coordinator's `CKDOutput.big_c` **is** `msk · H(pk ‖ app_id)`. The caller can also recover it trivially via `unmask(Scalar::ZERO)`:

```rust
// unmask: C - a·Y  →  C - 0·Y  =  C  =  msk·H(pk‖app_id)
pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
    self.big_c - self.big_y * secret_scalar
}
``` [6](#0-5) 

Impact: **Critical — disclosure of the confidential derived secret `msk · H(pk ‖ app_id)` to the coordinator and/or the attacker-caller without the application secret key.**

---

### Likelihood Explanation

The attack requires only calling the public `ckd()` API with `app_pk = G1Projective::identity()`. No cryptographic assumptions need to be broken, no privileged access is required, and the path is a single function call. Any application-layer caller (on-chain contract, off-chain client) that can submit a CKD request can trigger this.

---

### Recommendation

Add an identity-point check in `ckd()` before constructing the protocol:

```rust
use elliptic_curve::Group;

if app_pk.is_identity().into() {
    return Err(InitializationError::InvalidInput(
        "app_pk must not be the identity element".to_string(),
    ));
}
```

This should be placed immediately after the coordinator-presence check in `ckd()`. [7](#0-6) 

---

### Proof of Concept

```rust
#[test]
fn test_identity_app_pk_bypasses_masking() {
    use threshold_signatures::confidential_key_derivation::{
        ciphersuite::{G1Projective, Group as _, Field as _},
        protocol::ckd,
        AppId, Scalar, CKDOutputOption,
    };
    use rand_core::OsRng;

    let app_id = AppId::try_from(b"test-app".as_ref()).unwrap();
    // Attacker supplies the identity point as app_pk
    let app_pk = G1Projective::identity();

    let participants = /* generate 3 participants */;
    let keys = /* run_keygen */;
    let coordinator = participants[0];

    let mut protocols = vec![];
    for p in &participants {
        let kp = keys.get(p).unwrap().clone();
        let proto = ckd(&participants, coordinator, *p, kp, app_id.clone(), app_pk, OsRng).unwrap();
        protocols.push((*p, Box::new(proto)));
    }

    let results = run_protocol(protocols).unwrap();
    let ckd_out = results.into_iter().find_map(|(_, o)| o).unwrap();

    // With identity app_pk, unmask(0) == unmask(any_scalar) == msk·H(pk‖app_id)
    let secret_with_zero = ckd_out.unmask(Scalar::ZERO);
    let secret_with_rand = ckd_out.unmask(Scalar::random(OsRng));
    assert_eq!(secret_with_zero, secret_with_rand); // masking is gone
    // big_c IS the confidential key — coordinator can read it directly
    assert_eq!(ckd_out.big_c(), secret_with_zero);
}
```

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L44-56)
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

**File:** src/confidential_key_derivation/protocol.rs (L173-174)
```rust
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

**File:** docs/confidential_key_derivation/confidential-key-derivation.md (L102-104)
```markdown
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
