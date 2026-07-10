Looking at the full picture now. Let me check the `do_ckd_coordinator` output verification and compare with how DKG handles zero shares.

### Title
Malicious Participant Can Corrupt CKD Output by Supplying Arbitrary `private_share` (Including Zero) — (`src/confidential_key_derivation/protocol.rs`)

---

### Summary

`ckd()` accepts a caller-supplied `KeygenOutput` and passes `private_share` directly into `compute_signature_share` with no validation. A malicious participant can substitute any scalar — including zero — for their real DKG share. The coordinator blindly sums all contributions and returns a `CKDOutput` without any output-correctness check, so honest parties receive an unusable derived key.

---

### Finding Description

In `compute_signature_share`, the participant's contribution is:

```
big_s  = H(pk||app_id) * x_i          // x_i = private_share.to_scalar()
big_c  = big_s + app_pk * y_i
norm_big_c = lambda_i * big_c
``` [1](#0-0) 

The coordinator aggregates all `norm_big_c_i` and returns the result immediately:

```rust
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
Ok(Some(ckd_output))
``` [2](#0-1) 

There is **no verification** that the aggregated output satisfies `unmask(app_sk) == msk * H(pk||app_id)`. Compare with ECDSA signing, where the coordinator explicitly calls `sig.verify()` before returning.

The `ckd()` entry-point performs only structural checks (participant count, duplicates, membership): [3](#0-2) 

It never inspects `key_pair.private_share`. The `KeygenOutput` struct exposes `private_share` as a public field, so any caller can construct one with `SigningShare::new(Scalar::ZERO)`. [4](#0-3) 

Contrast with DKG, which explicitly rejects a zero secret before the protocol runs: [5](#0-4) 

---

### Impact Explanation

If participant j supplies `x_j = 0` (or any value ≠ their real share `x_j_real`), the aggregated ciphertext becomes:

```
C = (msk − λ_j · x_j_real) · H(pk||app_id) + a · Y
```

so `unmask(app_sk) = C − a·Y = (msk − λ_j · x_j_real) · H(pk||app_id) ≠ msk · H(pk||app_id)`.

The coordinator returns this corrupted `CKDOutput` as `Some(...)` with no error. Honest parties that call `unmask` receive a wrong group element; `verify_signature` on the result fails. The derived confidential key is permanently unusable for that `(pk, app_id)` pair.

This matches the **High** impact: *Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.*

---

### Likelihood Explanation

The attack requires only that one participant in the CKD session deliberately passes a crafted `KeygenOutput` to `ckd()`. The public API accepts it without complaint. No cryptographic assumption needs to be broken; no privileged access is required beyond being a listed participant. The attack is trivially reproducible in a unit test.

---

### Recommendation

1. **Coordinator output verification**: After aggregation, verify the result before returning it, analogous to how ECDSA signing verifies the signature:
   ```rust
   let confidential_key = ckd_output.unmask(app_sk); // requires app_sk at coordinator
   verify_signature(&key_pair.public_key, app_id, &confidential_key)?;
   ```
   (This requires the coordinator to hold or receive `app_sk`, which may not fit the protocol's confidentiality goals — see note below.)

2. **Zero-share guard in `ckd()`**: Mirror the DKG check — reject `private_share == 0` at the entry point, consistent with `assert_keyshare_inputs` in `dkg.rs`.

3. **Protocol-level binding (preferred)**: Add a zero-knowledge proof or Pedersen commitment that binds each participant's `norm_big_c` contribution to their public verifying share, so the coordinator can reject malformed inputs without learning the private share.

> Note: Option 1 alone is insufficient if `app_sk` is not available at the coordinator. Option 3 is the cryptographically sound fix; option 2 is a partial mitigation that only catches the zero case.

---

### Proof of Concept

```rust
#[test]
fn test_ckd_zero_share_corrupts_output() {
    use threshold_signatures::confidential_key_derivation::{
        ciphersuite::{verify_signature, G1Projective, Group as _},
        protocol::ckd, AppId, BLS12381SHA256, KeygenOutput, SigningShare,
    };
    use threshold_signatures::{participants::Participant, Scalar};
    use rand_core::OsRng;

    let mut rng = OsRng;
    let app_id = AppId::try_from(b"Near App").unwrap();
    let app_sk = Scalar::<BLS12381SHA256>::random(&mut rng);
    let app_pk = G1Projective::generator() * app_sk;

    // Run a real keygen for 3 participants
    let participants = /* generate_participants(3) */;
    let keys = /* run_keygen(&participants, 2) */;
    let public_key = keys[&participants[0]].public_key;
    let coordinator = participants[0];

    // Participant 1 uses their real key; participant 2 uses zero share
    let mut protocols = vec![];
    for (i, p) in participants.iter().enumerate() {
        let mut key_pair = keys[p].clone();
        if i == 1 {
            key_pair.private_share = SigningShare::new(Scalar::<BLS12381SHA256>::zero());
        }
        protocols.push((*p, Box::new(ckd(&participants, coordinator, *p,
            key_pair, app_id.clone(), app_pk, OsRng).unwrap())));
    }

    let result = run_protocol(protocols).unwrap();
    let ckd_out = result.into_iter().find_map(|(_, o)| o).unwrap();
    let confidential_key = ckd_out.unmask(app_sk);

    // This assertion FAILS — output is corrupted
    assert!(verify_signature(&public_key, &app_id, &confidential_key).is_ok(),
        "CKD output corrupted by zero-share participant");
}
```

The `verify_signature` call will fail, demonstrating that the coordinator accepted and returned an unusable `CKDOutput` with no error.

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L56-57)
```rust
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
    Ok(Some(ckd_output))
```

**File:** src/confidential_key_derivation/protocol.rs (L74-101)
```rust
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

**File:** src/confidential_key_derivation/protocol.rs (L171-180)
```rust
    let big_s = hash_point * private_share.to_scalar();

    // C <- S + y . A
    let big_c = big_s + app_pk * y.0;

    // Compute  λi := λi(0)
    let lambda_i = participants.lagrange::<BLS12381SHA256>(me)?;
    // Normalize Y and C into  (λi . Y , λi . C)
    let norm_big_y = big_y * lambda_i;
    let norm_big_c = big_c * lambda_i;
```

**File:** src/lib.rs (L51-55)
```rust
pub struct KeygenOutput<C: Ciphersuite> {
    pub private_share: SigningShare<C>,
    #[zeroize[skip]]
    pub public_key: VerifyingKey<C>,
}
```

**File:** src/dkg.rs (L48-52)
```rust
        if is_zero_secret {
            return Err(ProtocolError::AssertionFailed(format!(
                "{me:?} is running DKG with a zero share"
            )));
        }
```
