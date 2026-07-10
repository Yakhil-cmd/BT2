### Title
Missing `app_pk` Identity-Point Validation in CKD Allows Coordinator to Extract Confidential Derived Secret - (File: src/confidential_key_derivation/protocol.rs)

### Summary

The `ckd()` function in `src/confidential_key_derivation/protocol.rs` accepts a caller-supplied `app_pk: PublicKey` (the app's ElGamal public key `A`) without validating that it is not the group identity element. If `app_pk` is the identity point of G1, the ElGamal blinding factor `y_i * A` collapses to zero for every participant, causing the coordinator to directly receive the unblinded BLS signature `msk * H(pk, app_id)` — the confidential derived secret `s` — in the clear. This violates the core CKD security requirement that no single MPC node can compute `s`.

### Finding Description

The CKD protocol's confidentiality guarantee rests on ElGamal encryption: each participant computes `C_i = S_i + y_i * A` where `A = app_pk` is the app's fresh public key. The coordinator aggregates these into `C = msk * H(pk, app_id) + a * Y`, which hides `s = msk * H(pk, app_id)` behind the unknown scalar `a` (the app's secret key). Only the app, knowing `a`, can unmask `s`.

In `compute_signature_share()`:

```rust
// C <- S + y . A
let big_c = big_s + app_pk * y.0;   // line 174
``` [1](#0-0) 

If `app_pk` is the G1 identity element, then `app_pk * y.0 = identity`, so `big_c = big_s = x_i * H(pk, app_id)`. After Lagrange-weighted aggregation by the coordinator:

```
C = sum(lambda_i * C_i) = sum(lambda_i * x_i * H(pk, app_id)) = msk * H(pk, app_id)
```

The coordinator's output `CKDOutput { big_y, big_c }` now has `big_c = msk * H(pk, app_id)` — the raw BLS signature — with no blinding. A compromised coordinator can directly compute `s = HKDF(big_c)`.

The `ckd()` initialization block validates participant membership and coordinator presence, but performs **no check** that `app_pk` is a non-identity point: [2](#0-1) 

The `do_ckd_coordinator` function aggregates participant outputs without any point-validity check on `app_pk`: [3](#0-2) 

### Impact Explanation

The CKD security model explicitly states: *"No single node in the MPC network should be capable of computing `s`. This avoids key leakage in the case a single TEE is compromised."* [4](#0-3) 

With `app_pk = G1::identity()`, the coordinator — a single MPC node — directly observes `s = msk * H(pk, app_id)` in the aggregated `big_c` field. A compromised coordinator can then compute the app's confidential derived key `s = HKDF(msk * H(pk, app_id))` without the app's secret scalar `a`. This is a **Critical** impact: disclosure of a confidential derived secret to a single node, directly contradicting the stated security guarantee.

### Likelihood Explanation

The `app_pk` value originates from an on-chain CKD request submitted by the app. The developer contract is expected to verify that `A` is bound to the attestation report, but there is no requirement that `A != identity` — the identity point is a syntactically valid G1 element. A malicious app, a compromised developer contract, or any caller of the library that does not independently validate `app_pk` can trigger this path. The library provides no defense.

### Recommendation

Add an explicit check in `ckd()` (or in `compute_signature_share()`) that `app_pk` is not the group identity before proceeding:

```rust
if bool::from(app_pk.is_identity()) {
    return Err(InitializationError::BadParameters(
        "app_pk must not be the identity element".to_string(),
    ));
}
```

This mirrors the existing pattern used elsewhere in the codebase, such as the identity check on `big_r` in the robust ECDSA presign protocol: [5](#0-4) 

### Proof of Concept

1. Attacker (malicious app or compromised on-chain contract) submits a CKD request with `A = G1Projective::identity()`.
2. Each MPC node calls `ckd(..., app_pk = G1Projective::identity(), ...)`.
3. In `compute_signature_share()`, `big_c = big_s + identity * y = big_s = x_i * H(pk, app_id)`.
4. The coordinator aggregates: `norm_big_c = sum(lambda_i * x_i * H(pk, app_id)) = msk * H(pk, app_id)`.
5. The coordinator's `CKDOutput.big_c` equals `msk * H(pk, app_id)` — the unblinded BLS signature.
6. A compromised coordinator computes `s = HKDF(big_c)` directly, without needing the app's secret key `a`. [6](#0-5) [7](#0-6)

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

**File:** docs/confidential_key_derivation/confidential-key-derivation.md (L101-104)
```markdown
- $`s`$ must be deterministic as a function of $`\texttt{app\_id}`$ and only
  known by *app*
- No single node in the *MPC network* should be capable of computing $`s`$. This
avoids key leakage in the case a single TEE is compromised
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L226-232)
```rust
    if big_r
        .value()
        .ct_eq(&<Secp256K1Group as Group>::identity())
        .into()
    {
        return Err(ProtocolError::IdentityElement);
    }
```

**File:** src/confidential_key_derivation/mod.rs (L52-56)
```rust
    /// Takes a secret scalar and returns
    /// s <- C − a ⋅ Y = msk ⋅ H ( `app_id` )
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```
