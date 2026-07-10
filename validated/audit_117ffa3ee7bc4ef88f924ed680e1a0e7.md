### Title
Unvalidated Participant-Controlled CKD Contributions Allow Malicious Participant to Corrupt Derived Key Output - (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

In `do_ckd_coordinator`, the coordinator blindly accumulates `(big_y, big_c)` values sent by each participant with no proof of correctness. A single malicious participant can send arbitrary group elements, causing the coordinator to output a structurally valid but cryptographically wrong `CKDOutput`. The client will silently unmask a garbage key, permanently corrupting the CKD result for that invocation.

---

### Finding Description

The CKD protocol is a two-role protocol: each participant computes a share `(norm_big_y, norm_big_c)` and sends it privately to the coordinator. The coordinator sums all shares and returns the aggregate `CKDOutput`.

The honest computation per participant is:

```
y  ← random scalar
Y  = y · G
S  = x_i · H(pk ‖ app_id)
C  = S + y · app_pk
norm_big_y = λ_i · Y
norm_big_c = λ_i · C
```

The coordinator's aggregation in `do_ckd_coordinator` is:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
Ok(Some(ckd_output))
``` [1](#0-0) 

There is **no proof of knowledge, no consistency check, and no verification** that the received `big_y` and `big_c` satisfy the required algebraic relation `big_c = x_i · H(pk ‖ app_id) + (big_y / λ_i) · app_pk`. The coordinator cannot distinguish a legitimate share from an arbitrary pair of group elements.

Compare this to the honest participant path, which correctly computes the share: [2](#0-1) 

No part of that computation is committed to or proven to the coordinator.

---

### Impact Explanation

**High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

The client unmasks the output as:

```
S_derived = C_final − a · Y_final
```

where `a` is the app's secret key. If a malicious participant substitutes `(big_y', big_c')` for their legitimate share, the final output becomes:

```
Y_final = Y_honest + big_y'
C_final = C_honest + big_c'
S_derived = (msk · H(pk ‖ app_id)) + (big_c' − a · big_y')
```

The additive error term `(big_c' − a · big_y')` is undetectable by the coordinator (who does not know `a`) and undetectable by the client (who has no reference value for `msk · H(pk ‖ app_id)`). The client silently receives a wrong derived key. Unlike the ECDSA signing paths — which include a final `sig.verify(...)` guard that catches corrupted shares — the CKD coordinator has **no analogous verification step**. [3](#0-2) [4](#0-3) 

The CKD coordinator has no equivalent check: [5](#0-4) 

---

### Likelihood Explanation

**High.** Any single participant in the CKD protocol can trigger this. No special privilege is required beyond being a listed participant. The attack requires only sending two arbitrary `G1` points instead of the honest values — a trivial modification for a participant who controls their own process. The corruption is silent and produces no protocol-level error.

---

### Recommendation

Each participant must accompany their `(norm_big_y, norm_big_c)` with a zero-knowledge proof of correct formation. Concretely, the participant must prove in zero-knowledge that:

1. They know a scalar `y` such that `big_y = λ_i · y · G`.
2. They know their secret share `x_i` (consistent with the public key share `X_i = x_i · G_2`) such that `big_c = λ_i · (x_i · H(pk ‖ app_id) + y · app_pk)`.

A standard Sigma protocol (Schnorr-style proof of discrete log equality) over the BLS12-381 `G1` group suffices for (1). For (2), a proof of linear relation over `G1` is needed, binding `x_i` to the publicly known `X_i`.

The coordinator must verify all proofs before accumulating any contribution, and abort if any proof fails, identifying the malicious participant.

---

### Proof of Concept

1. A CKD session is initiated with participants `[P1, P2, P3]` and coordinator `P1`.
2. `P2` is malicious. Instead of computing the honest `(norm_big_y, norm_big_c)`, it sends `(G, G)` (the generator point for both fields).
3. The coordinator in `do_ckd_coordinator` receives `P2`'s message and executes:
   ```rust
   norm_big_y += participant_output.big_y(); // adds G
   norm_big_c += participant_output.big_c(); // adds G
   ``` [6](#0-5) 
4. The coordinator returns `CKDOutput { big_y: Y_honest + G, big_c: C_honest + G }` with no error.
5. The client calls `ckd_output.unmask(app_sk)`:
   ```rust
   pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
       self.big_c - self.big_y * secret_scalar
   }
   ``` [7](#0-6) 
6. The result is `msk · H(pk ‖ app_id) + G − app_sk · G = msk · H(pk ‖ app_id) + (1 − app_sk) · G`, which is a wrong key. No error is raised anywhere in the protocol.

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L50-57)
```rust
    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
    Ok(Some(ckd_output))
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

**File:** src/ecdsa/robust_ecdsa/sign.rs (L159-163)
```rust
    if !sig.verify(&public_key, &msg_hash) {
        return Err(ProtocolError::AssertionFailed(
            "signature failed to verify".to_string(),
        ));
    }
```

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L129-133)
```rust
    if !sig.verify(&public_key, &msg_hash) {
        return Err(ProtocolError::AssertionFailed(
            "signature failed to verify".to_string(),
        ));
    }
```

**File:** src/confidential_key_derivation/mod.rs (L54-56)
```rust
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```
