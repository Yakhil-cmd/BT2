### Title
Missing Cryptographic Verification of Participant Shares in CKD Protocol Allows Malicious Participant to Corrupt Derived Key Output - (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The CKD coordinator (`do_ckd_coordinator`) aggregates `(big_y, big_c)` shares from all participants with no cryptographic proof that each share is correctly computed relative to the participant's actual signing share and the public parameters. A single malicious participant can send arbitrary group elements, causing the coordinator to output a corrupted `CKDOutput` that the TEE application cannot use to recover the correct confidential key.

---

### Finding Description

**Root cause — `do_ckd_coordinator`, lines 50–55:**

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [1](#0-0) 

Each participant is supposed to send:

- `big_y_i = λ_i · y_i · G`
- `big_c_i = λ_i · (x_i · H(pk ‖ app_id) + y_i · A)`

where `x_i` is the participant's private signing share, `y_i` is a fresh random scalar, and `A` is the app's public key. [2](#0-1) 

The coordinator has all the public information needed to define what a valid share *should* look like (`G`, `A`, `H(pk ‖ app_id)`, and each participant's public key share `x_i · G`), yet it performs **zero cryptographic verification** before adding the received values into the aggregate. No discrete-log equality proof, no Chaum-Pedersen proof, nothing.

The CKD protocol has **no threshold**: it requires every participant to contribute (`participants.lagrange` is computed over the full set), so a single malicious participant is sufficient to corrupt the output. [3](#0-2) 

**Exploit path:**

1. Malicious participant `P_m` is a legitimate member of the CKD participant list.
2. Instead of computing `(big_y_m, big_c_m)` correctly, `P_m` sends arbitrary group elements, e.g. `(G, G)`.
3. `do_ckd_coordinator` adds them into the aggregate without any check.
4. The coordinator outputs `CKDOutput { big_y: Y', big_c: C' }` where `Y'` and `C'` are corrupted.
5. The TEE application calls `ckd_output.unmask(app_sk)` and computes `S' = C' − a·Y' ≠ msk · H(pk ‖ app_id)`.
6. The TEE application derives a wrong key for `app_id`. [4](#0-3) 

---

### Impact Explanation

**High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

The TEE application receives a structurally valid `CKDOutput` (two G1 points) but the unmasked value `S'` is not `msk · H(pk ‖ app_id)`. The derived confidential key is wrong and non-deterministic (it depends on the attacker's chosen garbage values). Because the CKD protocol is deterministic by design (same `app_id` must always yield the same key), a corrupted run permanently breaks the key derivation guarantee for that `app_id` until a fresh, honest run is completed. The honest coordinator and all honest participants have no way to detect the corruption at the protocol level.

---

### Likelihood Explanation

Any single participant in the CKD session can perform this attack. No special cryptographic knowledge is required — the attacker only needs to deviate from the protocol by sending two arbitrary G1 points. Because the protocol requires all `N` participants (no threshold), the attack surface is every participant, not just a coalition. The attacker needs no leaked keys or external assumptions; being a registered participant is sufficient.

---

### Recommendation

Each participant must accompany their `(big_y_i, big_c_i)` with a zero-knowledge proof of correct construction. Concretely, a Chaum-Pedersen / discrete-log-equality proof can show:

- `big_y_i = λ_i · y_i · G` (dlog proof over `G`)
- `big_c_i − λ_i · vk_share_i · H(pk ‖ app_id) = λ_i · y_i · A` (dlogeq proof: same `y_i` used in both `big_y_i` and the `y·A` term of `big_c_i`)

The coordinator must verify all proofs before aggregating. The existing `dlog` and `dlogeq` proof infrastructure in `src/crypto/proofs/` already provides the necessary primitives.



---

### Proof of Concept

```
Setup:
  participants = [P1 (coordinator), P2, P3]
  threshold = 3 (all must participate)
  app_id = b"test-app"
  app_sk = random scalar a
  app_pk = a * G1

Honest run:
  Each Pi sends (lambda_i * y_i * G, lambda_i * (x_i * H + y_i * A))
  Coordinator aggregates → (Y, C)
  App computes S = C - a*Y = msk * H  ✓

Attack (P2 is malicious):
  P2 sends (big_y_2, big_c_2) = (G1::generator(), G1::generator())
    instead of correctly computed shares
  Coordinator aggregates without verification:
    Y' = lambda_1*y_1*G + G + lambda_3*y_3*G
    C' = lambda_1*(x_1*H+y_1*A) + G + lambda_3*(x_3*H+y_3*A)
  App computes S' = C' - a*Y'
    = msk*H + G - a*G   (simplified)
    ≠ msk*H
  TEE app derives wrong key for "test-app" — output is corrupted.
```

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L35-58)
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

**File:** src/confidential_key_derivation/mod.rs (L54-56)
```rust
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```
