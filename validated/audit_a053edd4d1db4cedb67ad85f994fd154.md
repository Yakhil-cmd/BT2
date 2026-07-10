### Title
Malicious CKD Participant Injects Arbitrary Share Contributions Without Proof of Correctness, Corrupting the Coordinator's Output - (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

In the Confidential Key Derivation (CKD) protocol, the coordinator role in `do_ckd_coordinator` collects `(big_y, big_c)` group-element pairs from every participant and blindly sums them into the final `CKDOutput`. No zero-knowledge proof or commitment binding is required to demonstrate that a participant's contribution is correctly formed from their actual signing share and a consistent randomness scalar. A single malicious participant can therefore send arbitrary group elements, causing the coordinator to output a corrupted `CKDOutput` that decrypts to garbage instead of the correct confidential derived key.

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

Each honest participant is supposed to compute and send:

```
norm_big_y = λ_i · y_i · G
norm_big_c = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)
```

where `x_i` is their signing share and `y_i` is a fresh random scalar. [2](#0-1) 

The coordinator accumulates these contributions with no verification that:

1. `norm_big_y` is a valid scalar multiple of the generator (i.e., `λ_i · y_i · G` for some `y_i`).
2. `norm_big_c` uses the **same** `y_i` as `norm_big_y`.
3. `norm_big_c` uses the participant's **actual** signing share `x_i` (bound to the public key committed during DKG).
4. The Lagrange coefficient `λ_i` was applied correctly.

No Schnorr proof, DLEQ proof, or commitment-then-reveal scheme is present anywhere in the CKD round. [3](#0-2) 

**Exploit path:**

A malicious participant `P_m` replaces its honest contribution `(norm_big_y_m, norm_big_c_m)` with arbitrary group elements `(A, B)` of its choice. The coordinator sums all contributions:

```
Y_final  = Σ_{i≠m} norm_big_y_i  +  A
C_final  = Σ_{i≠m} norm_big_c_i  +  B
```

The resulting `CKDOutput(Y_final, C_final)` is returned to the application. When the application unmasks it via `C_final − app_sk · Y_final`, the result is:

```
msk · H(pk ‖ app_id)  +  (B − app_sk · A)  +  error_terms
```

which is not equal to `msk · H(pk ‖ app_id)` unless `B = app_sk · A`, a condition the attacker cannot satisfy without knowing `app_sk`. The output is therefore an incorrect, unusable derived key.

The attacker's entry point is the private message channel from participant to coordinator in `do_ckd_participant`:

```rust
chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;
``` [4](#0-3) 

A malicious participant simply substitutes arbitrary values before calling `send_private`.

---

### Impact Explanation

**High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

The coordinator outputs a `CKDOutput` that is structurally valid (two group elements) but cryptographically wrong. Every honest party that trusts the coordinator's result will derive an incorrect confidential key. The application-level consumer (e.g., a TEE) will silently receive garbage, breaking the entire purpose of the CKD protocol. The attack requires only one malicious participant out of the full participant set, well within the documented threat model.

---

### Likelihood Explanation

Any participant in a CKD session can trigger this with zero cryptographic capability — they simply send two arbitrary group elements instead of their honest contribution. No privileged access, no leaked keys, and no external assumptions are required. The attack is deterministic and reproducible on every CKD invocation in which the malicious participant is included.

---

### Recommendation

Require each participant to accompany their `(norm_big_y, norm_big_c)` with a DLEQ (Discrete Log Equality) proof demonstrating that:

- `norm_big_y = λ_i · y_i · G`
- `norm_big_c = λ_i · x_i · H(pk ‖ app_id) + λ_i · y_i · app_pk`

and that the same `y_i` appears in both terms. The coordinator must verify all proofs before summing contributions and abort if any proof is invalid. This is the standard technique used in threshold ElGamal encryption and verifiable secret sharing to prevent malicious share substitution — the exact analog of requiring a priority-queue / TWAP in the funding-rate context to prevent arbitrary price injection.

---

### Proof of Concept

**Setup:** 3 participants `{P1, P2, P3}`, threshold 2, coordinator = `P1`. Honest `P2` and `P3` compute correct shares. Malicious `P1` (coordinator) or malicious `P2` (participant) sends crafted values.

**Malicious participant path (P2 is attacker):**

1. `P2` intercepts the call to `compute_signature_share` and instead constructs `(A, B)` as two random group elements unrelated to its signing share.
2. `P2` calls `chan.send_private(waitpoint, coordinator, &(A, B))`.
3. The coordinator (`P1`) receives `(A, B)` from `P2` and sums it with the honest contributions from `P3` and itself — no error is raised.
4. The coordinator outputs `CKDOutput(Y_final, C_final)` where `C_final − app_sk · Y_final ≠ msk · H(pk ‖ app_id)`.
5. The application receives a structurally valid but cryptographically incorrect derived key with no indication of failure. [5](#0-4)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L29-31)
```rust
    let waitpoint = chan.next_waitpoint();
    chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;

```

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
