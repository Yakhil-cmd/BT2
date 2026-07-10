### Title
Malicious CKD Coordinator Has Unilateral, Unverifiable Control Over Derived Key Output — (`File: src/confidential_key_derivation/protocol.rs`)

---

### Summary

The CKD protocol designates a single coordinator who is the **sole recipient of the combined output**. Non-coordinator participants send their encrypted shares to the coordinator and unconditionally return `Ok(None)`. There is no commitment scheme, ZK proof, or broadcast-verification step that binds the coordinator to honest aggregation. A malicious coordinator can produce an arbitrary or corrupted `CKDOutput` without any participant being able to detect it.

---

### Finding Description

In `do_ckd_coordinator` the coordinator collects each participant's `(norm_big_y, norm_big_c)` share and sums them:

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

Non-coordinator participants simply send their share and return `None`:

```rust
chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;
Ok(None)
``` [2](#0-1) 

There is no step where:
- participants commit to their shares before revealing them,
- the coordinator broadcasts the combined result back for cross-verification,
- any ZK proof binds the coordinator's aggregation to the received inputs.

The public entry point `ckd()` contains no documentation of the trust assumption that the coordinator must be honest: [3](#0-2) 

The `compute_signature_share` function shows each participant's contribution encodes their private share `x_i` inside `C_i = λ_i*(x_i*H(pk,app_id) + y_i*app_pk)`, which is sent exclusively to the coordinator: [4](#0-3) 

---

### Impact Explanation

A malicious coordinator can:

1. **Drop one or more participants' shares** — the summed `(Y, C)` no longer encodes `msk·H(pk,app_id)`, so the application derives a wrong confidential key.
2. **Add an arbitrary offset** to `norm_big_c` or `norm_big_y` — same result: the unmasked value `C − Y·app_sk` is wrong.
3. **Return a completely fabricated `CKDOutput`** — the application silently accepts it.

In all cases the application calls `ckd_output.unmask(app_sk)` and obtains a value that is not `msk·H(pk,app_id)`. No honest participant can detect the manipulation because they all returned `None` and hold no reference output.

**Mapped impact**: *High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.*

---

### Likelihood Explanation

The coordinator is any participant designated at call time — there is no cryptographic barrier to becoming coordinator. In a deployment where the coordinator role rotates or is chosen by an external scheduler, a single compromised or malicious node that is assigned coordinator can silently corrupt every CKD session it runs. The attack requires no leaked keys, no cryptographic break, and no external dependency — only the ability to be the coordinator.

---

### Recommendation

1. **Commit-then-reveal**: Before sending shares, each participant broadcasts a hash commitment to their `(norm_big_y, norm_big_c)`. After the coordinator publishes the combined output, participants verify their committed values appear in the sum.
2. **Coordinator re-broadcasts the combined output**: The coordinator sends `(Y, C)` back to all participants; each participant verifies that `Y` contains their own `λ_i·y_i·G` contribution (which they know) by checking `Y − own_contribution` equals the expected partial sum from the remaining parties.
3. **ZK proof of correct aggregation**: Require the coordinator to provide a proof that the output is the honest sum of the received shares.
4. **At minimum, document the trust assumption** explicitly in the `ckd()` API: the coordinator must be trusted to aggregate honestly, and a malicious coordinator can silently corrupt the derived key.

---

### Proof of Concept

```
Setup: participants = [A (coordinator), B, C], threshold = 2

1. B computes (norm_big_y_B, norm_big_c_B) and sends to A.
2. C computes (norm_big_y_C, norm_big_c_C) and sends to A.
3. A (malicious) ignores received shares entirely.
   A fabricates: norm_big_y = G (generator), norm_big_c = G (generator).
4. A returns CKDOutput::new(G, G).
5. Application calls ckd_output.unmask(app_sk):
   result = G - G * app_sk  ≠  msk * H(pk, app_id)
6. B and C both returned Ok(None) — neither can detect the manipulation.
   The application silently uses the wrong derived key.
```

The root cause is the absence of any binding between the coordinator's output and the shares it received, directly analogous to the TangleswapFactory centralization risk where a single privileged party can unilaterally alter protocol-critical state with no on-chain enforcement of honest behavior.

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L29-32)
```rust
    let waitpoint = chan.next_waitpoint();
    chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;

    Ok(None)
```

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

**File:** src/confidential_key_derivation/protocol.rs (L60-74)
```rust
/// Runs the confidential key derivation protocol.
/// This exact same function is called for both
/// a coordinator and a normal participant.
///
/// Depending on whether the current participant is a coordinator or not,
/// runs the signature protocol as either a participant or a coordinator.
pub fn ckd(
    participants: &[Participant],
    coordinator: Participant,
    me: Participant,
    key_pair: KeygenOutput,
    app_id: impl Into<AppId>,
    app_pk: PublicKey,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = CKDOutputOption>, InitializationError> {
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
