### Title
Missing Proof of Correct Computation in CKD Protocol Allows Malicious Participant to Corrupt Derived Key Output — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary
The CKD coordinator blindly sums participant contributions `(norm_big_y, norm_big_c)` without any proof that each participant computed their share using their actual committed private key share. A single malicious participant can send arbitrary group elements, corrupting the final derived key output that the coordinator accepts.

---

### Finding Description

**Root cause — missing constraint on participant contribution:**

In `do_ckd_coordinator` the coordinator receives a `CKDOutput` from every other participant and unconditionally adds the two group elements together: [1](#0-0) 

The honest computation performed by every participant in `compute_signature_share` is:

```
norm_big_y = lambda_i * y_i * G
norm_big_c = lambda_i * (x_i * H(pk, app_id) + y_i * app_pk)
```

where `x_i` is the participant's private share and `y_i` is a fresh random scalar. [2](#0-1) 

There is **no proof** attached to the message sent by `do_ckd_participant`: [3](#0-2) 

A malicious participant can replace their honest `(norm_big_y, norm_big_c)` with any two arbitrary group elements. The coordinator has no mechanism to detect this substitution and will incorporate the forged values into the final `CKDOutput`.

**Analogy to the external report:**
The external report describes a missing boolean constraint `isNeg * (1 - isNeg) = 0` that allows an attacker to set `isNeg` to an arbitrary field element, bypassing the jump-destination constraint. Here, the missing constraint is a proof of correct computation: there is no enforcement that `norm_big_c` was computed using the participant's actual private share `x_i`. Both are cases where a value that must satisfy a specific algebraic relation is left entirely unconstrained, allowing an attacker to inject an arbitrary element.

**The fix already exists in the codebase but is unused:**
The `dlogeq` proof module (`src/crypto/proofs/dlogeq.rs`) proves exactly the required relation: that the discrete log of one point under generator `G` equals the discrete log of another point under an alternate generator. A participant could use it to prove knowledge of `y_i` such that `norm_big_y / lambda_i = y_i * G` and `(norm_big_c / lambda_i − x_i * H(pk, app_id)) = y_i * app_pk`. Its absence from the CKD protocol is the missing constraint. [4](#0-3) 

---

### Impact Explanation

The coordinator sums all contributions and outputs `CKDOutput::new(norm_big_y, norm_big_c)`. The derived confidential key is computed as `C − app_sk * Y`. With a corrupted contribution, the coordinator outputs an incorrect key that does not equal `msk * H(pk, app_id)`. The coordinator and any downstream TEE application relying on the derived key will accept this incorrect output without any indication of corruption.

This matches the allowed impact: **High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

---

### Likelihood Explanation

Any single malicious participant in the CKD protocol can trigger this. The protocol requires all `n` participants to contribute, and a single corrupted contribution corrupts the entire sum. No special privileges, leaked keys, or external assumptions are required beyond being a registered protocol participant.

---

### Recommendation

Require each participant to attach a `dlogeq` proof to their `(norm_big_y, norm_big_c)` message, proving knowledge of `y_i` such that:

- `norm_big_y / lambda_i = y_i * G`
- `(norm_big_c / lambda_i − x_i * H(pk, app_id)) = y_i * app_pk`

The coordinator must verify this proof before incorporating any contribution. The `dlogeq::verify` function in `src/crypto/proofs/dlogeq.rs` already implements the required verification logic. [4](#0-3) 

---

### Proof of Concept

1. Set up a CKD protocol with 3 participants `(P1, P2, P3)`, where `P3` is malicious and `P1` is the coordinator.
2. `P3` sends `(random_G1_point_A, random_G1_point_B)` to `P1` instead of the correctly computed `(norm_big_y_3, norm_big_c_3)`.
3. `P1` receives contributions from `P2` (honest) and `P3` (malicious), sums them with its own, and outputs a `CKDOutput`.
4. Calling `ckd_output.unmask(app_sk)` on the result will not equal `msk * H(pk, app_id)`, demonstrating that the coordinator accepted a corrupted derived key.

The entry path is direct: `ckd()` → `run_ckd_protocol()` → `do_ckd_coordinator()` → `recv_from_others()` → unconstrained addition. [5](#0-4)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L27-32)
```rust
    let (norm_big_y, norm_big_c) =
        compute_signature_share(participants, me, key_pair, app_id, app_pk, rng)?;
    let waitpoint = chan.next_waitpoint();
    chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;

    Ok(None)
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

**File:** src/confidential_key_derivation/protocol.rs (L159-181)
```rust
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

**File:** src/crypto/proofs/dlogeq.rs (L139-163)
```rust
pub fn verify<C: Ciphersuite>(
    transcript: &mut Transcript,
    statement: Statement<'_, C>,
    proof: &Proof<C>,
) -> Result<bool, ProtocolError>
where
    Element<C>: ConstantTimeEq,
{
    if statement.generator1.ct_eq(&C::Group::identity()).into() {
        return Err(ProtocolError::IdentityElement);
    }

    transcript.message(NEAR_DLOGEQ_STATEMENT_LABEL, &statement.encode()?);

    let (phi0, phi1) = statement.phi(&proof.s.0);
    let big_k0 = phi0 - *statement.public0 * proof.e.0;
    let big_k1 = phi1 - *statement.public1 * proof.e.0;

    let enc = encode_two_points::<C>(&big_k0, &big_k1)?;

    transcript.message(NEAR_DLOGEQ_COMMITMENT_LABEL, &enc);
    let mut rng = transcript.challenge_then_build_rng(NEAR_DLOGEQ_CHALLENGE_LABEL);
    let e = frost_core::random_nonzero::<C, _>(&mut rng);

    Ok(e == proof.e.0)
```
