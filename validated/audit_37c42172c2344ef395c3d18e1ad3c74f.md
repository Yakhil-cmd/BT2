The code confirms the vulnerability claim. Let me trace the exact path:

**`do_ckd_coordinator`** (lines 50–55) blindly aggregates every participant's `(big_y, big_c)` with no proof of correct formation:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

There is no DLEQ/ZK proof that `big_c_i = x_i·H(pk||app_id) + y_i·app_pk` and `big_y_i = y_i·G`. Compare this to other protocols in the same codebase (e.g., ECDSA triple generation) which DO attach `dlogeq` proofs and verify them before aggregating. The CKD path has no equivalent guard.

---

### Title
Missing Proof-of-Correct-Computation on Participant CKD Contributions Allows Any Single Participant to Corrupt the CKD Output — (`src/confidential_key_derivation/protocol.rs`)

### Summary
`do_ckd_coordinator` aggregates `(big_y_i, big_c_i)` from every participant with no structural or cryptographic consistency check. A single malicious participant can send arbitrary values — including `big_c = big_y` — causing the aggregated `(Y, C)` to encode an incorrect ElGamal ciphertext. The app's subsequent `unmask(app_sk)` call produces a garbage G1 point that fails BLS signature verification, permanently denying the app a valid derived key for as long as the malicious participant remains in the session.

### Finding Description
The CKD protocol is a single-round, all-participants-required aggregation. Each honest participant computes:

```
Y_i = y_i · G
S_i = x_i · H(pk || app_id)
C_i = S_i + y_i · app_pk
```

and sends `(λ_i·Y_i, λ_i·C_i)` to the coordinator.

The coordinator in `do_ckd_coordinator` receives these pairs and sums them: [1](#0-0) 

There is no check that the received `big_c_i` is correctly related to `big_y_i` and the participant's public key share. A malicious participant P_m can send any pair, e.g. `(R, R)` for a random G1 point `R`, and the coordinator will silently incorporate it. The resulting aggregated `C` will not equal `msk·H(pk||app_id) + app_sk·Y`, so `unmask(app_sk)` returns a wrong point.

For contrast, the ECDSA triple generation protocol in the same codebase attaches and verifies `dlogeq` proofs before aggregating analogous group-element contributions: [2](#0-1) 

No equivalent proof exists in the CKD path.

### Impact Explanation
The aggregated `CKDOutput` encodes an incorrect ElGamal ciphertext. The app calls `unmask(app_sk)` and obtains a G1 point that is not `msk·H(pk||app_id)`: [3](#0-2) 

BLS signature verification (`verify_signature`) will fail. The app cannot derive its confidential key. Because the protocol requires all `n` participants and the malicious participant cannot be identified from the output alone, the attack can be repeated on every CKD invocation, making the denial persistent.

Impact: **High — Corruption of CKD output / permanent denial of correct CKD output for honest parties.**

### Likelihood Explanation
- Requires only one compromised MPC node out of `n` — the lowest possible bar.
- The attack is a single-message substitution with no cryptographic work required.
- The malicious participant cannot be identified by the coordinator or the app from the corrupted output alone.
- The protocol is single-round, so there is no later round in which the bad contribution can be caught.

### Recommendation
Each participant must accompany their `(λ_i·Y_i, λ_i·C_i)` with a zero-knowledge proof of correct formation. Concretely, a DLEQ proof showing that the discrete log of `big_c_i - S_i` with respect to `app_pk` equals the discrete log of `big_y_i` with respect to `G` (i.e., both equal `y_i`) would suffice, provided `S_i = x_i·H(pk||app_id)` is also committed to via the participant's public key share. The coordinator must verify all proofs before aggregating, mirroring the `dlogeq::verify` pattern already used in the ECDSA triple generation protocol.

### Proof of Concept
```
Setup: n=3, participants P1 (honest), P2 (malicious), P3 (honest).
       app_sk, app_pk = random ElGamal keypair.
       Run DKG to obtain (x_1, x_2, x_3) with public key pk.

Attack:
  P2 intercepts its send_private call and instead sends CKDOutput { big_y: R, big_c: R }
  for a random G1 point R (e.g., R = random_scalar * G1::generator()).

Coordinator aggregates:
  Y = λ1·Y1 + R + λ3·Y3          (R replaces λ2·Y2)
  C = λ1·C1 + R + λ3·C3          (R replaces λ2·C2)

App computes:
  sig = C - app_sk * Y
      = (msk·H(pk||app_id) + app_sk·(λ1·Y1+λ3·Y3) + R)
        - app_sk·(λ1·Y1 + R + λ3·Y3)
      = msk·H(pk||app_id) + R - app_sk·R
      = msk·H(pk||app_id) + (1 - app_sk)·R   ≠ msk·H(pk||app_id)

assert verify_signature(&pk, &app_id, &sig).is_err()  // ✓ always fails
``` [4](#0-3) [5](#0-4)

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

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L483-491)
```rust
                if !dlogeq::verify(
                    &mut transcript.fork(b"dlogeq0", &from.bytes()),
                    statement,
                    their_phi_proof,
                )? {
                    return Err(ProtocolError::AssertionFailed(format!(
                        "dlogeq proof from {from:?} failed to verify"
                    )));
                }
```

**File:** src/confidential_key_derivation/mod.rs (L54-56)
```rust
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```
