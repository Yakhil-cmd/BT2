### Title
Missing Validation of Participant CKD Share Contributions Allows Malicious Participant to Corrupt Confidential Key Derivation Output - (File: src/confidential_key_derivation/protocol.rs)

### Summary
The CKD coordinator blindly aggregates `(big_y, big_c)` group elements received from all participants with no cryptographic validation. A single malicious participant can inject arbitrary curve points, causing the coordinator to output a corrupted `CKDOutput` that honest parties accept as valid.

### Finding Description
In `do_ckd_coordinator` (`src/confidential_key_derivation/protocol.rs`, lines 35–57), the coordinator collects one `CKDOutput` per participant via `recv_from_others` and unconditionally adds each received `big_y` and `big_c` into the running sums:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

`recv_from_others` (`src/protocol/helpers.rs`, lines 6–26) only enforces that the sender is a known participant and that each participant sends exactly one message. It performs no validation of the message payload:

```rust
while !seen.full() {
    let (from, msg) = chan.recv(waitpoint).await?;
    if seen.put(from) {
        messages.push((from, msg));
    }
}
```

The honest computation each participant is supposed to perform is:

```
big_y  = y * G
big_c  = x_i * H(pk, app_id) + y * app_pk
norm_big_y = lambda_i * big_y
norm_big_c = lambda_i * big_c
```

(`src/confidential_key_derivation/protocol.rs`, lines 148–181)

There is no commitment, zero-knowledge proof, or consistency check binding the received `(big_y, big_c)` to the participant's committed public key share or to any previously broadcast value. A malicious participant can substitute any pair of group elements — including the identity, a negation of an honest participant's contribution, or an attacker-chosen point — and the coordinator will accept and aggregate them without error.

### Impact Explanation
The final `CKDOutput` is `(sum_norm_big_y, sum_norm_big_c)`. The client unmasks it as:

```
confidential_key = big_c - app_sk * big_y  =  msk * H(pk, app_id)
```

If a malicious participant injects a crafted `delta_c` into `big_c` and a corresponding `delta_y` into `big_y`, the client recovers:

```
(sum_big_c + delta_c) - app_sk * (sum_big_y + delta_y)
= msk * H(pk, app_id) + (delta_c - app_sk * delta_y)
```

By choosing `delta_c` and `delta_y` freely (e.g., `delta_y = 0`, `delta_c = arbitrary`), the attacker shifts the derived confidential key to any attacker-chosen value. Honest parties — the coordinator and the client — accept this corrupted output as the legitimate CKD result, with no indication of tampering.

This matches the allowed impact: **High — Corruption of CKD outputs so honest parties accept unusable or attacker-controlled cryptographic outputs.**

### Likelihood Explanation
- Any single participant in the CKD session can mount this attack; no threshold of colluders is required.
- The attack requires only that the malicious participant send a crafted `CKDOutput` struct, which is a standard serialized message.
- There is no out-of-band mechanism in the protocol to detect the manipulation.
- Likelihood is **High**.

### Recommendation
Bind each participant's `(big_y, big_c)` contribution to their committed public key share using a zero-knowledge proof of correct construction. Concretely, each participant should prove in zero-knowledge that:

1. `big_y = y * G` for some scalar `y` they know (a Schnorr proof of discrete log).
2. `big_c = x_i * H(pk, app_id) + y * app_pk`, where `x_i` is consistent with the participant's public verification share from the DKG output (a proof of correct ElGamal encryption).

The coordinator should verify these proofs before aggregating contributions. This mirrors the pattern already used in `do_keyshare` (`src/dkg.rs`, lines 452–469), where every participant's commitment is verified via `verify_proof_of_knowledge` and `verify_commitment_hash` before being accepted.

### Proof of Concept

**Setup:** 3 participants `P1, P2, P3`; `P3` is malicious. `P3` is the coordinator.

**Attack steps:**

1. `P1` and `P2` honestly compute and send their `(norm_big_y_i, norm_big_c_i)` to the coordinator `P3`.
2. `P3` (coordinator) computes its own honest share but, instead of sending the correct `(norm_big_y_3, norm_big_c_3)` to itself, substitutes `(G1::identity(), attacker_point)` where `attacker_point` is any chosen `G1` element.
3. In `do_ckd_coordinator`, `P3` aggregates:
   ```
   norm_big_y = norm_big_y_1 + norm_big_y_2 + G1::identity()
   norm_big_c = norm_big_c_1 + norm_big_c_2 + attacker_point
   ```
4. The returned `CKDOutput` has `big_c` shifted by `attacker_point - norm_big_c_3`.
5. The client calls `ckd_output.unmask(app_sk)` and obtains a value that is not `msk * H(pk, app_id)`, with no error raised anywhere in the protocol.

The root cause is exclusively in `do_ckd_coordinator` at `src/confidential_key_derivation/protocol.rs` lines 50–55, where received shares are summed without any validity check. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L50-55)
```rust
    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
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

**File:** src/protocol/helpers.rs (L19-24)
```rust
    while !seen.full() {
        let (from, msg) = chan.recv(waitpoint).await?;
        if seen.put(from) {
            messages.push((from, msg));
        }
    }
```

**File:** src/confidential_key_derivation/mod.rs (L54-56)
```rust
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```
