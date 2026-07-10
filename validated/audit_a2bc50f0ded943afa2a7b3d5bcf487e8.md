### Title
Malicious CKD Participant Can Corrupt Derived Key Output Without Detection - (File: `src/confidential_key_derivation/protocol.rs`)

### Summary
The CKD coordinator blindly aggregates participant-provided shares `(norm_big_y, norm_big_c)` without any cryptographic proof of correct computation. This is the direct analog to M-09: the system implicitly relies on each participant's off-protocol local computation being honest, with no in-protocol mechanism to verify or audit those contributions. A single malicious participant can send arbitrary group elements, causing the coordinator to produce a corrupted `CKDOutput` that is silently accepted.

### Finding Description
In `do_ckd_coordinator` (`src/confidential_key_derivation/protocol.rs`, lines 50–55), the coordinator receives each participant's `CKDOutput` and unconditionally sums the values:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

The correct per-participant computation is defined in `compute_signature_share` (lines 148–181):

```
big_y  = y_i * G                          (random blinding term)
big_s  = x_i * H(pk || app_id)            (key-share contribution)
big_c  = big_s + y_i * app_pk             (masked key share)
norm_big_y = lambda_i * big_y
norm_big_c = lambda_i * big_c
```

There is no zero-knowledge proof, commitment, or any other cryptographic binding that forces a participant to use their actual signing share `x_i` when constructing `big_c`. The coordinator has no way to distinguish a correctly computed `(norm_big_y, norm_big_c)` from an arbitrary pair of group elements. This is the exact structural analog to M-09: the protocol implicitly relies on an unauditable, unverifiable off-protocol computation by each participant.

The attack path is:

1. Malicious participant `P_m` is a valid member of the CKD participant list.
2. Instead of computing `(norm_big_y, norm_big_c)` per the protocol, `P_m` sends arbitrary group elements, e.g., `(G, G)`.
3. The coordinator sums all contributions including `P_m`'s corrupted values (lines 53–54).
4. The resulting `CKDOutput` (line 56) contains wrong `(Y, C)` values.
5. The `unmask` operation on this output produces a confidential key that does not equal `msk * H(pk || app_id)`.
6. No participant, including the coordinator, can detect the corruption.

### Impact Explanation
**High — Corruption of CKD outputs.** The coordinator produces and returns a `CKDOutput` whose `unmask` result is a wrong group element, not the intended confidential derived key. Honest parties accept this output as valid because there is no in-protocol integrity check. The derived key is permanently unusable or silently wrong, matching the allowed impact: *"Corruption of CKD outputs so honest parties accept unusable cryptographic outputs."*

### Likelihood Explanation
Any single participant in the CKD protocol can execute this attack. No leaked keys, no privileged access, and no external assumptions are required — only the ability to participate in the protocol, which is the baseline attacker capability. The attack requires sending two arbitrary group elements instead of the correct ones, which is trivially achievable by any library caller.

### Recommendation
Each participant should accompany their `(norm_big_y, norm_big_c)` with a zero-knowledge proof of correct construction. Concretely, a DLEQ (Discrete Log Equality) proof can prove that `norm_big_c - norm_big_y * (app_pk / G)` lies on the correct coset determined by the participant's public key share, without revealing the private share. The coordinator must verify all such proofs before summing contributions and must abort if any proof fails.

### Proof of Concept
```
Setup: 3 participants [P1, P2, P3], coordinator = P1.
       Honest key shares: x1, x2, x3 with public key pk = (x1+x2+x3)*G2.
       app_id = b"test", app_pk = sk_app * G1.

Attack:
  P3 (malicious) sends (big_y=G1, big_c=G1) instead of correct values.

Coordinator aggregates:
  Y_total  = lambda1*y1*G1 + lambda2*y2*G1 + G1          ← corrupted
  C_total  = lambda1*(x1*H+y1*A) + lambda2*(x2*H+y2*A) + G1  ← corrupted

unmask(app_sk):
  result = C_total - app_sk * Y_total
         ≠ msk * H(pk || app_id)

Expected: msk * H(pk || app_id)
Actual:   wrong group element, silently accepted.
``` [1](#0-0) [2](#0-1)

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
