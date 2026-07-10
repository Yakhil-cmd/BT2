### Title
Malicious Participant Can Corrupt CKD Output by Supplying Arbitrary `app_pk` — (`File: src/confidential_key_derivation/protocol.rs`)

### Summary

In the Confidential Key Derivation (CKD) protocol, each participant independently supplies `app_pk` (the application's public key) as a local, caller-controlled parameter. The coordinator aggregates participant contributions by blindly summing them with no cross-participant validation that all parties used the same `app_pk`. A single malicious participant can supply an arbitrary `app_pk` to corrupt the final CKD output, causing honest parties to accept a cryptographically unusable derived key.

### Finding Description

The `ckd()` entry point accepts `app_pk: PublicKey` as a caller-supplied argument with no protocol-level enforcement that all participants agree on the same value. [1](#0-0) 

Each participant's share is computed in `compute_signature_share()` as:

```
big_c = big_s + app_pk * y
```

where `big_s = x_i * H(pk || app_id)` and `y` is a fresh random scalar. [2](#0-1) 

The coordinator then aggregates all participant contributions by simple addition:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [3](#0-2) 

There is no broadcast, commitment, or consistency check ensuring that the `app_pk` used by each participant matches the others. A malicious participant `j` can locally invoke `ckd()` with `app_pk' ≠ app_pk`, causing their contribution to `norm_big_c` to be:

```
λ_j * (x_j * H(pk || app_id) + y_j * app_pk')
```

instead of the correct:

```
λ_j * (x_j * H(pk || app_id) + y_j * app_pk)
```

The coordinator sums this corrupted share with the honest shares and outputs the result as the final `CKDOutput`. The unmask operation `C - app_sk * Y` will not recover `msk * H(pk || app_id)`, producing a garbage derived key.

### Impact Explanation

This is a **High** impact finding: **Corruption of CKD outputs so honest parties accept unusable cryptographic outputs**. The coordinator outputs a `CKDOutput` that is structurally valid (non-null group elements) but cryptographically incorrect. Any downstream consumer (e.g., a TEE application) that calls `ckd_output.unmask(app_sk)` will receive a value that does not equal the intended `msk * H(pk || app_id)`, silently breaking the confidential key derivation guarantee. The corruption is undetectable by the coordinator or any honest participant.

### Likelihood Explanation

Any participant in the protocol can trigger this. The `app_pk` parameter is passed locally by each party with no out-of-band or in-protocol agreement mechanism. A single compromised or malicious node among the `n` participants is sufficient. The attacker does not need to break any cryptographic primitive — they only need to pass a different group element as `app_pk` when calling `ckd()`.

### Recommendation

Before participants send their shares to the coordinator, all parties must commit to and verify a common `app_pk`. Concretely:

1. **Broadcast `app_pk` in Round 1**: Each participant broadcasts a hash commitment to their `app_pk` alongside the existing session-ID broadcast in `do_keyshare`-style protocols.
2. **Verify consistency**: Each participant (including the coordinator) checks that all received `app_pk` commitments match their own before computing or accepting any share.
3. Alternatively, treat `app_pk` as a protocol-level constant derived deterministically from `app_id` and the shared public key, removing it as a free caller parameter entirely.

### Proof of Concept

1. Honest participants `{1, 2, 3}` run `ckd()` with the correct `app_pk = G * app_sk`.
2. Malicious participant `2` instead calls `ckd()` with `app_pk' = identity` (the group identity element).
3. Participant `2`'s contribution becomes `λ_2 * (x_2 * H(pk || app_id) + y_2 * 0) = λ_2 * x_2 * H(pk || app_id)` — the blinding term `y_2 * app_pk` is eliminated.
4. The coordinator sums all three contributions. The resulting `norm_big_c` is:
   ```
   Σ_{i≠2} λ_i*(x_i*H + y_i*app_pk) + λ_2*(x_2*H)
   ```
5. `ckd_output.unmask(app_sk)` computes `C - app_sk * Y`, which does **not** equal `msk * H(pk || app_id)`.
6. The coordinator outputs a corrupted `CKDOutput` with no error, and no participant detects the inconsistency. [4](#0-3)

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

**File:** src/confidential_key_derivation/protocol.rs (L66-74)
```rust
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
