### Title
Malicious CKD Participant Can Send Arbitrary Shares to Corrupt the Derived Key Output - (File: src/confidential_key_derivation/protocol.rs)

### Summary
In the CKD protocol, `do_ckd_coordinator` receives `(big_y, big_c)` shares from every participant and sums them with no proof-of-correctness check. A single malicious participant can substitute arbitrary group elements for their honest share, silently corrupting the final `CKDOutput` and causing the client to unmask an incorrect, attacker-influenced derived key.

### Finding Description
`do_ckd_coordinator` (lines 35–58 of `src/confidential_key_derivation/protocol.rs`) iterates over messages from all other participants and unconditionally accumulates their reported `big_y` and `big_c` values:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
``` [1](#0-0) 

The protocol requires each participant to compute:
- `big_y_i = λ_i · y_i · G`
- `big_c_i = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)`

as implemented in `compute_signature_share`: [2](#0-1) 

No zero-knowledge proof, commitment, or consistency check is performed to verify that the received pair was honestly derived from the participant's actual private key share `x_i` and a valid random nonce `y_i`. A malicious participant can send any two valid `G1` points instead, and the coordinator has no mechanism to detect the substitution. The `do_ckd_participant` path computes the values correctly, but a malicious implementation can bypass it entirely and write arbitrary bytes to the channel. [3](#0-2) 

### Impact Explanation
A single malicious participant corrupts the aggregated `(Y, C)`. The client unmasks via `C − a · Y` (where `a` is the app secret key): [4](#0-3) 

With a corrupted `(Y, C)`, the result is `msk · H(pk ‖ app_id) + (big_c′ − a · big_y′)`, which is not the correct confidential derived key. The honest coordinator and client receive no error — `CKDOutput` is returned normally. This matches the allowed impact: **High: Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

### Likelihood Explanation
Any single participant in the CKD protocol can mount this attack. No special privileges, leaked keys, or cryptographic breaks are required. The attacker simply sends two arbitrary `G1` points instead of their honest share. The attack is silent — the coordinator returns a `CKDOutput` with no error, and the client receives a plausible-looking but incorrect derived key with no indication of tampering.

### Recommendation
Add a Sigma-protocol (or equivalent) proof of correct computation alongside each participant's `(big_y, big_c)` share. Each participant must prove in zero knowledge that:
- `big_y_i` is of the form `λ_i · y_i · G` for some `y_i`
- `big_c_i` is consistent with their committed public key share `x_i · G2` and the same `y_i`

The coordinator must verify all proofs before aggregating. This is the direct analog of the external report's fix: require the sender to commit to their parameters so the receiver can validate them before use.

### Proof of Concept
1. Initialize a CKD protocol with participants `[P1, P2, P3]`, coordinator `P1`, known `app_id` and `app_pk = a · G`.
2. `P2` (malicious) sends `(G1::generator(), G1::generator())` to the coordinator instead of its honest `(norm_big_y, norm_big_c)`.
3. `do_ckd_coordinator` adds `G` to both accumulators with no check (lines 53–55).
4. The final output is `(Y_honest + G, C_honest + G)`.
5. The client calls `ckd_output.unmask(a)` and receives:
   `(C_honest + G) − a · (Y_honest + G) = msk · H(pk ‖ app_id) + (1 − a) · G`
   which is not the correct derived key.
6. No error is raised anywhere in the protocol; the corruption is undetectable by honest parties.

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L17-33)
```rust
fn do_ckd_participant(
    mut chan: SharedChannel,
    participants: &ParticipantList,
    coordinator: Participant,
    me: Participant,
    key_pair: &KeygenOutput,
    app_id: &AppId,
    app_pk: PublicKey,
    rng: &mut impl CryptoRngCore,
) -> Result<CKDOutputOption, ProtocolError> {
    let (norm_big_y, norm_big_c) =
        compute_signature_share(participants, me, key_pair, app_id, app_pk, rng)?;
    let waitpoint = chan.next_waitpoint();
    chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;

    Ok(None)
}
```

**File:** src/confidential_key_derivation/protocol.rs (L48-57)
```rust
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

**File:** src/confidential_key_derivation/mod.rs (L54-56)
```rust
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```
