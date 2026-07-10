### Title
Malicious CKD Participant Can Corrupt Derived Confidential Key Without Detection - (File: `src/confidential_key_derivation/protocol.rs`)

### Summary
The CKD coordinator in `do_ckd_coordinator` blindly aggregates `(big_y, big_c)` shares received from every participant with no cryptographic proof that each share was honestly computed. This is the direct threshold-signatures analog of the external report's pattern: accepting an untrusted value and using it without a pre/post consistency check. A single malicious participant can silently corrupt the final CKD output accepted by all honest parties.

### Finding Description
`do_ckd_coordinator` (lines 35–58 of `src/confidential_key_derivation/protocol.rs`) collects each participant's `(norm_big_y, norm_big_c)` pair and sums them unconditionally:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
```

Each honest participant computes, inside `compute_signature_share` (lines 148–182):

```
big_y  = y_i · G
big_c  = x_i · H(pk ‖ app_id) + y_i · app_pk
```

and then Lagrange-linearises both before sending. The coordinator has no way to verify that the received `big_c` encodes the participant's actual secret share `x_i`, nor that `big_y` and `big_c` are consistent with each other (i.e., that the same `y_i` was used in both). No ZK proof, no commitment, and no post-aggregation consistency check is performed.

A malicious participant can send any pair `(big_y', big_c')` of its choosing. Because the coordinator simply adds all contributions, the final output becomes:

```
Y_out = Σ_{j≠m} λ_j·y_j·G  +  big_y'
C_out = Σ_{j≠m} λ_j·C_j    +  big_c'
```

The `unmask` step (`C_out − app_sk · Y_out`) will then yield a value that is not `msk · H(pk ‖ app_id)`, and the honest parties have no mechanism to detect the deviation.

### Impact Explanation
A single malicious participant can force the CKD output to encode an arbitrary wrong derived key. Every honest party that consumes the coordinator's output will silently accept a corrupted confidential key. This maps directly to the allowed High impact: **Corruption of CKD outputs so honest parties accept unusable cryptographic outputs**. The attack is undetectable at the protocol level because no honest party holds enough information to recompute the expected aggregate.

### Likelihood Explanation
Any one of the `N` participants in a CKD session is a sufficient attacker. No privileged access, leaked key material, or external assumption is required — the attacker only needs to be a legitimate participant (i.e., hold a valid key share from DKG). The attack is a single-message deviation: send a crafted `(big_y', big_c')` instead of the honest value. Likelihood is moderate-to-high given that the role is reachable by any node operator.

### Recommendation
Each participant must accompany its `(big_y, big_c)` contribution with a non-interactive ZK proof of correct computation. Concretely, a proof of discrete-log equality (dlogeq) can demonstrate that the same scalar `y_i` was used in both `big_y = y_i · G` and the `y_i · app_pk` term inside `big_c`, and a separate proof can bind `big_c` to the participant's committed public share `x_i · G` (available from the DKG output). The coordinator must verify all proofs before aggregating. This is the same pattern already applied in the OT-based triple generation (`src/ecdsa/ot_based_ecdsa/triples/generation.rs`, lines 365–389) and in the DKG itself (`src/dkg.rs`, lines 452–460).

### Proof of Concept
1. Run a CKD session with participants `{P_1, P_2, P_3}` where `P_3` is malicious.
2. `P_3` computes its honest share `(norm_big_y_3, norm_big_c_3)` but instead sends `(G, G)` (the generator point for both fields) to the coordinator.
3. The coordinator sums: `Y_out = λ_1·y_1·G + λ_2·y_2·G + G`, `C_out = λ_1·C_1 + λ_2·C_2 + G`.
4. `unmask(app_sk)` returns `C_out − app_sk·Y_out`, which differs from `msk·H(pk‖app_id)` by `G − app_sk·G = (1 − app_sk)·G`.
5. The coordinator returns this corrupted `CKDOutput` as `Some(ckd_output)`; all honest parties accept it with no error. [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** src/confidential_key_derivation/protocol.rs (L148-182)
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
}
```
