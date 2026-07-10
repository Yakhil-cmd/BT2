### Title
Malicious Participant Can Corrupt CKD Output via Unverified Contributions — (`src/confidential_key_derivation/protocol.rs`)

### Summary
The `do_ckd_coordinator` function aggregates participant-supplied `(norm_big_y, norm_big_c)` values with no zero-knowledge proof or consistency check that each contribution is correctly formed. A single malicious participant can inject arbitrary group elements, causing the coordinator to output a corrupted `CKDOutput` that the TEE will silently accept and use to derive an incorrect confidential key. This is the direct structural analog of the external report's pattern: unvalidated caller-controlled data is consumed by a critical operation whose post-step check cannot catch the manipulation.

### Finding Description

**Root cause — `do_ckd_coordinator`, lines 50–55:**

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

Each honest participant is supposed to send:

```
norm_big_y_i = λ_i · (y_i · G)
norm_big_c_i = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)
```

The coordinator sums every received pair and returns `CKDOutput(total_big_y, total_big_c)`. There is no proof-of-correct-formation attached to any contribution, and no post-aggregation consistency check. The function in `compute_signature_share` (lines 148–182) that honest participants call is never enforced on the received values.

**Exploit flow:**

1. A malicious participant P_m participates in a legitimate DKG and holds a valid key share.
2. During a CKD invocation, instead of calling `compute_signature_share`, P_m sends:
   - `norm_big_y_m = G` (or any arbitrary non-identity point)
   - `norm_big_c_m = δ` (any arbitrary group element chosen by the attacker)
3. The coordinator blindly adds these to the running sums.
4. The final `CKDOutput` is:
   - `total_big_y = Σ_honest(norm_big_y_i) + G`
   - `total_big_c = Σ_honest(norm_big_c_i) + δ`
5. The TEE unmasks: `key = total_big_c − app_sk · total_big_y`, which equals `correct_key + (δ − app_sk · G)`.
6. The TEE derives and uses an incorrect confidential key with no error signal, because there is no post-aggregation verification step.

The parallel to the external report is exact: the attacker supplies unvalidated data (`norm_big_c_m`, `norm_big_y_m`) to a critical aggregation step (`do_ckd_coordinator`), and the post-step "check" (the TEE's unmask computation) silently accepts the corrupted result just as the balance check in `_bridgeFunds` passed after the malicious NFT transfer.

### Impact Explanation

**High — Corruption of CKD outputs so honest parties accept inconsistent or unusable cryptographic outputs.**

The TEE receives and uses a `CKDOutput` that does not correspond to `msk · H(pk ‖ app_id)`. Every downstream operation that depends on the derived confidential key (e.g., decryption, re-encryption, key agreement) will silently produce wrong results. Because the TEE has no way to detect the corruption, it cannot raise an alarm or retry. The attacker does not need to know `app_sk` to cause this; any non-zero deviation in `norm_big_c_m` is sufficient to corrupt the output.

### Likelihood Explanation

Any single participant in the CKD session can trigger this. No special privilege is required beyond being a valid member of the participant set (which is the normal precondition for calling `ckd`). The attack requires only that the participant deviate from `compute_signature_share` when constructing their message to the coordinator — a trivial modification for a library caller who controls their own protocol instance.

### Recommendation

Require each participant to attach a zero-knowledge proof of correct formation alongside their `(norm_big_y, norm_big_c)` contribution. Specifically, each participant should prove in zero knowledge that:

```
norm_big_c_i = λ_i · x_i · H(pk ‖ app_id) + λ_i · y_i · app_pk
norm_big_y_i = λ_i · y_i · G
```

using a standard ElGamal consistency proof (a Chaum–Pedersen DLEQ proof over the pair `(norm_big_y_i, norm_big_c_i − λ_i · x_i · H(pk ‖ app_id))`). The coordinator must verify every proof before adding the contribution to the running sum and must abort if any proof fails, identifying the malicious participant.

### Proof of Concept

```
Setup:
  - 3 participants P1, P2, P3 complete DKG normally.
  - P3 is malicious.

CKD invocation:
  - P1 and P2 call compute_signature_share and send correct (norm_big_y, norm_big_c).
  - P3 sends (norm_big_y_3 = G, norm_big_c_3 = arbitrary_point) directly,
    bypassing compute_signature_share.

Coordinator (do_ckd_coordinator):
  - Receives P1 and P2's correct contributions.
  - Receives P3's crafted contribution.
  - Sums all three without any check.
  - Returns CKDOutput(corrupted_total_big_y, corrupted_total_big_c).

TEE:
  - Calls ckd_output.unmask(app_sk).
  - Derives key = corrupted_total_big_c - app_sk * corrupted_total_big_y
             ≠ msk * H(pk ‖ app_id).
  - No error is raised; the wrong key is used silently.
``` [1](#0-0) [2](#0-1)

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
