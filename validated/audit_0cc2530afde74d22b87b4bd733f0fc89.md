### Title
Malicious Participant Can Corrupt CKD Output by Sending Arbitrary Share Values to Coordinator — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

In `do_ckd_coordinator`, the coordinator collects `CKDOutput` shares from all other participants and sums them unconditionally. The sender identity is silently discarded (`_`), and there is no proof-of-correctness or commitment binding each participant to their share. Any participant in the protocol can substitute arbitrary elliptic-curve points for their legitimate `(norm_big_y, norm_big_c)` contribution, causing the coordinator to output a structurally valid but cryptographically wrong `CKDOutput`.

---

### Finding Description

`do_ckd_coordinator` aggregates participant shares as follows:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
``` [1](#0-0) 

The `from` participant returned by `recv_from_others` is thrown away (`_`). No check is made that the received `big_y` or `big_c` points were computed from the participant's actual key share `x_i` and the agreed `app_id`/`app_pk`. The coordinator simply adds whatever group elements it receives.

Compare this with the DKG protocol, where the analogous receive loop retains `from` and immediately calls `validate_received_share` to cryptographically verify the share against the participant's public commitment:

```rust
for (from, signing_share_from) in
    recv_from_others(&chan, wait_round_3, &participants, me).await?
{
    let full_commitment_from = all_full_commitments.index(from)?;
    validate_received_share::<C>(me, from, &signing_share_from, full_commitment_from)?;
``` [2](#0-1) 

The CKD coordinator performs no equivalent check. The `do_ckd_participant` path sends its share privately to the coordinator with no accompanying proof:

```rust
chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;
Ok(None)
``` [3](#0-2) 

The correct value each participant should contribute is `(λ_i · y_i · G, λ_i · (x_i · H(pk, app_id) + y_i · app_pk))`. Nothing in the protocol enforces this. [4](#0-3) 

---

### Impact Explanation

The coordinator's final output is:

```
big_C_total = Σ λ_i · (x_i · H(pk, app_id) + y_i · app_pk)
```

The `unmask` operation recovers `big_C_total − app_sk · big_Y_total = msk · H(pk, app_id)`, the confidential derived key. If any single participant substitutes an arbitrary `big_c'` for their legitimate contribution, the sum shifts by an attacker-controlled offset, and `unmask` yields a wrong key. The coordinator and any downstream consumer accept this output as valid because the protocol performs no integrity check on the aggregated result.

This matches: **High — Corruption of CKD outputs so honest parties accept inconsistent or unusable cryptographic outputs.** [5](#0-4) 

---

### Likelihood Explanation

Every non-coordinator participant in the CKD protocol has a direct, unauthenticated write path to the coordinator's aggregation loop. No threshold of honest parties can prevent a single malicious participant from corrupting the output, because the coordinator sums all `n−1` contributions and a single bad value poisons the sum. The attacker needs only to be a legitimate participant and deviate from the protocol in the single message they send.

---

### Recommendation

1. **Add a NIZK proof of correct share formation.** Each participant should accompany `(norm_big_y, norm_big_c)` with a Chaum–Pedersen or sigma-protocol proof that `big_c − y · app_pk` lies on the correct coset (i.e., equals `x_i · H(pk, app_id)`), using the participant's public key share as the verification key. The coordinator must verify each proof before adding the contribution.

2. **Retain and use the `from` field.** Even without a NIZK, the coordinator should at minimum record which participant sent which share (as DKG does) so that a misbehaving participant can be identified and excluded, rather than silently corrupting the output.

---

### Proof of Concept

1. Participants `{P1, P2, P3}` run `ckd()` with `P1` as coordinator.
2. `P2` (malicious) deviates: instead of calling `compute_signature_share`, it constructs `(big_y', big_c')` as arbitrary random group elements and sends them to `P1` via `chan.send_private(waitpoint, coordinator, &(big_y', big_c'))`.
3. `P1`'s `do_ckd_coordinator` loop receives `P2`'s crafted values and adds them to the running sum without any check.
4. The resulting `CKDOutput` satisfies `big_C_total = λ_1·C_1 + big_c' + λ_3·C_3`, which is not equal to `msk · H(pk, app_id)` scaled by any Lagrange coefficient.
5. `ckd_output.unmask(app_sk)` returns a wrong key. The coordinator returns `Some(ckd_output)` with no error, and all downstream consumers of the derived key receive an incorrect value. [6](#0-5)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L30-32)
```rust
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

**File:** src/confidential_key_derivation/protocol.rs (L165-181)
```rust
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

**File:** src/dkg.rs (L514-522)
```rust
    for (from, signing_share_from) in
        recv_from_others(&chan, wait_round_3, &participants, me).await?
    {
        // Verify the share
        // this deviates from the original FROST DKG paper
        // however it matches the FROST implementation of ZCash
        let full_commitment_from = all_full_commitments.index(from)?;
        // Step 5.2
        validate_received_share::<C>(me, from, &signing_share_from, full_commitment_from)?;
```
