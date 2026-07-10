### Title
Malicious CKD Participant Can Corrupt Confidential Key Derivation Output Without Detection - (File: `src/confidential_key_derivation/protocol.rs`)

### Summary
The CKD protocol's coordinator unconditionally aggregates `(big_y, big_c)` contributions from all participants with no cryptographic proof of correctness. Any single malicious participant can substitute arbitrary group elements, causing the coordinator to produce a silently corrupted confidential derived key that honest parties cannot distinguish from a valid one.

### Finding Description

In `do_ckd_coordinator`, the coordinator collects each participant's `CKDOutput` via `recv_from_others` and blindly sums the components: [1](#0-0) 

Each honest participant computes their contribution in `compute_signature_share` as:

```
norm_big_y_i = lambda_i * y_i * G
norm_big_c_i = lambda_i * (x_i * H(pk || app_id) + y_i * app_pk)
``` [2](#0-1) 

The coordinator sums these to recover `msk * H(pk || app_id)` after unmasking with `app_sk`. However, there is **no zero-knowledge proof** that any participant's `(norm_big_y_i, norm_big_c_i)` was computed from their actual secret share `x_i` and a consistent `y_i`. The coordinator performs no verification before accumulating: [3](#0-2) 

The `recv_from_others` helper only enforces that messages arrive from known participants; it performs no cryptographic validation of message content: [4](#0-3) 

This is the direct analog of the MetaSwap vulnerability: just as a newly added adapter could access user tokens because no isolation existed between the MetaSwap contract and its adapters, here a newly added (or malicious) participant in the CKD participant set can inject arbitrary values into the aggregation because no proof-of-correct-computation isolates their contribution from the coordinator's trust.

### Impact Explanation

A malicious participant sends `(big_y_m, big_c_m)` of their choosing instead of their correct contribution. The coordinator computes:

```
final_big_y = sum_honest_big_y + big_y_m
final_big_c = sum_honest_big_c + big_c_m
```

After the application calls `unmask(app_sk)`, the result is:

```
final_big_c - app_sk * final_big_y
  = msk * H(pk||app_id) - lambda_m * x_m * H(pk||app_id) + big_c_m - app_sk * big_y_m
```

This is not `msk * H(pk||app_id)` unless the malicious participant happens to satisfy the ElGamal consistency relation — which they control. The coordinator outputs a `CKDOutput` that is structurally valid (two group elements) but cryptographically wrong. Honest parties have no mechanism to detect the corruption.

**Matched allowed impact**: *High — Corruption of CKD outputs so honest parties accept inconsistent or unusable cryptographic outputs.* [5](#0-4) 

### Likelihood Explanation

Any single participant in the `participants` list can execute this attack. The attacker needs only to deviate from the protocol by sending arbitrary group elements instead of their correct `(norm_big_y, norm_big_c)`. No special knowledge, leaked keys, or external compromise is required. The attack is trivially reachable by any unprivileged participant who chooses to be malicious. [6](#0-5) 

### Recommendation

Require each participant to accompany their `(norm_big_y, norm_big_c)` with a non-interactive zero-knowledge proof of correct ElGamal encryption — specifically a Chaum-Pedersen proof demonstrating that `norm_big_c - norm_big_y * (app_pk / G)` lies on the curve in a way consistent with the participant's committed public share `lambda_i * x_i * G` (derivable from the DKG public commitments). The coordinator must verify all proofs before aggregating. This mirrors the MetaSwap fix: interpose a verification layer between the untrusted contributor and the aggregation, so a newly added or malicious participant cannot silently corrupt the output.

### Proof of Concept

1. Honest participants P1, P2, P3 run CKD. P3 is malicious.
2. P3 computes the correct `(norm_big_y_3, norm_big_c_3)` but instead sends `(G, G)` (the generator point for both components) to the coordinator.
3. The coordinator at line 53–54 adds `G` to `norm_big_y` and `G` to `norm_big_c` without any check.
4. The final `CKDOutput` satisfies `big_c - app_sk * big_y = msk * H(pk||app_id) - lambda_3 * x_3 * H(pk||app_id) + G - app_sk * G`, which is not the correct confidential key.
5. The application calls `unmask(app_sk)` and receives a wrong key with no error, no abort, and no indication of tampering. [3](#0-2)

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

**File:** src/protocol/helpers.rs (L6-26)
```rust
pub async fn recv_from_others<T>(
    chan: &SharedChannel,
    waitpoint: u64,
    participants: &ParticipantList,
    me: Participant,
) -> Result<Vec<(Participant, T)>, ProtocolError>
where
    T: serde::de::DeserializeOwned,
{
    let mut seen = ParticipantCounter::new(participants);
    seen.put(me);
    let mut messages = Vec::with_capacity(participants.others(me).count());

    while !seen.full() {
        let (from, msg) = chan.recv(waitpoint).await?;
        if seen.put(from) {
            messages.push((from, msg));
        }
    }

    Ok(messages)
```
