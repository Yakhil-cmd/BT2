### Title
Missing Validity Checks on Received CKD Participant Contributions Allow Malicious Participant to Corrupt the Derived Confidential Key - (File: src/confidential_key_derivation/protocol.rs)

### Summary
In `do_ckd_coordinator`, the coordinator receives `CKDOutput` contributions (`big_y`, `big_c`) from every participant and accumulates them directly into the running totals without any validity checks on the received group elements. A malicious participant can send the identity element (or any crafted G1 point) for either field, silently corrupting the aggregated CKD output that all honest parties ultimately accept. This is the direct structural analog to the Chainlink `rawPrice > 0` / `updateTime != 0` missing-check pattern: external data is consumed without asserting it is non-degenerate.

### Finding Description

**Root cause — `do_ckd_coordinator`, lines 50–55:**

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();   // no identity check
    norm_big_c += participant_output.big_c();   // no identity check
}
```

Each participant computes `(norm_big_y_i, norm_big_c_i)` locally in `compute_signature_share` and sends it privately to the coordinator. The coordinator is the only party that sees all contributions; it simply adds them together and returns the aggregate as the protocol output.

There is no check that:
1. `big_y` ≠ identity element in G1 (analogous to `rawPrice > 0`)
2. `big_c` ≠ identity element in G1 (analogous to `updateTime != 0`)
3. The received points are torsion-free (subgroup membership)

Contrast this with `verify_signature` in `src/confidential_key_derivation/ciphersuite.rs` (lines 223–229), which explicitly performs all three checks before using any G1/G2 element:

```rust
if (!element1.is_on_curve() | !element1.is_torsion_free() | element1.is_identity()).into() {
    return Err(frost_core::Error::InvalidSignature);
}
```

The same defensive pattern is conspicuously absent in the aggregation loop.

**Exploit path:**

1. A malicious participant is one of the `n` parties in the CKD session.
2. Instead of computing the honest `(norm_big_y_i, norm_big_c_i)`, it sends `(G1::identity(), G1::identity())` (or any crafted point).
3. The coordinator adds these to `norm_big_y` / `norm_big_c` without complaint.
4. The final `CKDOutput::new(norm_big_y, norm_big_c)` is built from the corrupted sums.
5. When the caller invokes `ckd_output.unmask(app_sk)` — computing `big_c − app_sk · big_y` — the result is not `msk · H(pk ∥ app_id)` but a wrong, attacker-influenced point.
6. All honest parties accept this output as the legitimate derived key; no error is raised.

### Impact Explanation

**High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

The CKD protocol's purpose is to produce `msk · H(pk ∥ app_id)` as a deterministic confidential derived key for a TEE. A malicious participant can silently shift the aggregate away from this value. The coordinator and all downstream consumers have no way to detect the corruption: the protocol returns `Ok(Some(ckd_output))` with a structurally valid but semantically wrong `CKDOutput`. Any TEE operation that depends on the derived key (decryption, authentication, further derivation) will silently fail or produce attacker-influenced material.

### Likelihood Explanation

Any single participant in the CKD session is an unprivileged attacker-controlled entry point. The participant role requires no special privilege beyond being included in the `participants` list. The attack requires only that the malicious party deviate from the protocol by sending crafted G1 points — a trivial modification to the library's own `ckd()` call. No cryptographic break, no key leakage, and no external dependency is required.

### Recommendation

Before accumulating each participant's contribution, validate the received group elements:

```rust
for (from, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    let big_y = participant_output.big_y();
    let big_c = participant_output.big_c();

    // Mirror the checks already present in verify_signature (ciphersuite.rs:223-229)
    let y_affine: G1Affine = big_y.into();
    if (!y_affine.is_on_curve() | !y_affine.is_torsion_free() | y_affine.is_identity()).into() {
        return Err(ProtocolError::MaliciousParticipant(from));
    }
    let c_affine: G1Affine = big_c.into();
    if (!c_affine.is_on_curve() | !c_affine.is_torsion_free() | c_affine.is_identity()).into() {
        return Err(ProtocolError::MaliciousParticipant(from));
    }

    norm_big_y += big_y;
    norm_big_c += big_c;
}
```

Additionally, consider adding a NIZK proof of correct computation (a Schnorr-style proof that `big_y = y·G` and `big_c = x_i·H(pk∥app_id) + y·app_pk` for the same `y`) so the coordinator can verify each share without trusting the sender.

### Proof of Concept

```
Honest setup: 3 participants, coordinator = P0.
P1 and P2 compute honest (norm_big_y_i, norm_big_c_i).
Malicious P1 instead sends (G1::identity(), G1::identity()).

Coordinator accumulates:
  norm_big_y = norm_big_y_P0 + identity + norm_big_y_P2
             = norm_big_y_P0 + norm_big_y_P2   ← missing P1's share
  norm_big_c = norm_big_c_P0 + identity + norm_big_c_P2
             = norm_big_c_P0 + norm_big_c_P2   ← missing P1's share

ckd_output.unmask(app_sk) returns:
  norm_big_c − app_sk · norm_big_y
  ≠ msk · H(pk ∥ app_id)

Protocol returns Ok(Some(corrupted_output)) with no error.
``` [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** src/confidential_key_derivation/ciphersuite.rs (L223-229)
```rust
    let element1: G1Affine = signature.into();
    if (!element1.is_on_curve() | !element1.is_torsion_free() | element1.is_identity()).into() {
        return Err(frost_core::Error::InvalidSignature);
    }
    let element2: G2Affine = verifying_key.to_element().into();
    if (!element2.is_on_curve() | !element2.is_torsion_free() | element2.is_identity()).into() {
        return Err(frost_core::Error::MalformedVerifyingKey);
```
