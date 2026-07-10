### Title
Malicious CKD Participant Can Corrupt Derived Key Output via Unvalidated Group Element Contributions — (File: `src/confidential_key_derivation/protocol.rs`)

### Summary
In `do_ckd_coordinator`, the coordinator receives `CKDOutput` values (pairs of BLS12-381 G1 points) from each participant and accumulates them without any cryptographic validation of correctness. A single malicious participant can send arbitrary valid G1 points in place of their honest contribution, causing the coordinator to produce a silently corrupted CKD output that all honest parties accept as legitimate.

### Finding Description
The CKD coordinator aggregates participant shares in `do_ckd_coordinator`:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [1](#0-0) 

Each honest participant is expected to send `(λ_i · y_i · G, λ_i · (x_i · H(pk, app_id) + y_i · A))`. The coordinator performs no verification whatsoever — no zero-knowledge proof, no commitment binding, no range or subgroup check beyond what deserialization of `blstrs::G1Projective` provides (curve membership only).

The `CKDOutput` struct is a plain pair of G1 points with no attached proof:

```rust
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CKDOutput {
    big_y: ElementG1,
    big_c: ElementG1,
}
``` [2](#0-1) 

A malicious participant can substitute any two valid G1 points (e.g., random points, the generator, or a crafted point that biases the output toward an attacker-chosen value) and the coordinator will silently incorporate them. The final `CKDOutput` returned to the caller will not equal `msk · H(pk, app_id)` as required by the protocol.

Contrast this with the OT-based ECDSA triple generation, which validates polynomial degrees, commitment openings, and dlog proofs for every received message: [3](#0-2) 

No equivalent validation exists in the CKD path.

### Impact Explanation
A single malicious participant (one of the N parties in the CKD session) can cause the coordinator to output a `CKDOutput` whose `unmask` result is an arbitrary G1 point rather than the correct `msk · H(pk, app_id)`. The honest coordinator and client accept this output without any indication of tampering. The derived confidential key is silently wrong, rendering it unusable for its intended cryptographic purpose and potentially leaking information about the honest participants' shares depending on the attacker's chosen substitution. This maps directly to: **High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

### Likelihood Explanation
Any one of the N participants in a CKD session can mount this attack. No privileged access, leaked keys, or external compromise is required — the attacker simply sends a crafted `CKDOutput` message over the normal protocol channel. The attack is undetectable by the coordinator or the client after the fact.

### Recommendation
- **Short term:** Add a Schnorr-style zero-knowledge proof of discrete log for `big_y` (proving knowledge of `y_i` such that `big_y = y_i · G`) and a proof of correct construction of `big_c` relative to the participant's committed public key share. Reject any `CKDOutput` that fails verification before accumulating it.
- **Long term:** Bind each participant's contribution to their public key share via a commitment in an earlier round, then open and verify before aggregation, mirroring the commitment-then-reveal pattern used in `do_keyshare`.

### Proof of Concept
1. Run a CKD session with participants `[P0, P1, P2]` where `P1` is malicious.
2. `P1` computes the honest `(norm_big_y, norm_big_c)` but instead sends `(G1::generator(), G1::generator())` — two arbitrary valid G1 points — to the coordinator.
3. The coordinator's `do_ckd_coordinator` loop adds these without complaint:
   `norm_big_y += G1::generator(); norm_big_c += G1::generator();`
4. The returned `CKDOutput` satisfies `big_c - big_y * app_sk ≠ msk · H(pk, app_id)`.
5. The client calls `ckd_output.unmask(app_sk)` and receives a wrong key with no error. [4](#0-3)

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

**File:** src/confidential_key_derivation/mod.rs (L31-35)
```rust
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CKDOutput {
    big_y: ElementG1,
    big_c: ElementG1,
}
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L343-389)
```rust
                if their_big_e.degree() != threshold.value() - 1
                    || their_big_f.degree() != threshold.value() - 1
                    // degree is threshold - 2 because the constant element identity is not serializable
                    || their_big_l.degree() != threshold.value() - 2
                {
                    return Err(ProtocolError::AssertionFailed(format!(
                        "polynomial from {from:?} has the wrong length"
                    )));
                }

                if !all_commitments
                    .index(from)?
                    .check(
                        &(&their_big_e, &their_big_f, &their_big_l),
                        their_randomizer,
                    )
                    .map_err(|_| ProtocolError::PointSerialization)?
                {
                    return Err(ProtocolError::AssertionFailed(format!(
                        "commitment from {from:?} did not match revealed F"
                    )));
                }
                let statement0 = dlog::Statement::<C> {
                    public: &their_big_e.eval_at_zero()?.value(),
                };
                if !dlog::verify(
                    &mut transcript.fork(b"dlog0", &from.bytes()),
                    statement0,
                    their_phi_proof0,
                )? {
                    return Err(ProtocolError::AssertionFailed(format!(
                        "dlog proof from {from:?} failed to verify"
                    )));
                }

                let statement1 = dlog::Statement::<C> {
                    public: &their_big_f.eval_at_zero()?.value(),
                };
                if !dlog::verify(
                    &mut transcript.fork(b"dlog1", &from.bytes()),
                    statement1,
                    their_phi_proof1,
                )? {
                    return Err(ProtocolError::AssertionFailed(format!(
                        "dlog proof from {from:?} failed to verify"
                    )));
                }
```
