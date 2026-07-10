### Title
Unverified Participant Outputs in CKD Coordinator Allow Malicious Participant to Corrupt Derived Key - (File: src/confidential_key_derivation/protocol.rs)

### Summary
The `do_ckd_coordinator` function in `src/confidential_key_derivation/protocol.rs` blindly sums `CKDOutput` values (`big_y`, `big_c`) received from participants without any cryptographic verification. A single malicious participant can send arbitrary group elements, causing the coordinator to produce a corrupted `CKDOutput` that honest parties accept as valid. This is the direct analog of the ERC4626 "trust the return value" bug: the protocol trusts participant-supplied outputs instead of independently verifying them against committed state.

### Finding Description

In `do_ckd_coordinator` (lines 50–57), the coordinator receives each participant's `(norm_big_y, norm_big_c)` pair and unconditionally adds them to the running sum:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
Ok(Some(ckd_output))
``` [1](#0-0) 

Each honest participant `i` is supposed to compute:
- `norm_big_y = λ_i · y_i · G`
- `norm_big_c = λ_i · (x_i · H(pk, app_id) + y_i · app_pk)`

so that the coordinator's sum yields `C = msk · H(pk, app_id) + Y · app_pk`. There are **no ZK proofs, no commitments, and no consistency checks** on the received `(big_y, big_c)` pairs. A malicious participant can send any arbitrary group elements.

Contrast this with:
- The **DKG** protocol, which verifies every received signing share against a published polynomial commitment before accepting it: [2](#0-1) 
- The **robust ECDSA** triple generation, which uses `dlogeq` ZK proofs to verify that each participant's contribution is consistent with their committed values: [3](#0-2) 
- The **robust ECDSA signing** coordinator, which verifies the final signature before returning it: [4](#0-3) 

The CKD protocol has none of these safeguards.

### Impact Explanation

**High — Corruption of CKD output so honest parties accept an incorrect derived key.**

A malicious participant `P_j` sends `(big_y' = big_y_j + Δ_y, big_c' = big_c_j + Δ_c)` for arbitrary group elements `Δ_y`, `Δ_c`. The coordinator computes:

```
C_final = msk · H(pk, app_id) + Y_final · app_pk + Δ_c - Δ_y · app_pk
```

The resulting `CKDOutput` is cryptographically invalid: `unmask(app_sk)` will not yield `msk · H(pk, app_id)`. The application receives a silently wrong derived key with no error signal. Depending on the attacker's choice of `Δ_c` and `Δ_y`, the output can be set to the identity element or any other value, rendering the CKD permanently unusable for honest parties.

This maps directly to the allowed impact: **"Corruption of CKD outputs so honest parties accept inconsistent or unusable cryptographic outputs."**

### Likelihood Explanation

Any single participant in the CKD session is sufficient to trigger this. The attacker needs no special privilege beyond being a protocol participant. The attack requires only sending two malformed group elements in a single protocol message — no cryptographic break, no key leakage, no external dependency. Likelihood is **High**.

### Recommendation

Each participant must accompany their `(norm_big_y, norm_big_c)` with a zero-knowledge proof of correct formation — specifically, a proof of discrete-log equality (`dlogeq`) demonstrating that `norm_big_c - norm_big_y · app_pk` lies on the same discrete-log relation as the participant's public key share. The coordinator must verify all proofs before summing. This mirrors the pattern already used in triple generation: [3](#0-2) 

Alternatively, at minimum, the coordinator should verify the final `CKDOutput` satisfies the expected algebraic relation using the known public key `verifying_key` and `H(pk, app_id)` before returning it, analogous to the signature verification check in `do_sign_coordinator`: [4](#0-3) 

### Proof of Concept

1. Run the CKD protocol with `n ≥ 2` participants, one of which is malicious (`P_j`).
2. `P_j` computes its honest share `(norm_big_y_j, norm_big_c_j)` but instead sends `(norm_big_y_j, ElementG1::identity())` (zeroing out its `big_c` contribution).
3. The coordinator sums all contributions. The final `norm_big_c` is missing `P_j`'s share of `msk · H(pk, app_id)`.
4. `ckd_output.unmask(app_sk)` returns a value that does not equal `msk · H(pk, app_id)`.
5. The coordinator returns `Ok(Some(ckd_output))` with no error — honest parties silently accept the corrupted key.

The existing test at `src/confidential_key_derivation/protocol.rs` line 278 confirms the expected equality `confidential_key == expected_confidential_key`; this assertion would fail under the attack, but the protocol itself raises no error. [5](#0-4)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L44-57)
```rust
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

**File:** src/dkg.rs (L520-522)
```rust
        let full_commitment_from = all_full_commitments.index(from)?;
        // Step 5.2
        validate_received_share::<C>(me, from, &signing_share_from, full_commitment_from)?;
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L435-448)
```rust
            let statement = dlogeq::Statement::<C> {
                public0: &big_e_i.eval_at_zero()?.value(),
                generator1: &big_f.eval_at_zero()?.value(),
                public1: &big_c_i,
            };
            let witness = dlogeq::Witness {
                x: e.eval_at_zero()?,
            };
            let my_phi_proof = dlogeq::prove_with_nonce(
                &mut transcript.fork(b"dlogeq0", &me.bytes()),
                statement,
                witness,
                my_phi_proof_nonces[i],
            )?;
```

**File:** src/ecdsa/robust_ecdsa/sign.rs (L159-163)
```rust
    if !sig.verify(&public_key, &msg_hash) {
        return Err(ProtocolError::AssertionFailed(
            "signature failed to verify".to_string(),
        ));
    }
```
