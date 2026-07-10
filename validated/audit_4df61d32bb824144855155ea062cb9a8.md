Now I have all the information needed to analyze this vulnerability claim. Let me trace the exact code path.

**Key question:** Does `verify_proof_of_knowledge` / `internal_verify_proof_of_knowledge` verify that an old participant's constant-term commitment equals their correct Lagrange-weighted share commitment?

The analysis is complete. Here is the determination:

---

### Title
Single Malicious Old Participant Can Permanently Abort Reshare via Arbitrary Constant-Term Commitment — (`src/dkg.rs`)

### Summary
During reshare, `internal_verify_proof_of_knowledge` only proves that a participant knows the discrete log of their constant-term commitment `C_i(0)`. It does **not** prove that `C_i(0)` equals the correct Lagrange-weighted share commitment `λ_i · secret_i · G`. A single malicious old participant can choose any arbitrary scalar `a_0'`, produce a valid Schnorr proof for it, and broadcast `C_i(0)' = a_0' · G`. The aggregate public key computed by all honest parties will then differ from `old_pk`, causing every honest party to abort with `ProtocolError::AssertionFailed("new public key does not match old public key")`. No honest party can identify the culprit, making the denial permanent.

### Finding Description

In `do_keyshare` (`src/dkg.rs`), Round 4 verifies each participant's commitment via `verify_proof_of_knowledge`, which ultimately calls `internal_verify_proof_of_knowledge`: [1](#0-0) 

The check is:
```
R == z·G - c·C(0)
```
This is a standard Schnorr proof that the prover knows `dlog(C(0))`. It says nothing about **what value** `C(0)` encodes. The protocol specification requires old participant `P_i` to set `f_i(0) = λ_i · secret_i`, but this constraint is never cryptographically enforced.

After all commitments pass the proof-of-knowledge check, the aggregate public key is computed: [2](#0-1) 

If any old participant contributed a wrong `C_i(0)`, the sum deviates from `old_pk` and every honest party aborts. There is no per-participant attribution at this point — the error message is generic and no culprit is identified.

The `do_reshare` entry point passes the old public key and old participants list into `do_keyshare` via `old_reshare_package`: [3](#0-2) 

### Impact Explanation
A single malicious old participant can unconditionally abort every reshare attempt. Because the proof of knowledge passes (the attacker knows the discrete log of their chosen `C_i(0)'`), the only detection point is the aggregate public key mismatch check, which causes all honest parties to abort without identifying the culprit. The reshare cannot complete as long as the malicious participant participates, constituting a **permanent denial of reshare**.

### Likelihood Explanation
The attack requires only that the attacker is one of the old participants — a role that is explicitly part of the protocol's participant model. The attack is trivial: pick any `a_0' ≠ λ_i · secret_i`, compute a valid Schnorr proof for it, and broadcast. No cryptographic assumption needs to be broken.

### Recommendation
Enforce that the sum of constant-term commitments from old participants equals `old_pk` **per-participant** rather than only in aggregate. One approach: require each old participant `P_i` to additionally prove that `C_i(0) = λ_i · VK_i`, where `VK_i` is their individual public verification share from the previous keygen output (which is public). This is a proof of equality of discrete logs (a standard sigma protocol). Alternatively, collect individual `C_i(0)` values and verify `sum_i C_i(0) == old_pk` with per-participant accountability so the deviating party can be identified and excluded.

### Proof of Concept

1. Run a keygen with participants `{P1, P2, P3}`, threshold 2. Each `P_i` holds `secret_i`; the public key is `PK`.
2. Initiate reshare. `P1` is malicious.
3. `P1` picks a random scalar `a_0' ≠ λ_1 · secret_1`, computes `C_1(0)' = a_0' · G`, and generates a valid Schnorr proof `(R, z)` for `a_0'`.
4. `P1` broadcasts `(C_1', proof)` — `verify_proof_of_knowledge` passes because `R = z·G - c·C_1(0)'` holds.
5. Honest parties `P2`, `P3` compute `verifying_key = C_1(0)' + C_2(0) + C_3(0) ≠ PK`.
6. Both abort at line 491–494 with `"new public key does not match old public key"`.
7. The reshare is permanently blocked as long as `P1` participates. [4](#0-3) [5](#0-4)

### Citations

**File:** src/dkg.rs (L145-166)
```rust
fn internal_verify_proof_of_knowledge<C: Ciphersuite>(
    session_id: &HashOutput,
    domain_separator: &mut DomainSeparator,
    participant: Participant,
    commitment: &VerifiableSecretSharingCommitment<C>,
    proof_of_knowledge: &Signature<C>,
) -> Result<(), ProtocolError> {
    // creates an identifier for the participant
    let id = participant.scalar::<C>();
    let vk_share = commitment
        .coefficients()
        .first()
        .ok_or_else(|| ProtocolError::AssertionFailed("Empty coefficient list".to_string()))?;

    let big_r = proof_of_knowledge.R();
    let z = proof_of_knowledge.z();
    let c = challenge::<C>(domain_separator, session_id, id, vk_share, big_r)?;
    if *big_r != <C::Group>::generator() * *z - vk_share.value() * c.to_scalar() {
        return Err(ProtocolError::InvalidProofOfKnowledge(participant));
    }
    Ok(())
}
```

**File:** src/dkg.rs (L484-496)
```rust
    // Step 4.5
    let verifying_key = public_key_from_commitments(all_commitments_refs)?;

    // Step 4.5 +++
    // In the case of Resharing, check if the old public key is the same as the new one
    if let Some(old_vk) = old_verification_key {
        // check the equality between the old key and the new key without failing the unwrap
        if old_vk != verifying_key {
            return Err(ProtocolError::AssertionFailed(
                "new public key does not match old public key".to_string(),
            ));
        }
    }
```

**File:** src/dkg.rs (L622-634)
```rust
    let old_reshare_package = Some((old_public_key, old_participants));
    let keygen_output = do_keyshare::<C>(
        chan,
        participants,
        me,
        threshold,
        secret,
        old_reshare_package,
        &mut rng,
    )
    .await?;

    Ok(keygen_output)
```
