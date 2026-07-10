### Title
Unvalidated Participant Contributions in CKD Protocol Allow Malicious Participant to Corrupt Confidential Key Derivation Output — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

In `do_ckd_coordinator`, the coordinator accumulates `(big_y, big_c)` values sent by each participant and sums them without any proof of correctness. A single malicious participant can send arbitrary group elements in place of their honest contribution, corrupting the final `CKDOutput` and causing the application to derive a wrong confidential key.

---

### Finding Description

The CKD protocol is structured so that each participant computes a signature share and sends it privately to the coordinator. The coordinator's role is to sum all contributions:

```rust
// src/confidential_key_derivation/protocol.rs, lines 50–55
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

Each honest participant is supposed to compute:

```rust
// src/confidential_key_derivation/protocol.rs, lines 165–180
let big_y = ElementG1::generator() * y.0;          // y·G
let big_s = hash_point * private_share.to_scalar(); // xᵢ·H(pk‖app_id)
let big_c = big_s + app_pk * y.0;                  // xᵢ·H(pk‖app_id) + y·A
let norm_big_y = big_y * lambda_i;
let norm_big_c = big_c * lambda_i;
```

The coordinator then reconstructs the confidential key as:

```
total_big_c − app_sk · total_big_y  =  msk · H(pk‖app_id)
```

However, **no proof of correctness accompanies the transmitted `(norm_big_y, norm_big_c)` pair**. There is no NIZK, no commitment-then-reveal, and no consistency check against the participant's public key share. The coordinator blindly adds whatever group elements it receives.

Contrast this with the DKG protocol, which enforces:
- A commitment hash round before revealing polynomial commitments (`verify_commitment_hash`, `dkg.rs` lines 222–236)
- A Schnorr proof of knowledge of the secret coefficient (`internal_verify_proof_of_knowledge`, `dkg.rs` lines 145–166)
- Per-share verification against the committed polynomial (`validate_received_share`, `dkg.rs` lines 259–286)

The CKD protocol has none of these safeguards.

---

### Impact Explanation

A malicious participant sends an arbitrary `(big_y', big_c')` pair. The coordinator's final sum becomes:

```
total_big_c  =  msk · H(pk‖app_id) + λⱼ · δ_c
total_big_y  =  Σ λᵢ yᵢ G  +  λⱼ · δ_y
```

where `δ_c` and `δ_y` are the attacker's chosen deviations. When the application calls `unmask(app_sk)`:

```
total_big_c − app_sk · total_big_y  =  msk · H(pk‖app_id) + λⱼ(δ_c − app_sk · δ_y)
```

The result is a wrong confidential key. Honest parties (coordinator and application) accept this corrupted output as legitimate, since no verification step exists. This maps directly to the allowed High impact: **Corruption of CKD outputs so honest parties accept unusable cryptographic outputs**.

---

### Likelihood Explanation

Any single participant in the CKD protocol can trigger this. The attacker requires no special privilege beyond being a listed participant. The attack requires only sending a malformed message — no cryptographic break, no key leakage, and no external dependency. The entry path is the private message sent at `waitpoint` in `do_ckd_participant` (line 30), which is received unconditionally by the coordinator.

---

### Recommendation

Add a non-interactive zero-knowledge proof (NIZK) that each participant's `(big_y, big_c)` is correctly formed with respect to their public key share. Concretely, each participant should prove knowledge of `(xᵢ, y)` such that:

- `big_y = y · G`
- `big_c = xᵢ · H(pk‖app_id) + y · app_pk`
- `xᵢ · G₂ = public_share_i` (binding to the DKG-derived public share)

A Chaum–Pedersen or sigma-protocol proof over the BLS12-381 G1 group is sufficient. This mirrors the proof-of-knowledge mechanism already present in the DKG protocol (`proof_of_knowledge` / `internal_verify_proof_of_knowledge` in `src/dkg.rs`).

---

### Proof of Concept

1. Participants `{P1, P2, P3}` run the CKD protocol with coordinator `P1`.
2. Malicious participant `P2` computes the correct `(norm_big_y, norm_big_c)` but instead sends `(G1::identity(), G1::identity())` to the coordinator.
3. The coordinator at lines 50–55 of `protocol.rs` adds the identity elements, effectively subtracting `P2`'s honest contribution from the sum.
4. The final `CKDOutput` satisfies `big_c = (msk − λ₂·x₂)·H(pk‖app_id) + …`, which is not `msk·H(pk‖app_id)`.
5. The application calls `ckd_output.unmask(app_sk)` (line 55 of `mod.rs`) and obtains a wrong confidential key with no error or indication of failure.
6. Any data protected under the expected confidential key is inaccessible, and the derived key is attacker-influenced. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L50-55)
```rust
    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
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

**File:** src/confidential_key_derivation/mod.rs (L54-56)
```rust
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```

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

**File:** src/dkg.rs (L222-236)
```rust
fn verify_commitment_hash<C: Ciphersuite>(
    session_id: &HashOutput,
    participant: Participant,
    domain_separator: &mut DomainSeparator,
    commitment: &VerifiableSecretSharingCommitment<C>,
    all_hash_commitments: &ParticipantMap<'_, HashOutput>,
) -> Result<(), ProtocolError> {
    let actual_commitment_hash = all_hash_commitments.index(participant)?;
    let commitment_hash =
        domain_separate_hash(domain_separator, &(&participant, &commitment, &session_id))?;
    if *actual_commitment_hash != commitment_hash {
        return Err(ProtocolError::InvalidCommitmentHash);
    }
    Ok(())
}
```
