### Title
Missing Verification of Participant CKD Shares Allows Malicious Participant to Corrupt Derived Confidential Key Output - (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The `do_ckd_coordinator` function in `src/confidential_key_derivation/protocol.rs` aggregates ElGamal-encrypted BLS signature shares from all participants by simple addition, with no proof-of-correct-computation check on any received share. A single malicious participant can send an arbitrary `(big_y, big_c)` pair, silently shifting the final `CKDOutput` to an attacker-chosen wrong value. The coordinator (TEE) then calls `unmask()` on this corrupted output and derives an incorrect confidential key, with no mechanism to detect the corruption.

---

### Finding Description

The CKD coordinator path in `do_ckd_coordinator` collects each participant's `CKDOutput` and accumulates it:

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

Each participant is supposed to send `(λ_i · y_i · G, λ_i · (x_i · H(pk‖app_id) + y_i · app_pk))`. There is no commitment, no Schnorr proof, and no pairing check to enforce this. Any participant can instead send an arbitrary group element pair `(Δ_Y, Δ_C)`.

The `compute_signature_share` function that honest participants use is:

```rust
let big_y = ElementG1::generator() * y.0;
let big_s = hash_point * private_share.to_scalar();
let big_c = big_s + app_pk * y.0;
``` [2](#0-1) 

Nothing in the protocol forces a participant to use their actual `private_share` or a valid `y`. The coordinator has no way to distinguish a correct share from a fabricated one.

The `unmask` function that the TEE calls on the final output performs no verification either:

```rust
pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
    self.big_c - self.big_y * secret_scalar
}
``` [3](#0-2) 

The README explicitly notes that no verification algorithm is implemented inside the protocol: [4](#0-3) 

Contrast this with the DKG protocol, which enforces correctness of every participant's contribution through polynomial commitments and Schnorr proofs of knowledge before accepting any share: [5](#0-4) 

The CKD protocol has no equivalent safeguard.

---

### Impact Explanation

A malicious participant sends `(Δ_Y, Δ_C)` of their choice. The coordinator's final output becomes:

```
big_Y_final = Σ_{honest i} λ_i·y_i·G  +  Δ_Y
big_C_final = Σ_{honest i} λ_i·(x_i·H + y_i·A)  +  Δ_C
```

After `unmask(app_sk)`:

```
derived_key = big_C_final − app_sk · big_Y_final
            = msk·H(pk‖app_id)  +  (Δ_C − app_sk · Δ_Y)
```

The TEE derives a key that differs from the correct `msk·H(pk‖app_id)` by an attacker-controlled additive term `(Δ_C − app_sk · Δ_Y)`. Because the attacker does not know `app_sk`, they cannot target a specific known key, but they can guarantee the output is wrong. The TEE silently accepts and uses this corrupted key.

**Allowed impact matched**: *High — Corruption of CKD outputs so honest parties accept inconsistent or unusable cryptographic outputs.*

---

### Likelihood Explanation

Any single participant in the CKD session can trigger this. The attacker needs only to be a registered participant (an unprivileged library caller). No special privilege, no leaked key, and no cryptographic break is required. The attack is a single-round, single-message substitution with no observable side-effect to the coordinator.

---

### Recommendation

Add a proof-of-correct-computation to each participant's CKD share before the coordinator accepts it. Two concrete options:

1. **Pairing-based verification (post-aggregation):** After `unmask`, the coordinator checks `e(derived_key, G2) == e(H(pk‖app_id), pk)` using the BLS12-381 pairing. This catches corruption of the aggregate but does not identify the malicious participant.

2. **Per-share ZK proof (pre-aggregation, preferred):** Each participant attaches a Chaum-Pedersen / DLEQ proof showing that `big_c − app_pk · big_y` lies on the correct coset (i.e., is a scalar multiple of `H(pk‖app_id)` consistent with their committed public share). The coordinator verifies each proof before adding the share, enabling identification and exclusion of the malicious participant.

Option 2 is consistent with how the DKG protocol already handles participant contributions. [6](#0-5) 

---

### Proof of Concept

```
Setup: 3 participants P1 (honest), P2 (honest), P3 (malicious), coordinator = P1.

1. P1 and P2 compute correct shares (norm_big_y_i, norm_big_c_i) and send to P1.
2. P3 sends (Δ_Y = G1::generator(), Δ_C = G1::identity()) instead of its real share.
3. Coordinator accumulates:
     big_Y_final = correct_Y + G
     big_C_final = correct_C + 0
4. unmask(app_sk) returns:
     msk·H(pk‖app_id) + (0 − app_sk · G)   ← wrong key, no error raised
5. TEE uses this wrong key silently; any data encrypted under the correct key
   is permanently inaccessible (denial of CKD for honest parties).
```

No error is returned by `do_ckd_coordinator` or `unmask`. The corruption is undetectable by the coordinator. [1](#0-0) [3](#0-2)

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

**File:** src/confidential_key_derivation/protocol.rs (L165-174)
```rust
    let big_y = ElementG1::generator() * y.0;

    // H(pk || app_id) when H is a random oracle
    let hash_point = hash_app_id_with_pk(&key_pair.public_key, app_id);

    // S <- x . H(app_id)
    let big_s = hash_point * private_share.to_scalar();

    // C <- S + y . A
    let big_c = big_s + app_pk * y.0;
```

**File:** src/confidential_key_derivation/mod.rs (L54-56)
```rust
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```

**File:** README.md (L137-140)
```markdown
* We do not implement any verification algorithm. In fact, a party possessing
  the message-signature pair can simply run the verification algorithm of the
  corresponding classic, non-distributed scheme using the master verification
  key.
```

**File:** src/dkg.rs (L479-496)
```rust
    // Verify vk asap
    // cannot fail as all_commitments at least contains my commitment
    let all_commitments_refs = all_full_commitments.to_refs_or_none().ok_or_else(|| {
        ProtocolError::AssertionFailed("all_full_commitments is empty".to_string())
    })?;
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
