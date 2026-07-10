### Title
Missing Validation of Participant Contributions in CKD Protocol Allows Malicious Participant to Corrupt Derived Key Output - (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The CKD coordinator blindly accumulates `(big_y, big_c)` group-element contributions from every participant with no proof of correctness. A single malicious participant can substitute arbitrary curve points, causing the coordinator to assemble and return a `CKDOutput` whose `unmask` result is not `msk · H(pk ‖ app_id)`. Honest callers have no mechanism to detect or bound this deviation — a direct structural analog to the missing slippage controls in the ERC-4626 report.

---

### Finding Description

In `do_ckd_coordinator` (`src/confidential_key_derivation/protocol.rs`, lines 35–57), the coordinator receives one `CKDOutput` tuple per peer and unconditionally adds both fields into running accumulators:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();   // line 53
    norm_big_c += participant_output.big_c();   // line 54
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);  // line 56
Ok(Some(ckd_output))
```

Each honest participant `i` is supposed to send:

```
big_Y_i = λ_i · y_i · G₁
big_C_i = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)
```

so that the coordinator's sum satisfies `C − a·Y = msk · H(pk ‖ app_id)`.

No zero-knowledge proof, commitment, or consistency check is attached to these values. The coordinator cannot distinguish a correctly-formed contribution from an arbitrary pair of `G₁` points. Compare this with the DKG protocol (`src/dkg.rs`), which enforces `verify_proof_of_knowledge` (lines 452–460) and `verify_commitment_hash` (lines 463–469) before accepting any participant's material — the CKD protocol has no equivalent gate.

The `compute_signature_share` helper (`src/confidential_key_derivation/protocol.rs`, lines 148–182) correctly computes the honest values, but nothing in the coordinator path checks that what arrives over the wire matches what `compute_signature_share` would have produced.

---

### Impact Explanation

**High — Corruption of CKD output so honest parties accept an unusable or attacker-influenced derived key.**

Let participant `j` be malicious and send `(big_Y_j*, big_C_j*)` of its choice instead of the honest values. The coordinator computes:

```
Y_final  = Y_honest + big_Y_j*
C_final  = C_honest + big_C_j*
```

The requester then calls `CKDOutput::unmask(app_sk)`:

```rust
pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
    self.big_c - self.big_y * secret_scalar   // mod.rs line 55
}
```

which yields:

```
(C_honest + big_C_j*) − a·(Y_honest + big_Y_j*)
= msk·H(pk‖app_id) + (big_C_j* − a·big_Y_j*)
```

The extra term `big_C_j* − a·big_Y_j*` is non-zero for any `(big_Y_j*, big_C_j*)` not equal to the honest contribution, so the derived confidential key is wrong. Because `a` (the app secret key) is unknown to the attacker, the attacker cannot steer the output to a specific target key, but they can reliably corrupt it to an unpredictable value, rendering the CKD output unusable for every honest party.

---

### Likelihood Explanation

Any participant in the CKD session is a reachable, unprivileged attacker. The `ckd()` entry point (`src/confidential_key_derivation/protocol.rs`, lines 66–117) requires only that the caller is listed in `participants` and that `participants.len() >= 2`. There is no threshold for the CKD aggregation — all participants contribute, so a single malicious participant is sufficient to corrupt the output. No special privilege, leaked key, or cryptographic break is required.

---

### Recommendation

Add a zero-knowledge proof of correct formation to each participant's contribution, analogous to the `proof_of_knowledge` / `verify_proof_of_knowledge` pattern already used in `src/dkg.rs` (lines 118–141 and 145–166). Concretely, each participant should prove in zero knowledge that `big_C_i − y_i · app_pk` lies on the line `x_i · H(pk ‖ app_id)` (i.e., a Schnorr-style DLEQ proof relating `big_Y_i` and `big_C_i` to the participant's committed key share). The coordinator must verify all proofs before summing. Alternatively, the protocol documentation should explicitly state that all participants are assumed honest and that the CKD output must be verified by the requester against the expected public output `msk · H(pk ‖ app_id)` using `verify_signature` (`src/confidential_key_derivation/ciphersuite.rs`, lines 218–244) before use.

---

### Proof of Concept

1. A session is started with participants `[P1, P2, P3]` where `P3` is malicious and `P1` is the coordinator.
2. `P3` calls `ckd(...)` but, instead of running `compute_signature_share`, sends `(G₁, G₁)` (the generator point) as its `(big_y, big_c)` contribution to the coordinator.
3. The coordinator's loop at lines 50–55 adds these unchecked values into `norm_big_y` and `norm_big_c`.
4. The returned `CKDOutput` satisfies `big_c − a·big_y ≠ msk·H(pk‖app_id)`.
5. The requester calls `unmask(app_sk)` and obtains a wrong key with no error or indication of failure.
6. Every downstream operation that depends on the derived confidential key silently uses an incorrect value. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L48-57)
```rust
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

**File:** src/confidential_key_derivation/mod.rs (L54-56)
```rust
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```

**File:** src/dkg.rs (L452-469)
```rust
        verify_proof_of_knowledge(
            &session_id,
            &mut proof_domain_separator.clone(), // you want to have the same state
            threshold,
            p,
            old_participants.clone(),
            commitment_i,
            proof_i.as_ref(),
        )?;

        // verify that the commitment sent hashes to the received commitment_hash in round 1
        verify_commitment_hash(
            &session_id,
            p,
            &mut commit_domain_separator.clone(), // you want to have the same state
            commitment_i,
            &all_hash_commitments,
        )?;
```

**File:** src/confidential_key_derivation/ciphersuite.rs (L218-244)
```rust
pub fn verify_signature(
    verifying_key: &VerifyingKey,
    msg: &[u8],
    signature: &Signature,
) -> Result<(), frost_core::Error<BLS12381SHA256>> {
    let element1: G1Affine = signature.into();
    if (!element1.is_on_curve() | !element1.is_torsion_free() | element1.is_identity()).into() {
        return Err(frost_core::Error::InvalidSignature);
    }
    let element2: G2Affine = verifying_key.to_element().into();
    if (!element2.is_on_curve() | !element2.is_torsion_free() | element2.is_identity()).into() {
        return Err(frost_core::Error::MalformedVerifyingKey);
    }

    // Concatenate the master public key (96 bytes) in the hash computation
    // H(pk || app_id) when H is a random oracle
    let base1 = hash_app_id_with_pk(verifying_key, msg).into();
    let base2 =
        <<BLS12381SHA256 as frost_core::Ciphersuite>::Group as frost_core::Group>::generator()
            .into();

    if blstrs::pairing(&base1, &element2).eq(&blstrs::pairing(&element1, &base2)) {
        Ok(())
    } else {
        Err(frost_core::Error::InvalidSignature)
    }
}
```
