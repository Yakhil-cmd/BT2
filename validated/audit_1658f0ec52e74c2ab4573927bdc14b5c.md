### Title
Missing Output Verification in CKD Coordinator Allows Malicious Participant to Corrupt Derived Key - (`src/confidential_key_derivation/protocol.rs`)

### Summary

The `do_ckd_coordinator` function in `src/confidential_key_derivation/protocol.rs` aggregates participant BLS signature shares into a `CKDOutput` without performing any verification of the final result. Unlike the ECDSA coordinator, which calls `sig.verify()` before returning, the CKD coordinator never calls `verify_signature` on the aggregated output. A single malicious participant can send an arbitrary `(big_y, big_c)` contribution, silently corrupting the `CKDOutput` returned to the caller.

### Finding Description

The `do_ckd_coordinator` function receives `CKDOutput` contributions from each participant and sums them: [1](#0-0) 

No validation is performed on the individual contributions, and no verification of the final aggregated output is performed before returning it. The function `verify_signature` exists in `src/confidential_key_derivation/ciphersuite.rs` and is capable of checking a BLS signature against the master public key: [2](#0-1) 

However, it is never called anywhere inside the production protocol path — only in tests.

By contrast, both ECDSA coordinators explicitly verify the final signature before returning: [3](#0-2) [4](#0-3) 

The CKD coordinator has no equivalent check. The coordinator does have access to `key_pair.public_key` and `app_id`, which are the inputs needed to call `verify_signature` — but it lacks `app_sk` (the ElGamal private key needed to unmask the encrypted signature). This means the coordinator cannot verify the final unmasked BLS signature directly. However, the absence of any per-contribution validation (e.g., a ZK proof from each participant that their `(norm_big_y, norm_big_c)` is correctly formed) means a malicious participant's corrupted share passes through silently.

**Attack path:**
1. A malicious participant `P_m` calls `ckd(...)` and, instead of computing the correct `(norm_big_y, norm_big_c)`, sends arbitrary group elements (e.g., the identity, or random points) to the coordinator.
2. `do_ckd_coordinator` receives the malicious contribution via `recv_from_others` and adds it to the running sum without any check.
3. The coordinator returns a `CKDOutput` that is cryptographically invalid — `C - a*Y ≠ msk * H(pk || app_id)`.
4. The caller receives `Some(CKDOutput)` with no error, treating the corrupted output as a valid protocol result.
5. When the client calls `ckd_output.unmask(app_sk)`, they obtain a point that fails `verify_signature`, yielding an unusable derived key. [5](#0-4) 

### Impact Explanation

A single malicious participant can corrupt the `CKDOutput` for all honest parties. The coordinator returns the corrupted output with `Ok(Some(...))`, giving no indication of failure. Honest parties and the coordinator accept the output as valid. The derived key is unusable, and the corruption is undetectable at the protocol level. This matches: **High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

### Likelihood Explanation

Any single participant who deviates from the protocol can trigger this. No special privilege is required beyond being a valid participant in the CKD session. The attacker-controlled entry point is the `chan.send_private` call in `do_ckd_participant`, where the malicious participant sends arbitrary `(norm_big_y, norm_big_c)` values. [6](#0-5) 

### Recommendation

Add per-contribution validation from participants. Each participant should accompany their `(norm_big_y, norm_big_c)` with a zero-knowledge proof of correct formation (e.g., a proof that `norm_big_c` is consistent with their public key share and the `app_id`). Alternatively, the coordinator should propagate the `CKDOutput` to the client with a clear indication that it is unverified, and the client must call `verify_signature` after unmasking before trusting the derived key. At minimum, document that the CKD output is not authenticated against malicious participants, unlike the ECDSA signing output.

### Proof of Concept

In `src/confidential_key_derivation/protocol.rs`, replace the honest `compute_signature_share` call in `do_ckd_participant` with a send of `(ElementG1::identity(), ElementG1::identity())`. The coordinator will sum this with honest contributions, producing a `CKDOutput` where `C - a*Y ≠ msk * H(pk || app_id)`. The protocol returns `Ok(Some(corrupted_output))` with no error. Calling `verify_signature(&public_key, &app_id, &corrupted_output.unmask(app_sk))` will return `Err(InvalidSignature)`, confirming the output is unusable. [7](#0-6)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L27-32)
```rust
    let (norm_big_y, norm_big_c) =
        compute_signature_share(participants, me, key_pair, app_id, app_pk, rng)?;
    let waitpoint = chan.next_waitpoint();
    chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;

    Ok(None)
```

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

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L129-133)
```rust
    if !sig.verify(&public_key, &msg_hash) {
        return Err(ProtocolError::AssertionFailed(
            "signature failed to verify".to_string(),
        ));
    }
```

**File:** src/ecdsa/robust_ecdsa/sign.rs (L159-163)
```rust
    if !sig.verify(&public_key, &msg_hash) {
        return Err(ProtocolError::AssertionFailed(
            "signature failed to verify".to_string(),
        ));
    }
```

**File:** src/confidential_key_derivation/mod.rs (L54-56)
```rust
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```
