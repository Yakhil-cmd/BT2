### Title
Missing Torsion-Free Check on Received G1 Points Allows CKD Output Corruption - (`src/confidential_key_derivation/mod.rs`, `src/confidential_key_derivation/protocol.rs`)

---

### Summary

`do_ckd_coordinator` aggregates `CKDOutput` messages from participants without verifying that the received G1 points are in the prime-order subgroup. A malicious participant can inject a small-subgroup-contaminated G1 point, causing the coordinator to produce a corrupted, unusable CKD output.

---

### Finding Description

`CKDOutput` is defined with plain serde derive: [1](#0-0) 

The fields `big_y` and `big_c` are `ElementG1 = blstrs::G1Projective`. Their serde deserialization goes through `blstrs`'s own implementation, which calls `blst_p1_uncompress` internally. That function checks the point is on the curve but **does not call `is_torsion_free()`**. BLS12-381's G1 has a non-trivial cofactor (h₁ ≈ 2⁷⁶), so points on the curve that are not in the prime-order subgroup exist and are representable in compressed form.

`recv_from_others` is a generic helper that deserializes via `rmp_serde` with no group-element validation: [2](#0-1) 

`do_ckd_coordinator` then directly adds the received points to the running aggregates: [3](#0-2) 

No `is_torsion_free()` check is performed anywhere on the received `big_y` or `big_c` before aggregation. The only place `is_torsion_free()` appears in the entire codebase is inside `verify_signature`, on the *output* signature: [4](#0-3) 

---

### Impact Explanation

A malicious participant sends a `CKDOutput` where `big_y` (or `big_c`) is a valid compressed G1 point that lies on the curve but outside the prime-order subgroup (i.e., has a non-trivial torsion component T of order dividing h₁). The coordinator adds T into the aggregated Y. The final `CKDOutput::unmask` result therefore contains a torsion component, and when `verify_signature` is called on it, the `!element1.is_torsion_free()` check at line 224 fires, returning `Err(frost_core::Error::InvalidSignature)`. Every honest party that relies on the CKD output receives an unusable result.

This matches: **High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

---

### Likelihood Explanation

- The attacker is any protocol participant (not the coordinator).
- Constructing a non-torsion-free BLS12-381 G1 point is trivial: take any random curve point P, compute T = r·P (where r is the prime order); if T ≠ ∞ then T is a small-subgroup point. Add T to any valid G1 point to get a contaminated point.
- No cryptographic assumption needs to be broken.
- The attack requires only one malicious participant and one protocol run.

---

### Recommendation

After deserializing each `CKDOutput` in `do_ckd_coordinator`, validate both G1 points before aggregating:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    let y_affine: G1Affine = participant_output.big_y().into();
    let c_affine: G1Affine = participant_output.big_c().into();
    if (!y_affine.is_torsion_free() | !y_affine.is_on_curve()).into() {
        return Err(ProtocolError::AssertionFailed("big_y not in prime-order subgroup".into()));
    }
    if (!c_affine.is_torsion_free() | !c_affine.is_on_curve()).into() {
        return Err(ProtocolError::AssertionFailed("big_c not in prime-order subgroup".into()));
    }
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

Alternatively, implement a custom serde deserializer for `ElementG1` that enforces the subgroup check at the type level, so no deserialization path can produce an out-of-subgroup point.

---

### Proof of Concept

```rust
// 1. Construct a small-subgroup point T on BLS12-381 G1.
//    r is the prime order of G1. Any random curve point P satisfies r·P ∈ small-subgroup.
let p = G1Projective::generator(); // in prime-order subgroup
// Multiply by r gives identity for in-subgroup points, but a random curve point
// not in the subgroup gives a non-identity torsion point.
// For a concrete torsion point, use a known cofactor-clearing construction in reverse.

// 2. Craft a CKDOutput with the torsion point as big_y.
let torsion_point: G1Projective = /* small-subgroup point */;
let malicious_output = CKDOutput::new(torsion_point, G1Projective::generator());

// 3. Serialize and inject as a participant message to the coordinator.
//    The coordinator's recv_from_others will deserialize it without torsion check.

// 4. After the protocol completes, call verify_signature on the CKD output.
//    It returns Err(InvalidSignature) because is_torsion_free() fails on the
//    aggregated signature, which now contains the torsion component.
assert!(verify_signature(&vk, app_id.as_bytes(), &ckd_output.unmask(app_sk)).is_err());
```

### Citations

**File:** src/confidential_key_derivation/mod.rs (L31-35)
```rust
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CKDOutput {
    big_y: ElementG1,
    big_c: ElementG1,
}
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

**File:** src/confidential_key_derivation/protocol.rs (L50-56)
```rust
    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
```

**File:** src/confidential_key_derivation/ciphersuite.rs (L224-226)
```rust
    if (!element1.is_on_curve() | !element1.is_torsion_free() | element1.is_identity()).into() {
        return Err(frost_core::Error::InvalidSignature);
    }
```
