Now I have all the information needed. Let me verify the serde path for `CKDOutput` vs the frost_core Group deserialization path.

### Title
Malicious Participant Can Corrupt CKD Output by Sending G1 Identity Points — (`src/confidential_key_derivation/protocol.rs`)

### Summary

`do_ckd_coordinator` aggregates `CKDOutput` messages from all participants with no validation of the received G1 points. A malicious participant can send `big_y = G1::identity()` and `big_c = G1::identity()`, which deserializes successfully via blstrs's serde implementation (bypassing the `frost_core::Group::deserialize` identity check), causing the coordinator to silently exclude that participant's contribution from the aggregation. The resulting derived key is cryptographically wrong and fails `verify_signature`.

---

### Finding Description

`CKDOutput` is declared with `#[derive(Deserialize, Serialize)]` over raw `ElementG1 = blstrs::G1Projective`: [1](#0-0) 

This uses **blstrs's own serde implementation**, not the `frost_core::Group` trait methods. The `BLS12381G1Group::deserialize` implementation that rejects identity points: [2](#0-1) 

...is only invoked for FROST-internal serialization paths. It is **never called** when `CKDOutput` is deserialized via serde in the protocol message flow.

In blstrs, `G1Projective::from_compressed()` returns `Some(identity)` for the BLS12-381 point-at-infinity encoding (the infinity flag byte), so the identity point round-trips through serde without error.

`recv_from_others` performs no content validation — it only tracks which participants have sent a message: [3](#0-2) 

`do_ckd_coordinator` then unconditionally adds the received values to its running sums: [4](#0-3) 

Adding the identity point is a no-op in the group, so the malicious participant's share is silently dropped from the aggregation.

---

### Impact Explanation

The correct CKD invariant is:

```
C - a*Y  =  Σ_i λ_i * x_i * H(pk||app_id)  =  msk * H(pk||app_id)
```

If participant `j` sends `(identity, identity)`, the coordinator computes:

```
Y'  =  Σ_{i≠j} λ_i * y_i * G
C'  =  Σ_{i≠j} λ_i * (x_i * H(pk||app_id) + y_i * A)
```

The unmasked result `C' - a*Y'` equals `Σ_{i≠j} λ_i * x_i * H(pk||app_id)`, which is **not** `msk * H(pk||app_id)`. The output is a wrong, unusable derived key. `verify_signature` will fail for any consumer of the output.

Impact: **High — Corruption of CKD output so honest parties accept an unusable cryptographic output.**

---

### Likelihood Explanation

Any participant in the CKD protocol can trivially craft and send a `CKDOutput` with identity points at the correct waitpoint. No cryptographic assumption needs to be broken. The attack requires only that the attacker controls one participant slot, which is within the standard threshold adversary model (up to `t-1` malicious participants).

---

### Recommendation

In `do_ckd_coordinator`, validate each received `CKDOutput` before adding it to the running sums. Reject any message where either `big_y` or `big_c` is the G1 identity:

```rust
for (from, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    if participant_output.big_y().is_identity().into()
        || participant_output.big_c().is_identity().into()
    {
        return Err(ProtocolError::AssertionFailed(
            format!("participant {from:?} sent identity point in CKD output"),
        ));
    }
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

Alternatively, add a `CKDOutput::validate(&self) -> Result<(), ProtocolError>` method and call it on every received message.

---

### Proof of Concept

```rust
#[test]
fn test_ckd_identity_point_attack() {
    use blstrs::G1Projective;
    use group::Group;

    // Normal CKD setup with 3 participants, threshold 2
    // ... (standard setup as in test_ckd) ...

    // Malicious participant sends identity points instead of real share
    let malicious_output = CKDOutput::new(G1Projective::identity(), G1Projective::identity());

    // Serialize and inject into the coordinator's message channel at the correct waitpoint
    // The coordinator accepts it (no identity check), adds identity (no-op)
    // Final aggregated output is missing malicious participant's contribution

    // Unmask and verify — this will fail
    let confidential_key = ckd_output.unmask(app_sk);
    assert!(
        verify_signature(&public_key, &app_id, &confidential_key).is_err(),
        "Derived key is wrong due to missing participant contribution"
    );
}
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

**File:** src/confidential_key_derivation/ciphersuite.rs (L202-213)
```rust
    fn deserialize(buf: &Self::Serialization) -> Result<Self::Element, frost_core::GroupError> {
        Self::Element::from_compressed(buf).into_option().map_or(
            Err(frost_core::GroupError::MalformedElement),
            |point| {
                if point.is_identity().into() {
                    Err(frost_core::GroupError::InvalidIdentityElement)
                } else {
                    Ok(point)
                }
            },
        )
    }
```

**File:** src/protocol/helpers.rs (L6-27)
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
}
```

**File:** src/confidential_key_derivation/protocol.rs (L50-57)
```rust
    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
    Ok(Some(ckd_output))
```
