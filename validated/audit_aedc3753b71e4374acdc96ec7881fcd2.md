### Title
Malicious Participant Can Inject Inconsistent `SigningCommitments` During Presign, Permanently Breaking `sign_v2` Sessions — (`src/frost/mod.rs`, `src/frost/eddsa/sign.rs`)

---

### Summary

`do_presign` exchanges nonce commitments via `send_many`, which is explicitly **not a reliable broadcast**. Each participant stores received commitments locally in their own `PresignOutput.commitments_map` with no cross-validation. In `sign_v2`, every participant independently reconstructs a `SigningPackage` from their local `commitments_map`. A malicious participant who sends different `SigningCommitments` to different honest parties causes each honest party to build a different `SigningPackage`, making their signature shares cryptographically incompatible. The coordinator's `aggregate()` call then fails or produces an invalid signature, permanently breaking the signing session.

---

### Finding Description

**Step 1 — Presign: no broadcast consistency**

In `do_presign`, each participant generates a commitment and broadcasts it with `send_many`: [1](#0-0) 

`send_many` is explicitly documented as **not a reliable broadcast**: [2](#0-1) 

`recv_from_others` simply collects one message per participant with no cross-participant consistency check: [3](#0-2) 

There is no echo broadcast, no hash commitment, and no cross-validation of received commitments. Each participant's `PresignOutput.commitments_map` is built entirely from what they individually received.

**Step 2 — sign_v2: each participant builds their own `SigningPackage` locally**

In `do_sign_participant_v2`, the participant constructs a `SigningPackage` directly from their local `presignature.commitments_map` and immediately computes a signature share: [4](#0-3) 

In `do_sign_coordinator_v2`, the coordinator does the same: [5](#0-4) 

**Contrast with sign_v1:** In `sign_v1`, the coordinator broadcasts the `SigningPackage` to all participants, ensuring a single consistent view: [6](#0-5) 

`sign_v2` has no equivalent broadcast step. Each participant uses their own locally-stored `commitments_map` without any consistency guarantee.

**Step 3 — Aggregate fails**

The coordinator collects signature shares computed over different `SigningPackage`s and calls `aggregate()`: [7](#0-6) 

Because FROST's binding factor and challenge are derived from the full commitment set, shares computed over different `SigningPackage`s are cryptographically incompatible. `aggregate()` returns an error (mapped to `ProtocolError::AssertionFailed`), permanently breaking the signing session.

---

### Impact Explanation

A malicious participant sends commitment `C1` to participant A and commitment `C2` to participant B during presign. After presign:
- A holds `commitments_map = {A: Ca, B: Cb, M: C1}`
- B holds `commitments_map = {A: Ca, B: Cb, M: C2}`

In `sign_v2`, A and B each build a different `SigningPackage`. Their signature shares are computed over different binding factors and challenges. The coordinator's `aggregate()` call fails. The signing session is permanently broken for all honest parties.

**Impact:** High — Permanent denial of signing for honest parties under valid protocol inputs.

---

### Likelihood Explanation

The attack requires only a single malicious participant in the signing group. The attacker controls what bytes they deliver to each peer (the `message()` call on each participant's `Protocol` instance). The `send_many` action explicitly provides no consistency guarantee. No cryptographic assumption needs to be broken. The attack is fully local and testable.

---

### Recommendation

Replace the plain `send_many` in `do_presign` with an echo broadcast (the same `do_broadcast` used in DKG), or add a consistency-check round where participants exchange hashes of their received `commitments_map` and abort if any mismatch is detected. Alternatively, adopt the `sign_v1` pattern in `sign_v2`: have the coordinator broadcast the assembled `SigningPackage` to all participants before they compute their shares, so all parties sign over an identical commitment set.

---

### Proof of Concept

```rust
// Simulate presign with a malicious participant M that sends C1 to A and C2 to B.
// After presign:
//   presign_output_a.commitments_map[M] == C1
//   presign_output_b.commitments_map[M] == C2
//
// Run sign_v2 for A and B with their respective presign outputs.
// Assert that aggregate() returns Err or the resulting signature fails verification.

let signing_package_a = SigningPackage::new(presign_output_a.commitments_map, message);
let signing_package_b = SigningPackage::new(presign_output_b.commitments_map, message);
// signing_package_a != signing_package_b  =>  shares are incompatible
// aggregate() on the coordinator returns ProtocolError::AssertionFailed
```

The inconsistency is introduced at the network layer (the test harness delivers different bytes to different participants for the same `SendMany` action), which is within the documented threat model for a malicious participant.

### Citations

**File:** src/frost/mod.rs (L101-111)
```rust
    let (nonces, commitments) = commit(&signing_share, &mut rng);
    commitments_map.insert(me.to_identifier()?, commitments);

    let commit_waitpoint = chan.next_waitpoint();
    // Sending the commitments to all
    chan.send_many(commit_waitpoint, &commitments)?;

    // Collecting the commitments
    for (from, commitment) in recv_from_others(&chan, commit_waitpoint, &participants, me).await? {
        commitments_map.insert(from.to_identifier()?, commitment);
    }
```

**File:** src/protocol/README.md (L24-24)
```markdown
- `SendMany(data)` -- send the same message to all other participants (not a reliable broadcast)
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

**File:** src/frost/eddsa/sign.rs (L136-137)
```rust
    let r2_wait_point = chan.next_waitpoint();
    chan.send_many(r2_wait_point, &signing_package)?;
```

**File:** src/frost/eddsa/sign.rs (L189-202)
```rust
    let signing_package =
        frost_ed25519::SigningPackage::new(presignature.commitments_map, message.as_slice());

    let mut signature_shares: BTreeMap<frost_ed25519::Identifier, round2::SignatureShare> =
        BTreeMap::new();

    let vk_package = keygen_output.public_key;

    let key_package =
        construct_key_package(threshold, me, keygen_output.private_share, &vk_package)?;

    let key_package = Zeroizing::new(key_package);
    let signature_share = round2::sign(&signing_package, &presignature.nonces, &key_package)
        .map_err(|e| ProtocolError::AssertionFailed(e.to_string()))?;
```

**File:** src/frost/eddsa/sign.rs (L219-220)
```rust
    let signature = aggregate(&signing_package, &signature_shares, &public_key_package)
        .map_err(|e| ProtocolError::AssertionFailed(e.to_string()))?;
```

**File:** src/frost/eddsa/sign.rs (L339-344)
```rust
    let signing_package = SigningPackage::new(presignature.commitments_map, message);
    let signature_share = round2::sign(&signing_package, &presignature.nonces, &key_package)
        .map_err(|e| ProtocolError::AssertionFailed(e.to_string()))?;

    let sign_waitpoint = chan.next_waitpoint();
    chan.send_private(sign_waitpoint, coordinator, &signature_share)?;
```
