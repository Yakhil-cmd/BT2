### Title
Malicious Participant Can Corrupt CKD Output by Swapping `big_y`/`big_c` Fields — (`src/confidential_key_derivation/protocol.rs`)

### Summary
The CKD coordinator aggregates participant contributions with no content validation. A valid-but-malicious participant can send a `CKDOutput`-shaped message with `big_y` and `big_c` swapped. The coordinator blindly adds the swapped values, producing a semantically corrupted `CKDOutput` that will never unmask to the correct BLS signature.

### Finding Description

In `do_ckd_coordinator`, the coordinator receives each participant's contribution via `recv_from_others::<CKDOutput>` and immediately accumulates the fields:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [1](#0-0) 

`recv_from_others` only validates that the sender is a known participant (`seen.put(from)` returns true iff the sender is in the participant list and not yet seen). It performs **zero content validation**:

```rust
if seen.put(from) {
    messages.push((from, msg));
}
``` [2](#0-1) 

`CKDOutput` has two fields of identical type `ElementG1`:

```rust
pub struct CKDOutput {
    big_y: ElementG1,
    big_c: ElementG1,
}
``` [3](#0-2) 

Because both fields are the same type, a message with the two G1 points in swapped order is a perfectly valid deserialization. There is no zero-knowledge proof, commitment, or any other binding that ties the received `big_y` to a scalar `y` and `big_c` to `x_i·H + y_i·A`.

A malicious participant computes the correct `(norm_big_y, norm_big_c)` via `compute_signature_share` but transmits `(norm_big_c, norm_big_y)`. The coordinator deserializes this as `CKDOutput { big_y: norm_big_c, big_c: norm_big_y }` and adds the swapped values into the running totals. [4](#0-3) 

### Impact Explanation

The resulting aggregated output has:
- `big_Y = Y_coordinator + Σ_honest(λ_i·Y_i) + λ_attacker·C_attacker`
- `big_C = C_coordinator + Σ_honest(λ_i·C_i) + λ_attacker·Y_attacker`

When the app calls `unmask(a)` — computing `big_C − a·big_Y` — the result is not `msk·H(pk, app_id)`. The app's BLS signature verification fails and the derived key is unrecoverable.

**The claimed "Critical" impact is overstated.** The attacker cannot force the output to unmask to a specific valid BLS signature (that would require solving discrete log). The actual impact is:

> **High: Corruption of CKD outputs so honest parties receive unusable cryptographic outputs**, matching the allowed High scope. A single malicious participant (1-of-n) can permanently deny CKD service by repeating this on every protocol run. [5](#0-4) 

### Likelihood Explanation

Any participant who is a valid member of the participant list can execute this. No special privilege beyond list membership is required. The attack is trivially repeatable and undetectable by the coordinator (no attribution is possible from the corrupted output alone).

### Recommendation

Add a zero-knowledge proof of knowledge (Schnorr PoK) binding each participant's `big_y` to the scalar `y` and `big_c` to `x_i·H + y_i·A`. At minimum, require participants to send a Schnorr proof that `big_y = y·G` for a known `y`, and that `big_c − big_s = y·A` for the committed `big_s = x_i·H`. The coordinator must verify these proofs before accumulating any contribution.

### Proof of Concept

```rust
// Malicious participant: swap big_y and big_c before sending
let (norm_big_y, norm_big_c) =
    compute_signature_share(&participants, me, key_pair, app_id, app_pk, rng)?;
let waitpoint = chan.next_waitpoint();
// Send swapped: big_y field gets norm_big_c, big_c field gets norm_big_y
chan.send_private(waitpoint, coordinator, &(norm_big_c, norm_big_y))?;
```

The coordinator accepts this without error. The resulting `CKDOutput` will fail `unmask(app_sk) == msk·H(pk, app_id)`, confirming corruption. A unit test injecting this swap and asserting `ckd_output.unmask(app_sk) != expected_confidential_key` would pass immediately. [6](#0-5)

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

**File:** src/protocol/helpers.rs (L21-23)
```rust
        if seen.put(from) {
            messages.push((from, msg));
        }
```

**File:** src/confidential_key_derivation/mod.rs (L31-35)
```rust
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CKDOutput {
    big_y: ElementG1,
    big_c: ElementG1,
}
```

**File:** src/confidential_key_derivation/mod.rs (L54-56)
```rust
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```
