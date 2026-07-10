### Title
Malicious Participant Can Corrupt CKD Output by Sending Unauthenticated G1 Shares — (`src/confidential_key_derivation/protocol.rs`)

### Summary
`do_ckd_coordinator` aggregates `(norm_big_y, norm_big_c)` shares from all participants with no proof of correct formation. Any participant in the protocol can substitute arbitrary G1 points, causing the coordinator to produce a `CKDOutput` whose unmasked value is not `msk · H(pk ∥ app_id)`.

### Finding Description
In `do_ckd_coordinator`, the coordinator receives each participant's `CKDOutput` via `recv_from_others` and unconditionally adds the two G1 fields into the running sum: [1](#0-0) 

`recv_from_others` is a generic helper that only requires `T: serde::de::DeserializeOwned`; it performs no cryptographic check on the received values: [2](#0-1) 

The honest computation each participant is supposed to perform is:

```
Y_i  = y_i · G
C_i  = x_i · H(pk ∥ app_id) + y_i · app_pk
norm_Y_i = λ_i · Y_i
norm_C_i = λ_i · C_i
``` [3](#0-2) 

There is no zero-knowledge proof, commitment, or any other binding that forces a participant to send values derived from their actual key share `x_i`. A malicious participant can send any two valid-on-curve G1 points instead.

### Impact Explanation
The final `CKDOutput` is:

```
Y  = Σ norm_Y_i
C  = Σ norm_C_i
``` [4](#0-3) 

If participant j substitutes `(big_y', big_c')` for their honest share, the unmasked result becomes:

```
C' − a·Y' = msk·H(pk∥app_id) + (big_c' − λ_j·C_j) − a·(big_y' − λ_j·y_j·G)
```

Because the attacker does not know the app secret key `a`, they cannot steer the unmasked value to a specific target — so the **Critical** framing (attacker-chosen derived key) is not achievable. However, the attacker can trivially corrupt the output (e.g., send identity points for both fields), causing `unmask` to return a value that is not `msk · H(pk ∥ app_id)`. The coordinator and client accept this corrupted `CKDOutput` with no error, satisfying the **High** impact category: corruption of CKD outputs so honest parties accept unusable cryptographic outputs. [5](#0-4) 

### Likelihood Explanation
Any single participant in the protocol can mount this attack. The participant is already an authenticated member of the `ParticipantList` (checked at initialization), so no external privilege is required. The attack requires only that the participant deviate from the protocol by sending crafted bytes over the message channel — a straightforward implementation-level action.

### Recommendation
Each participant must accompany their `(norm_big_y, norm_big_c)` with a non-interactive zero-knowledge proof of correct formation (e.g., a Schnorr-style proof showing knowledge of `y_i` and `x_i` such that `Y_i = y_i·G` and `C_i = x_i·H(pk∥app_id) + y_i·app_pk`). The coordinator must verify all proofs before aggregating. Alternatively, a commitment scheme can be used: participants commit to their share before revealing it, and the coordinator verifies the opening.

### Proof of Concept
```rust
// Malicious participant: instead of calling compute_signature_share,
// send identity points (or any arbitrary G1 points).
let crafted_big_y = ElementG1::identity();
let crafted_big_c = ElementG1::identity();
chan.send_private(waitpoint, coordinator, &CKDOutput::new(crafted_big_y, crafted_big_c))?;

// The coordinator will sum these in without any check (lines 50-55 of protocol.rs),
// producing a CKDOutput where unmask(app_sk) ≠ msk · H(pk ∥ app_id).
```

A fuzz test injecting random G1 pairs as participant messages and asserting `ckd_output.unmask(app_sk) == expected_key` will reliably fail, confirming the corruption.

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L44-56)
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
```

**File:** src/confidential_key_derivation/protocol.rs (L159-181)
```rust
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

**File:** src/confidential_key_derivation/mod.rs (L52-56)
```rust
    /// Takes a secret scalar and returns
    /// s <- C − a ⋅ Y = msk ⋅ H ( `app_id` )
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```
