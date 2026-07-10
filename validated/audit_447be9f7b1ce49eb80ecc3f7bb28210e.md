The vulnerability is real. Let me confirm the exact code path before writing the report.

The coordinator in `do_ckd_coordinator` receives `CKDOutput` structs from participants and blindly aggregates them: [1](#0-0) 

There is no zero-knowledge proof or consistency check binding `norm_big_y` and `norm_big_c` to the same scalar `y`. The `recv_from_others` helper simply deserializes and returns messages: [2](#0-1) 

`compute_signature_share` uses a single `y` for both `big_y = y * G` and `big_c = big_s + y * app_pk`, but an attacker bypasses this function entirely and sends arbitrary bytes: [3](#0-2) 

---

### Title
Missing ElGamal Consistency Proof Allows Malicious Participant to Corrupt CKD Output — (`src/confidential_key_derivation/protocol.rs`)

### Summary
A malicious participant can send a `(norm_big_y, norm_big_c)` pair where `norm_big_y = λ_i · y' · G` and `norm_big_c = λ_i · (x_i · H(pk ‖ app_id) + y · app_pk)` with `y' ≠ y`. The coordinator aggregates these without any consistency check, producing a `CKDOutput` whose `unmask` result deviates from `msk · H(pk ‖ app_id)` by an attacker-controlled group element.

### Finding Description
In `do_ckd_coordinator` (lines 50–55), the coordinator iterates over messages received via `recv_from_others` and unconditionally adds each participant's `big_y` and `big_c` contributions:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

There is no proof that the same scalar `y` was used in both components. A malicious participant can craft any `CKDOutput` struct (it is `pub` with a `pub fn new(...)` constructor) and send it. The protocol is a single round with no challenge-response, so there is no opportunity for the coordinator to verify consistency.

### Impact Explanation
Let the attacker choose scalars `y` and `y'` with `y ≠ y'`. They send:
- `norm_big_c = λ_i · (x_i · H(pk ‖ app_id) + y · app_pk)` (correct C)
- `norm_big_y = λ_i · y' · G` (wrong Y)

After aggregation:
- `C = msk · H(pk ‖ app_id) + (y_honest + y) · app_pk`
- `Y = (y_honest + y') · G`

Unmask: `C − a · Y = msk · H(pk ‖ app_id) + a · (y − y') · G`

The deviation `a · (y − y') · G` is non-zero and attacker-controlled in magnitude `(y − y')`. The honest app derives a wrong key. This matches **High: Corruption of CKD outputs so honest parties accept unusable cryptographic outputs**.

The impact does not reach Critical because the attacker does not know `a` (the app's ElGamal secret key), so they cannot predict or compute the actual deviation — they can corrupt but not steer the output to a chosen value.

### Likelihood Explanation
Any single valid participant in the participant list can execute this attack. The attacker only needs to construct a `CKDOutput` with mismatched fields and inject it via the private channel to the coordinator. No cryptographic assumption needs to be broken. The attack is single-round and requires no interaction beyond normal protocol participation.

### Recommendation
Require each participant to provide a zero-knowledge proof of consistency between `norm_big_y` and `norm_big_c` — specifically, a Chaum-Pedersen DLEQ proof showing that the discrete log of `norm_big_y` with respect to `G` equals the discrete log of `(norm_big_c − norm_big_s)` with respect to `app_pk`, where `norm_big_s = λ_i · x_i · H(pk ‖ app_id)` is the participant's public BLS share contribution (verifiable from the public key). The coordinator must verify this proof before accepting any contribution.

### Proof of Concept
```rust
// Malicious participant sends mismatched (Y', C) where Y' uses y'=0 instead of y
let y = Scalar::random(&mut rng);
let big_c_honest = hash_point * x_i + app_pk * y;  // correct C with y
let norm_big_c = big_c_honest * lambda_i;
let norm_big_y = ElementG1::identity();             // Y' = 0*G, i.e. y'=0

// Coordinator aggregates without checking consistency
// Result: unmask(app_sk) = msk*H(pk||app_id) + app_sk * y * G
//                        ≠ msk*H(pk||app_id)
// The deviation is app_sk * y * G, which is non-zero with overwhelming probability.
assert_ne!(ckd_output.unmask(app_sk), expected_confidential_key);
```

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

**File:** src/confidential_key_derivation/protocol.rs (L159-180)
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
