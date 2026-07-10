### Title
Malicious Participant Can Corrupt CKD Output Without Validation in `do_ckd_coordinator` — (`src/confidential_key_derivation/protocol.rs`)

---

### Summary

In `do_ckd_coordinator`, the coordinator receives `(norm_big_y, norm_big_c)` group-element pairs from every participant and blindly accumulates them with no proof of correctness, no range check, and no consistency verification against the participant's committed key share. A single malicious participant can send arbitrary BLS12-381 G1 points to steer the aggregated `CKDOutput` to any value they choose, causing every honest consumer of that output to derive an incorrect confidential key.

---

### Finding Description

`do_ckd_coordinator` collects each participant's contribution and sums them:

```rust
// src/confidential_key_derivation/protocol.rs  lines 50-57
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
``` [1](#0-0) 

The honest computation each participant is supposed to perform is:

```rust
// src/confidential_key_derivation/protocol.rs  lines 159-180
let big_y  = ElementG1::generator() * y.0;          // y·G
let big_s  = hash_point * private_share.to_scalar(); // xᵢ·H(pk‖app_id)
let big_c  = big_s + app_pk * y.0;                  // xᵢ·H + y·A
let norm_big_y = big_y * lambda_i;                   // λᵢ·y·G
let norm_big_c = big_c * lambda_i;                   // λᵢ·(xᵢ·H + y·A)
``` [2](#0-1) 

Nothing in the coordinator path verifies that the received `(norm_big_y, norm_big_c)` satisfies any of these relations. There is no:

- Proof of knowledge that the sender knows the discrete log of `norm_big_y` (i.e., that `y` was chosen honestly).
- Consistency check that `norm_big_c` encodes the sender's actual key share `xᵢ` and the same `y`.
- Subgroup or identity check on the received points.

The participant path simply sends whatever it computes privately to the coordinator:

```rust
// src/confidential_key_derivation/protocol.rs  lines 29-31
chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;
Ok(None)
``` [3](#0-2) 

Because `recv_from_others` waits for **all** other participants before the coordinator proceeds, a single malicious participant who sends `(Δ_Y, Δ_C)` of their choice causes the final output to be:

```
Y_out = Y_honest_sum + Δ_Y
C_out = C_honest_sum + Δ_C
```

The TEE later unmasks the key as `C_out − app_sk · Y_out`, which equals:

```
msk · H(pk‖app_id) + (Δ_C − app_sk · Δ_Y)
```

The additive error term `(Δ_C − app_sk · Δ_Y)` is fully attacker-controlled (the attacker picks `Δ_Y` and `Δ_C` freely), so the derived confidential key is corrupted to an arbitrary value.

---

### Impact Explanation

**High — Corruption of CKD outputs so honest parties accept an incorrect confidential derived key.**

The coordinator outputs a `CKDOutput` that is cryptographically indistinguishable from a legitimate one (it is still a valid pair of G1 points), but it encodes a wrong key. Every downstream consumer (e.g., a TEE) that calls `ckd_output.unmask(app_sk)` will silently obtain a wrong secret. There is no post-hoc way for the coordinator or the TEE to detect the corruption without an independent reference value.

---

### Likelihood Explanation

**Medium.** The CKD protocol has no threshold robustness parameter — unlike the robust ECDSA presign which enforces `participants.len() == 2*max_malicious+1`, the `ckd` entry point accepts any participant list with no malicious-tolerance guarantee. A single compromised or adversarial node in the MPC network is sufficient to trigger the corruption on every CKD invocation it participates in. The library targets "decentralized MPC networks" where such adversarial participants are an explicitly considered threat. [4](#0-3) 

---

### Recommendation

Add a non-interactive proof of knowledge (e.g., a Schnorr proof) that binds each participant's `norm_big_y` to a known discrete log, and a consistency proof that `norm_big_c` was formed using the same blinding scalar and the participant's committed key share. Concretely:

1. Each participant computes a Schnorr proof `π` for `(y, norm_big_y)` and a proof that `norm_big_c = λᵢ·xᵢ·H + y·λᵢ·A`.
2. The coordinator verifies all proofs before accumulating the contributions.
3. Reject (and identify) any participant whose proof fails.

Alternatively, adopt a commit-then-reveal pattern similar to the DKG's `verify_commitment_hash` / `verify_proof_of_knowledge` flow already present in `src/dkg.rs`. [5](#0-4) 

---

### Proof of Concept

A malicious participant replaces its honest `compute_signature_share` output with arbitrary points before sending:

```rust
// Malicious participant overrides its contribution
let delta_y = ElementG1::generator() * Scalar::random(rng); // arbitrary
let delta_c = ElementG1::generator() * Scalar::random(rng); // arbitrary
chan.send_private(waitpoint, coordinator, &(delta_y, delta_c))?;
```

The coordinator accumulates these without complaint:

```rust
// coordinator — no validation
norm_big_y += participant_output.big_y(); // += delta_y
norm_big_c += participant_output.big_c(); // += delta_c
```

The resulting `CKDOutput` encodes a key `msk·H(pk‖app_id) + (Δ_C − app_sk·Δ_Y)`, which is wrong for any `Δ_Y, Δ_C` not equal to the honest contribution. The TEE silently derives and uses this incorrect key. [6](#0-5)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L29-32)
```rust
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

**File:** src/confidential_key_derivation/protocol.rs (L66-101)
```rust
pub fn ckd(
    participants: &[Participant],
    coordinator: Participant,
    me: Participant,
    key_pair: KeygenOutput,
    app_id: impl Into<AppId>,
    app_pk: PublicKey,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = CKDOutputOption>, InitializationError> {
    // not enough participants
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }

    // kick out duplicates
    let Some(participants) = ParticipantList::new(participants) else {
        return Err(InitializationError::DuplicateParticipants);
    };

    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }

    // ensure the coordinator is a participant
    if !participants.contains(coordinator) {
        return Err(InitializationError::MissingParticipant {
            role: "coordinator",
            participant: coordinator,
        });
    }
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
