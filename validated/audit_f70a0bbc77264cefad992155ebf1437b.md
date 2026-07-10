### Title
Presign Threshold Can Be Set Below DKG Threshold, Corrupting Presignature Outputs — (`File: src/ecdsa/ot_based_ecdsa/presign.rs`)

---

### Summary

The OT-based ECDSA presign function accepts a caller-supplied `threshold` that is only validated against the triple thresholds, but is never checked to be at least as large as the DKG reconstruction threshold. The protocol specification explicitly requires `t_presign >= t_DKG`, but this invariant is not enforced in code. A malicious coordinator can generate triples with an arbitrarily low threshold and drive presign with that lower threshold, causing all honest participants to compute Lagrange-linearized key-share contributions with wrong coefficients, producing a cryptographically invalid presignature and permanently denying signing.

---

### Finding Description

The orchestration document states the required threshold ordering across phases:

> `N_1 >= t_0 >= t` — the presign threshold must be at least the DKG threshold `t`. [1](#0-0) 

In `src/ecdsa/ot_based_ecdsa/presign.rs`, the `presign()` initializer enforces only that the caller-supplied `args.threshold` matches the two triple thresholds:

```rust
if args.threshold != args.triple0.1.threshold || args.threshold != args.triple1.1.threshold {
    return Err(InitializationError::BadParameters(
        "New threshold must match the threshold of both triples".to_string(),
    ));
}
``` [2](#0-1) 

There is no check that `args.threshold >= keygen_threshold`. The `KeygenOutput` struct returned by DKG stores only `private_share` and `public_key`; the DKG threshold is not persisted: [3](#0-2) 

Because `KeygenOutput` carries no threshold field, the presign function has no basis on which to enforce the `t_presign >= t_DKG` invariant. The triple generation function `validate_triple_inputs` similarly imposes no lower bound relative to the DKG threshold — it only requires `threshold >= 2`: [4](#0-3) 

**Attack path:**

1. A malicious coordinator calls `generate_triple` with `threshold = 2` (the minimum), producing triples with a threshold far below the DKG threshold `t`.
2. The coordinator calls `presign` with those triples and `args.threshold = 2`. The initializer accepts this because `2 == triple0.threshold == triple1.threshold`.
3. Inside `do_presign`, each honest participant computes its Lagrange coefficient over the presign participant set (size `N_1 >= 2`) and linearizes its key share: `x_prime_i = lambda_me * private_share`. [5](#0-4) 

4. Because `N_1 < t_DKG`, the Lagrange basis is evaluated over too few points. The sum `Σ x_prime_i` does not reconstruct the actual secret key `x`. The presignature is built on a wrong effective key.
5. The resulting `PresignOutput` is cryptographically invalid. Any subsequent signing attempt produces a signature that fails verification, permanently denying signing for all honest parties.

---

### Impact Explanation

**High — Corruption of presign outputs / permanent denial of signing.**

Honest participants accept and store a `PresignOutput` whose embedded key-share linearization is incorrect. Every signature produced from this presignature will be invalid against the real public key. Because presignatures are one-time-use and consumed on signing, the corrupted presignature cannot be recovered; a fresh presign round must be initiated. If the malicious coordinator controls triple generation and presign orchestration, it can repeat this attack indefinitely, permanently denying signing to honest parties.

---

### Likelihood Explanation

**Medium.** The coordinator role is explicitly part of the protocol model. A malicious coordinator who also controls triple generation (a separate, unauthenticated call) can trivially supply low-threshold triples. No cryptographic break is required; the attack is a pure parameter-manipulation at the API boundary. The missing check is a single missing inequality (`args.threshold >= dkg_threshold`), and the `KeygenOutput` type provides no way to recover the DKG threshold at presign time.

---

### Recommendation

1. **Store the DKG threshold in `KeygenOutput`**: Add a `threshold: ReconstructionLowerBound` field to `KeygenOutput` so that downstream protocols can enforce the ordering invariant.
2. **Enforce `args.threshold >= keygen_out.threshold` in `presign()`**: After the existing triple-threshold check, add:
   ```rust
   if args.threshold < args.keygen_out.threshold {
       return Err(InitializationError::BadParameters(
           "Presign threshold must be >= DKG threshold".to_string(),
       ));
   }
   ```
3. **Apply the same fix to triple generation**: `validate_triple_inputs` should also accept and enforce a minimum threshold equal to the DKG threshold.

---

### Proof of Concept

```
Setup:
  DKG with N=5 participants, t_DKG = 4 (threshold = 4).
  Each participant holds a degree-3 polynomial share.

Attack:
  Malicious coordinator generates triples with threshold = 2.
  Coordinator calls presign(participants[0..2], me, PresignArguments {
      triple0: (share0, pub0_with_threshold_2),
      triple1: (share1, pub1_with_threshold_2),
      keygen_out: honest_keygen_out,
      threshold: 2,   // passes the triple-match check; NOT checked against t_DKG=4
  });

Result:
  lambda_me = Lagrange({P0, P1}, P0)  // computed over 2-party set, not 4-party set
  x_prime_0 = lambda_me * x_0         // wrong coefficient
  x_prime_1 = lambda_me * x_1         // wrong coefficient
  sum(x_prime_i) != x                 // does not reconstruct the secret key

  PresignOutput.sigma is based on wrong x → signature verification fails.
  Signing is permanently denied for this presignature.
```

### Citations

**File:** docs/ecdsa/ot_based_ecdsa/orchestration.md (L49-56)
```markdown
The thresholds can also change, subject to the following conditions:

$$
\begin{aligned}
&N_0 \geq t\cr
&N_1 \geq t_0 \geq t\cr
&N_2 \geq t_1 \geq t
\end{aligned}
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L43-47)
```rust
    if args.threshold != args.triple0.1.threshold || args.threshold != args.triple1.1.threshold {
        return Err(InitializationError::BadParameters(
            "New threshold must match the threshold of both triples".to_string(),
        ));
    }
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L93-103)
```rust
    let lambda_me = participants.lagrange::<Secp256>(me)?;

    let k_prime_i = lambda_me * k_i;
    let e_i: Scalar = lambda_me * e_i;

    let a_prime_i = lambda_me * a_i;
    let b_prime_i = lambda_me * b_i;

    let big_x: ProjectivePoint = args.keygen_out.public_key.to_element();
    let private_share = args.keygen_out.private_share.to_scalar();
    let x_prime_i = lambda_me * private_share;
```

**File:** src/dkg.rs (L533-537)
```rust
    // Return the key pair
    Ok(KeygenOutput {
        private_share: SigningShare::new(my_signing_share),
        public_key: verifying_key,
    })
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L681-708)
```rust
fn validate_triple_inputs(
    participants: &[Participant],
    threshold: impl Into<ReconstructionLowerBound>,
) -> Result<(ParticipantList, ReconstructionLowerBound), InitializationError> {
    let threshold = threshold.into();
    let threshold_value = threshold.value();
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }
    // Spec 1.1
    if threshold_value > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: threshold_value,
            max: participants.len(),
        });
    }
    if threshold_value < 2 {
        return Err(InitializationError::ThresholdTooSmall {
            threshold: threshold_value,
            min: 2,
        });
    }
    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;
    Ok((participants, threshold))
}
```
