### Title
Malicious Coordinator Can Vary `RerandomizationArguments.participants` Across Signing Sessions to Extract the Private Key via Split-View Attack — (File: `src/ecdsa/robust_ecdsa/sign.rs`, `src/ecdsa/mod.rs`)

---

### Summary

The `participants` field inside `RerandomizationArguments` is hashed into the HKDF derivation of the rerandomization scalar `delta`, which directly transforms every presignature share. However, `robust_ecdsa::sign::sign()` accepts an already-rerandomized presignature without ever checking that the `participants` list used during rerandomization matches the actual signing participants. A malicious coordinator can exploit this gap to run two signing sessions against the same presignature with different effective `delta` values, producing two valid ECDSA signatures whose nonces are multiplicatively related, and then recover the private key with standard nonce-reuse algebra.

---

### Finding Description

**Root cause — `RerandomizationArguments.participants` is included in `delta` but never validated in `sign()`**

`RerandomizationArguments::derive_randomness()` concatenates the participant IDs into the HKDF input:

```rust
for participant in self.participants.participants() {
    concatenation.extend_from_slice(&participant.bytes());
}
``` [1](#0-0) 

This means any change to `args.participants` produces a completely different `delta`, and therefore a completely different rerandomized nonce `R' = R · delta` and different share scalars `alpha'`, `beta'`.

`RerandomizedPresignOutput::rerandomize_presign()` applies this transformation:

```rust
let rerandomized_big_r = presignature.big_r * delta;
let rerandomized_alpha = presignature.alpha * inv_delta;
let rerandomized_beta =
    (presignature.beta + presignature.c * args.tweak.value()) * inv_delta;
``` [2](#0-1) 

`robust_ecdsa::sign::sign()` then accepts the already-rerandomized presignature as an opaque value and performs no check that the `participants` used during rerandomization equals the `participants` passed to `sign()`:

```rust
pub fn sign(
    participants: &[Participant],
    coordinator: Participant,
    max_malicious: impl Into<MaxMalicious>,
    me: Participant,
    public_key: AffinePoint,
    presignature: RerandomizedPresignOutput,   // ← no rerandomization args stored
    msg_hash: Scalar,
) -> Result<impl Protocol<Output = SignatureOption>, InitializationError> {
``` [3](#0-2) 

The only split-view mitigations enforced in code are `N = 2t+1` and `msg_hash ≠ 0`:

```rust
if participants.len() != robust_ecdsa_threshold { ... }
if bool::from(msg_hash.is_zero()) { ... }
``` [4](#0-3) 

The `participants` dimension of the rerandomization input is entirely unguarded.

**Attack path (malicious coordinator)**

1. Presigning completes normally with `N = 2t+1` participants, producing raw presignature shares `(R, alpha_i, beta_i, c_i, e_i)`.
2. **Session 1**: Coordinator instructs all signers to rerandomize with `participants = {P1…P5}`, `msg_hash = h1`, `tweak = ε1`, `entropy = ρ1`. All compute the same `delta1`; the session produces a valid signature `(R1 = R·delta1, s1)`.
3. **Session 2 (same presignature)**: Coordinator instructs all signers to rerandomize with `participants = {P1…P4, P_fake}` (a fabricated participant ID), keeping `msg_hash = h2`, `tweak = ε2`, `entropy = ρ2`. All compute the same `delta2 ≠ delta1`; the session produces a valid signature `(R2 = R·delta2, s2)`.
4. The coordinator now holds two valid ECDSA signatures whose nonces satisfy `R1 = R2 · (delta1/delta2)` — a multiplicative relation. Standard ECDSA nonce-reuse algebra recovers the private key `x`.

The security documentation explicitly identifies this class of attack and states the constraint that must hold:

> "Ensure all participants agree on (h, ε) and the signing set. The coordinator must not be able to present different message hashes, tweaks, or participant lists to different signers." [5](#0-4) 

However, the code enforces only two of the four documented constraints (`msg_hash ≠ 0` and `N = 2t+1`). The `participants` dimension of the rerandomization input is left entirely to the caller, with no binding between the rerandomization arguments and the signing invocation.

---

### Impact Explanation

**Impact: Critical**

A malicious coordinator can obtain two valid threshold ECDSA signatures whose nonces are multiplicatively related by varying only the `participants` field of `RerandomizationArguments` across two signing sessions that consume the same presignature. Standard ECDSA nonce-reuse recovery then yields the full aggregate private key `x`, satisfying the Critical impact criterion: *Extraction, reconstruction, or disclosure of private signing shares or aggregate secret material*.

---

### Likelihood Explanation

**Likelihood: Medium**

The coordinator role is a designated, privileged participant in every signing session. A coordinator that turns malicious — or is compromised — can silently vary the `participants` field without any honest signer detecting the manipulation, because each signer independently constructs their own `RerandomizationArguments` based solely on what the coordinator communicates. Two signing sessions are sufficient. The presignature-reuse requirement is also undocumented at the code level (no enforcement), making accidental or deliberate reuse realistic in production orchestration.

---

### Recommendation

1. **Bind rerandomization arguments to the signing invocation.** Pass `RerandomizationArguments` (or a commitment to it) into `sign()` and assert that `args.participants` equals the actual signing `participants`, `args.msg_hash` equals `msg_hash`, and `args.tweak` equals the tweak used to derive `public_key`. This closes the gap without changing the external API semantics.

2. **Store a rerandomization transcript in `RerandomizedPresignOutput`.** Include a hash of `(participants, msg_hash, tweak, entropy, big_r)` so that `sign()` can verify consistency without exposing secret material.

3. **Enforce presignature single-use at the library level.** Add a consumed/spent flag or require callers to pass a unique session token that is checked against a local registry, preventing the coordinator from reusing the same presignature across sessions.

---

### Proof of Concept

The following pseudocode demonstrates the attack using the library's public API:

```rust
// Setup: presigning with N=5, max_malicious=2
let presign_outputs: Vec<(Participant, PresignOutput)> = run_presign(keys, max_malicious);

// Session 1: legitimate rerandomization
let args1 = RerandomizationArguments::new(
    pk, tweak1, msg_hash1, big_r,
    ParticipantList::new(&[P1, P2, P3, P4, P5]).unwrap(),  // real set
    entropy1,
);
let rerand1: Vec<(Participant, RerandomizedPresignOutput)> = presign_outputs.iter()
    .map(|(p, ps)| (*p, RerandomizedPresignOutput::rerandomize_presign(ps, &args1).unwrap()))
    .collect();
let sig1 = run_sign(rerand1, max_malicious, coordinator, pk, msg_hash1); // (R1, s1)

// Session 2: coordinator substitutes a fake participant in rerandomization args
// (same raw presignature shares, different delta)
let args2 = RerandomizationArguments::new(
    pk, tweak2, msg_hash2, big_r,
    ParticipantList::new(&[P1, P2, P3, P4, P_FAKE]).unwrap(), // ← fabricated set
    entropy2,
);
let rerand2: Vec<(Participant, RerandomizedPresignOutput)> = presign_outputs.iter()
    .map(|(p, ps)| (*p, RerandomizedPresignOutput::rerandomize_presign(ps, &args2).unwrap()))
    .collect();
// sign() accepts this without checking that args2.participants == [P1..P5]
let sig2 = run_sign(rerand2, max_malicious, coordinator, pk, msg_hash2); // (R2, s2)

// R1 = R·delta1, R2 = R·delta2  →  nonce relation known to coordinator
// Standard ECDSA nonce-reuse algebra recovers private key x.
```

The `sign()` function in `src/ecdsa/robust_ecdsa/sign.rs` accepts both `rerand1` and `rerand2` without error because it only checks `participants.len() == 2t+1` and `msg_hash ≠ 0`; it never inspects what `participants` list was used to compute `delta`. [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** src/ecdsa/mod.rs (L139-188)
```rust
    pub fn derive_randomness(&self) -> Result<Scalar, ProtocolError> {
        // create a string containing (pk, msg_hash, big_r, sorted(participants))
        let pk_encoded_point = self.pk.to_encoded_point(true);
        let encoded_pk: &[u8] = pk_encoded_point.as_bytes();
        let encoded_tweak: &[u8] = &<Secp256K1ScalarField as Field>::serialize(&self.tweak.value());
        let encoded_msg_hash: &[u8] = &self.msg_hash;
        let big_r_encoded_point = self.big_r.to_encoded_point(true);
        let encoded_big_r: &[u8] = big_r_encoded_point.as_bytes();

        // concatenate all the bytes
        let mut concatenation = Vec::new();
        // 1 byte counter, used in the unlikely case that the hash result is 0
        concatenation.extend_from_slice(&[0u8, 1]);
        concatenation.extend_from_slice(encoded_pk);
        concatenation.extend_from_slice(encoded_tweak);
        concatenation.extend_from_slice(encoded_msg_hash);
        concatenation.extend_from_slice(encoded_big_r);
        // Append each ParticipantId's
        for participant in self.participants.participants() {
            concatenation.extend_from_slice(&participant.bytes());
        }

        // initiate hkdf with the salt and with some `good' entropy
        let hk = Hkdf::<sha3::Sha3_256>::new(Some(&Self::SALT), &self.entropy);

        let mut delta = Scalar::ZERO;
        // If the randomness created is 0 then we want to generate a new randomness
        while bool::from(delta.is_zero()) {
            // Generate randomization out of HKDF(counter, entropy, pk, msg_hash, big_r, participants, )
            // where entropy is a public but unpredictable random string.
            // The counter depends on the number of times we enter into this loop
            let mut okm = [0u8; 32];

            hk.expand(&concatenation, &mut okm)
                .map_err(|_| ProtocolError::HashingError)?;

            // derive the randomness delta
            delta = Scalar::from_repr(okm.into()).unwrap_or(
                // if delta falls outside the field
                // probability is negligible: in the order of 1/2^224
                Scalar::ZERO,
            );
            // Increment the counter, the probability that this overflows is astronomically low
            let concatenation_0 = concatenation
                .first_mut()
                .ok_or(ProtocolError::InvalidIndex)?;
            *concatenation_0 += 1;
        }
        Ok(delta)
    }
```

**File:** src/ecdsa/robust_ecdsa/mod.rs (L54-86)
```rust
impl RerandomizedPresignOutput {
    pub fn rerandomize_presign(
        presignature: &PresignOutput,
        args: &RerandomizationArguments,
    ) -> Result<Self, ProtocolError> {
        if presignature.big_r != args.big_r {
            return Err(ProtocolError::IncompatibleRerandomizationInputs);
        }
        let delta = args.derive_randomness()?;
        if delta.is_zero().into() {
            return Err(ProtocolError::ZeroScalar);
        }

        // cannot be zero due to the previous check
        let inv_delta = delta.invert().unwrap();

        // delta * R
        let rerandomized_big_r = presignature.big_r * delta;

        // alpha * delta^{-1}
        let rerandomized_alpha = presignature.alpha * inv_delta;

        // (beta + c*tweak) * delta^{-1}
        let rerandomized_beta =
            (presignature.beta + presignature.c * args.tweak.value()) * inv_delta;

        Ok(Self {
            big_r: rerandomized_big_r.into(),
            alpha: rerandomized_alpha,
            beta: rerandomized_beta,
            e: presignature.e,
        })
    }
```

**File:** src/ecdsa/robust_ecdsa/sign.rs (L33-41)
```rust
pub fn sign(
    participants: &[Participant],
    coordinator: Participant,
    max_malicious: impl Into<MaxMalicious>,
    me: Participant,
    public_key: AffinePoint,
    presignature: RerandomizedPresignOutput,
    msg_hash: Scalar,
) -> Result<impl Protocol<Output = SignatureOption>, InitializationError> {
```

**File:** src/ecdsa/robust_ecdsa/sign.rs (L84-95)
```rust
    // The next two conditions prevent split-view attacks
    // documented in docs/ecdsa/robust_ecdsa/signing.md
    if participants.len() != robust_ecdsa_threshold {
        return Err(InitializationError::BadParameters(
            "the number of participants during signing must be exactly 2*max_malicious+1 to avoid split view attacks".to_string(),
        ));
    }
    if bool::from(msg_hash.is_zero()) {
        return Err(InitializationError::BadParameters(
            "msg_hash cannot be 0 to avoid potential split view attacks".to_string(),
        ));
    }
```

**File:** docs/ecdsa/robust_ecdsa/signing.md (L172-174)
```markdown
2. **Ensure all participants agree on $(h, \epsilon)$ and the signing set.**
   The coordinator must not be able to present different message hashes, tweaks, or
   participant lists to different signers.
```
