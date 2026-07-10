### Title
Missing Participant-Set Consistency Check Between Rerandomization and Signing Enables Split-View Secret-Key Extraction — (`src/ecdsa/robust_ecdsa/sign.rs`, `src/ecdsa/robust_ecdsa/mod.rs`)

---

### Summary

The robust ECDSA `sign()` function accepts a `participants` argument and a `RerandomizedPresignOutput` with no enforcement that the signing participant set matches the participant set embedded in the rerandomization HKDF. Because `RerandomizedPresignOutput` does not store the participant set used during rerandomization, a malicious coordinator can run two signing sessions from the same `PresignOutput` with different participant sets, obtaining two valid signatures with multiplicatively related nonces and recovering the aggregate secret key.

---

### Finding Description

The `RerandomizationArguments` struct binds the rerandomization scalar δ to `(pk, tweak, msg_hash, big_r, participants, entropy)` via HKDF: [1](#0-0) 

The `participants` field is serialized into the HKDF input, so δ is participant-set-specific: [2](#0-1) 

However, the resulting `RerandomizedPresignOutput` discards the participant set entirely — it stores only the rerandomized cryptographic values: [3](#0-2) 

`rerandomize_presign()` takes the `PresignOutput` by shared reference (`&PresignOutput`), so the raw presignature is never consumed and can be rerandomized multiple times with different participant sets: [4](#0-3) 

`sign()` enforces `N = 2t+1` and `msg_hash ≠ 0`, but has no check that the `participants` argument matches the participant set used to produce the `presignature`: [5](#0-4) 

The security specification explicitly requires this consistency but the library does not enforce it: [6](#0-5) 

---

### Impact Explanation

The security note documents the exact consequence: two signing sessions over the same presignature with different `(h, ε)` or different participant sets produce signatures with multiplicatively related nonces, enabling standard ECDSA nonce-reuse key recovery. [7](#0-6) 

Because `RerandomizedPresignOutput` carries no participant-set binding, `sign()` cannot detect that the presignature was rerandomized for a different signing set. A malicious coordinator can therefore orchestrate two valid signing sessions from the same `PresignOutput`, each with a distinct 2t+1 participant set, and extract the aggregate secret key. This maps to **Critical: Extraction of aggregate secret material**.

---

### Likelihood Explanation

The coordinator is an explicit participant in the protocol and controls which `RerandomizationArguments` (including `participants`) are distributed to each signer. `PresignOutput` is `Clone` and `Serialize/Deserialize`, so the coordinator can trivially retain and reuse it across sessions. No out-of-band mechanism in the library prevents this; the only mitigations are the `N = 2t+1` count check and the `msg_hash ≠ 0` check, neither of which addresses participant-set reuse across sessions. [8](#0-7) 

---

### Recommendation

Store the participant set inside `RerandomizedPresignOutput` at rerandomization time and assert equality in `sign()`:

```rust
pub struct RerandomizedPresignOutput {
    pub big_r: AffinePoint,
    pub e: Scalar,
    pub alpha: Scalar,
    pub beta: Scalar,
    pub participants: ParticipantList,   // <-- add this
}

// In rerandomize_presign():
Ok(Self {
    big_r: rerandomized_big_r.into(),
    alpha: rerandomized_alpha,
    beta: rerandomized_beta,
    e: presignature.e,
    participants: args.participants.clone(),  // bind at creation
})

// In sign(), after building the ParticipantList:
if participants != presignature.participants {
    return Err(InitializationError::BadParameters(
        "signing participants must match rerandomization participants".to_string(),
    ));
}
```

---

### Proof of Concept

```
Setup: t = 1, so 2t+1 = 3 participants required.
Participants available: {A, B, C, D}

Step 1 – Presign with {A, B, C}:
  Each of A, B, C runs presign() → PresignOutput_A, PresignOutput_B, PresignOutput_C

Step 2 – Coordinator clones each PresignOutput (Clone is derived).

Step 3 – Session 1 (coordinator presents participants = {A, B, C}):
  A: rerandomize_presign(PresignOutput_A, args{participants={A,B,C}, h=h1}) → Rerand1_A
  B: rerandomize_presign(PresignOutput_B, args{participants={A,B,C}, h=h1}) → Rerand1_B
  C: rerandomize_presign(PresignOutput_C, args{participants={A,B,C}, h=h1}) → Rerand1_C
  sign({A,B,C}, ..., Rerand1_*, h1) → valid signature (R, s1)

Step 4 – Session 2 (coordinator presents participants = {A, B, D}):
  A: rerandomize_presign(PresignOutput_A_clone, args{participants={A,B,D}, h=h2}) → Rerand2_A
  B: rerandomize_presign(PresignOutput_B_clone, args{participants={A,B,D}, h=h2}) → Rerand2_B
  D: rerandomize_presign(PresignOutput_D_clone, args{participants={A,B,D}, h=h2}) → Rerand2_D
  sign({A,B,D}, ..., Rerand2_*, h2) → valid signature (R', s2)

Step 5 – Both signatures share nonces derived from the same presignature.
  Apply standard ECDSA nonce-reuse equations to (R,s1,h1) and (R',s2,h2)
  → recover aggregate secret key x.
```

`sign()` accepts both calls without error because each session independently satisfies `N = 2t+1 = 3` and `msg_hash ≠ 0`. The missing participant-set binding in `RerandomizedPresignOutput` is the necessary vulnerable step. [9](#0-8) [10](#0-9)

### Citations

**File:** src/ecdsa/mod.rs (L94-103)
```rust
pub struct RerandomizationArguments {
    // Preferable (but non-binding) the master public key
    pub pk: AffinePoint,
    pub tweak: Tweak,
    pub msg_hash: [u8; 32],
    pub big_r: AffinePoint,
    pub participants: ParticipantList,
    /// Fresh, Unpredictable, and Public source of entropy
    pub entropy: [u8; 32],
}
```

**File:** src/ecdsa/mod.rs (L155-159)
```rust
        concatenation.extend_from_slice(encoded_big_r);
        // Append each ParticipantId's
        for participant in self.participants.participants() {
            concatenation.extend_from_slice(&participant.bytes());
        }
```

**File:** src/ecdsa/robust_ecdsa/mod.rs (L26-37)
```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ZeroizeOnDrop)]
pub struct PresignOutput {
    /// The public nonce commitment.
    #[zeroize(skip)]
    pub big_r: AffinePoint,

    /// Our secret shares of the nonces.
    pub c: Scalar,
    pub e: Scalar,
    pub alpha: Scalar,
    pub beta: Scalar,
}
```

**File:** src/ecdsa/robust_ecdsa/mod.rs (L42-52)
```rust
#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct RerandomizedPresignOutput {
    /// The rerandomized public nonce commitment.
    #[zeroize(skip)]
    big_r: AffinePoint,

    /// Our rerandomized secret shares of the nonces.
    e: Scalar,
    alpha: Scalar,
    beta: Scalar,
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

**File:** src/ecdsa/robust_ecdsa/sign.rs (L33-108)
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
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }

    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;

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

    // ensure number of participants during the signing phase is >= 2 * max_malicious + 1
    let robust_ecdsa_threshold = max_malicious
        .into()
        .value()
        .checked_mul(2)
        .and_then(|v| v.checked_add(1))
        .ok_or_else(|| {
            InitializationError::BadParameters(
                "2*threshold+1 must be less than usize::MAX".to_string(),
            )
        })?;
    if robust_ecdsa_threshold > participants.len() {
        return Err(InitializationError::BadParameters(
            "2*max_malicious+1 must be less than or equals to participant count".to_string(),
        ));
    }

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

    let ctx = Comms::new();
    let fut = fut_wrapper(
        ctx.shared_channel(),
        participants,
        coordinator,
        me,
        public_key,
        presignature,
        msg_hash,
    );
    Ok(make_protocol(ctx, fut))
}
```

**File:** docs/ecdsa/robust_ecdsa/signing.md (L149-158)
```markdown
Before implementing or using the robust ECDSA scheme implemented here,
be aware that it is vulnerable to **split-view attacks** in the robust setting when the
signing parameters are not globally consistent. If different subsets of size at least
$2t + 1$ sign different $(h, \epsilon)$ values using shares derived from the same
presignature, the resulting signatures use multiplicatively related nonces and the
secret key can be recovered using standard ECDSA nonce-reuse attacks.

Moreover, due to protocol modifications relative to [[DJNPO20](https://eprint.iacr.org/2020/501)] (notably signature-share
linearization), **a novel split-view attack exists that can extract the secret key using as
few as $2t + 2$ presigning participants**, with as few as two signing sessions.
```

**File:** docs/ecdsa/robust_ecdsa/signing.md (L160-174)
```markdown
To reduce the risk of accidental misuse, enforce the following constraints:

1. **Use exactly $N_1 = N_2 = 2t + 1$ participants for both presigning and signing.**
   Do **not** allow any deviation from this value. In particular:

   * Do **not** allow $N_1 > 2t + 1$, and
   * Do **not** allow $N_2 < N_1$.

   Allowing larger presigning sets or smaller signing sets enables split-view and
   presignature-reuse attacks when a coordinator can run parallel or partially overlapping
   signing sessions.

2. **Ensure all participants agree on $(h, \epsilon)$ and the signing set.**
   The coordinator must not be able to present different message hashes, tweaks, or
   participant lists to different signers.
```
