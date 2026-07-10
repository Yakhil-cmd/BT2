### Title
Caller-Controlled Predictable Entropy in `RerandomizationArguments` Bypasses Presignature Rerandomization, Enabling Secret Key Extraction - (File: src/ecdsa/mod.rs)

### Summary
`RerandomizationArguments::new` accepts an `entropy: [u8; 32]` field with no validation whatsoever. A malicious coordinator can supply all-zero (or any fixed, predictable) entropy, making the rerandomization scalar `delta` fully deterministic from public inputs. This nullifies the Wagner-attack protection and, combined with presignature reuse across two signing sessions, gives the coordinator enough information to solve for the aggregate secret key algebraically.

### Finding Description
`RerandomizationArguments` is the struct that binds a presignature to a signing context and derives the rerandomization scalar `delta` via HKDF-SHA3-256:

```rust
// src/ecdsa/mod.rs  lines 94-103
pub struct RerandomizationArguments {
    pub pk: AffinePoint,
    pub tweak: Tweak,
    pub msg_hash: [u8; 32],
    pub big_r: AffinePoint,
    pub participants: ParticipantList,
    /// Fresh, Unpredictable, and Public source of entropy
    pub entropy: [u8; 32],
}
``` [1](#0-0) 

`derive_randomness` feeds `self.entropy` directly as the HKDF IKM:

```rust
// src/ecdsa/mod.rs  lines 161-162
let hk = Hkdf::<sha3::Sha3_256>::new(Some(&Self::SALT), &self.entropy);
``` [2](#0-1) 

If `entropy = [0u8; 32]`, HKDF still produces a non-zero output, so the only guard in `rerandomize_presign` — `delta.is_zero()` — passes silently:

```rust
// src/ecdsa/ot_based_ecdsa/mod.rs  lines 73-76
let delta = args.derive_randomness()?;
if delta.is_zero().into() {
    return Err(ProtocolError::ZeroScalar);
}
``` [3](#0-2) 

There is no check that `entropy` is non-trivial anywhere in the codebase. Because all participants must agree on the same `entropy` to compute the same `delta` (the entropy is "public"), the coordinator is the natural party to generate and broadcast it. A malicious coordinator broadcasts `[0u8; 32]`, and every participant silently accepts it.

The analog to `randomIndex` is direct: just as `keccak256(nonce, msg.sender, block.difficulty, block.timestamp)` is predictable to a miner, `HKDF(salt, 0x00…00, pk ‖ tweak ‖ h ‖ R ‖ participants)` is predictable to anyone who knows the public inputs — which is everyone.

### Impact Explanation
The security documentation for the robust ECDSA scheme explicitly warns:

> If different subsets of size at least 2t+1 sign different (h, ε) values using shares derived from the same presignature, the resulting signatures use multiplicatively related nonces and the secret key can be recovered using standard ECDSA nonce-reuse attacks. [4](#0-3) 

Rerandomization is the sole mitigation: it makes `delta` unpredictable so the coordinator cannot engineer related nonces. With `entropy = 0`, `delta₁` and `delta₂` for two sessions over the same presignature `R` are both fully computable from public data. The two rerandomized nonces are `k/delta₁` and `k/delta₂`, related by the known ratio `delta₂/delta₁`. Given two resulting ECDSA signatures `(r₁, s₁)` and `(r₂, s₂)`:

```
s₁ · (k/delta₁) = h₁ + r₁ · x
s₂ · (k/delta₂) = h₂ + r₂ · x
```

Dividing and solving yields the aggregate secret key `x` in closed form. This is **Critical** impact: full extraction of the private signing key by a malicious coordinator.

### Likelihood Explanation
The attack entry point is the `entropy` parameter of `RerandomizationArguments::new`, which is a public API. A malicious coordinator:
1. Generates `entropy = [0u8; 32]` (or any fixed value).
2. Broadcasts it to all participants as the "public entropy" for the signing session.
3. Participants have no library-enforced mechanism to reject it — the library performs zero entropy validation.
4. Runs two signing sessions over the same presignature with different messages.

No cryptographic break, no leaked keys, and no external dependency is required. The coordinator role is explicitly listed as a potential adversary in the threat model.

### Recommendation
Add an explicit entropy quality check in `RerandomizationArguments::new` or `derive_randomness`:

```rust
if self.entropy == [0u8; 32] {
    return Err(ProtocolError::InvalidEntropy);
}
```

More robustly, require participants to contribute entropy via a coin-flipping sub-protocol so no single party (including the coordinator) can fix the value. At minimum, document that participants **must** independently verify the entropy is non-trivial before accepting `RerandomizationArguments`.

### Proof of Concept
1. Malicious coordinator constructs `entropy = [0u8; 32]` and broadcasts it.
2. All participants call `RerandomizationArguments::new(pk, tweak1, h1, R, participants, [0u8;32])` — accepted without error.
3. Each participant calls `RerandomizedPresignOutput::rerandomize_presign(presig, &args)` — succeeds because `delta₁ = HKDF(SALT, 0…0, pk‖ε₁‖h₁‖R‖…) ≠ 0`.
4. Signing session 1 completes; coordinator collects `(r₁, s₁)`.
5. Coordinator reuses the same presignature with `entropy = [0u8; 32]`, `tweak2`, `h2` → `delta₂` is again publicly computable.
6. Signing session 2 completes; coordinator collects `(r₂, s₂)`.
7. Coordinator computes `x = (s₂·delta₁·h₁ − s₁·delta₂·h₂) / (s₁·delta₂·r₂ − s₂·delta₁·r₁)`, recovering the aggregate secret key. [5](#0-4) [6](#0-5)

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

**File:** src/ecdsa/mod.rs (L117-188)
```rust
    pub fn new(
        pk: AffinePoint,
        tweak: Tweak,
        msg_hash: [u8; 32],
        big_r: AffinePoint,
        participants: ParticipantList,
        entropy: [u8; 32],
    ) -> Self {
        Self {
            pk,
            tweak,
            msg_hash,
            big_r,
            participants,
            entropy,
        }
    }

    /// Derives a random string from the public key, tweak, message hash, presignature R,
    /// set of participants and the entropy.
    ///
    /// Outputs a random string computed as HKDF(entropy, pk, hash, R, participants)
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

**File:** src/ecdsa/ot_based_ecdsa/mod.rs (L65-96)
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

        // delta . R
        let rerandomized_big_r = presignature.big_r * delta;

        //  (sigma + tweak * k) * delta^{-1}
        let rerandomized_sigma =
            (presignature.sigma + args.tweak.value() * presignature.k) * inv_delta;

        // k * delta^{-1}
        let rerandomized_k = presignature.k * inv_delta;

        Ok(Self {
            big_r: rerandomized_big_r.into(),
            k: rerandomized_k,
            sigma: rerandomized_sigma,
        })
    }
```

**File:** docs/ecdsa/robust_ecdsa/signing.md (L150-158)
```markdown
be aware that it is vulnerable to **split-view attacks** in the robust setting when the
signing parameters are not globally consistent. If different subsets of size at least
$2t + 1$ sign different $(h, \epsilon)$ values using shares derived from the same
presignature, the resulting signatures use multiplicatively related nonces and the
secret key can be recovered using standard ECDSA nonce-reuse attacks.

Moreover, due to protocol modifications relative to [[DJNPO20](https://eprint.iacr.org/2020/501)] (notably signature-share
linearization), **a novel split-view attack exists that can extract the secret key using as
few as $2t + 2$ presigning participants**, with as few as two signing sessions.
```
