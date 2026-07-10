### Title
Presignature Not Consumed on Use Enables Nonce-Reuse Private Key Extraction - (File: `src/ecdsa/ot_based_ecdsa/mod.rs`, `src/ecdsa/robust_ecdsa/mod.rs`)

---

### Summary

Both `ot_based_ecdsa::RerandomizedPresignOutput::rerandomize_presign` and `robust_ecdsa::RerandomizedPresignOutput::rerandomize_presign` accept the presignature as a shared reference (`&PresignOutput`) rather than consuming it by value. Combined with `PresignOutput` deriving `Clone`, the library provides no API-level enforcement of the single-use invariant it explicitly documents as critical. A malicious coordinator can reuse the same presignature across two signing sessions with different message hashes, producing signatures with multiplicatively related nonces, which is sufficient to reconstruct the aggregate private key via standard ECDSA nonce-reuse algebra.

---

### Finding Description

The library's own documentation states the single-use requirement unambiguously:

- `docs/ecdsa/ot_based_ecdsa/orchestration.md` lines 70–71: *"It's **critical** that the output is then destroyed, so that no other group of parties attempts to re-use that output for another phase."*
- `src/ecdsa/ot_based_ecdsa/README.md` line 12: *"Each output is consumed **exactly once** (one-time use)."*
- `src/ecdsa/robust_ecdsa/README.md` line 12: *"Each presignature is consumed **exactly once** (one-time use)."*
- `docs/ecdsa/robust_ecdsa/signing.md` line 176: *"**Never reuse a presignature**, even across failed, aborted, or partially completed signing sessions."*

Despite this, the API does not enforce the invariant. The two `rerandomize_presign` functions both borrow the presignature:

```rust
// src/ecdsa/ot_based_ecdsa/mod.rs
pub fn rerandomize_presign(
    presignature: &PresignOutput,          // ← shared reference, not consumed
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError>
```

```rust
// src/ecdsa/robust_ecdsa/mod.rs
pub fn rerandomize_presign(
    presignature: &PresignOutput,          // ← shared reference, not consumed
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError>
``` [1](#0-0) [2](#0-1) 

`PresignOutput` in the OT-based scheme derives `Clone`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, ZeroizeOnDrop)]
pub struct PresignOutput { ... }
``` [3](#0-2) 

Because the function takes `&PresignOutput`, Rust's ownership system never destroys the presignature after the call. Any holder of a `PresignOutput` can call `rerandomize_presign` an arbitrary number of times with different `RerandomizationArguments` (different `msg_hash`, `tweak`, or `entropy`), producing distinct `RerandomizedPresignOutput` values that all share the same underlying nonce material `k`.

The security consequence is documented explicitly in `docs/ecdsa/robust_ecdsa/signing.md` lines 152–154:

> *"If different subsets of size at least 2t+1 sign different (h, ε) values using shares derived from the same presignature, the resulting signatures use multiplicatively related nonces and the secret key can be recovered using standard ECDSA nonce-reuse attacks."* [4](#0-3) 

The same attack applies to the OT-based scheme, where the presignature nonce `k` is shared across all rerandomizations of the same `PresignOutput`.

---

### Impact Explanation

Two signatures produced from the same `PresignOutput` with different message hashes `h1`, `h2` satisfy:

```
s1 = (h1·k + Rx·σ) / δ1
s2 = (h2·k + Rx·σ) / δ2
```

where `δ1`, `δ2` are the HKDF-derived rerandomization scalars (both known to the attacker since `RerandomizationArguments` is public). From these two equations the attacker can eliminate `σ` and solve for `k`, then recover the private key `x`. This constitutes **full extraction of the aggregate private signing key**, matching the Critical impact tier: *"Extraction, reconstruction, or disclosure of private signing shares, aggregate secret material, presign secrets, nonce material, or confidential derived secrets."*

---

### Likelihood Explanation

The coordinator role is reachable by any participant (it is chosen per-session and is not a permanently trusted party). A malicious coordinator can:

1. Complete a legitimate presigning session, obtaining `PresignOutput` shares.
2. Initiate signing session 1 for message `h1`, collecting all partial signatures.
3. Immediately initiate signing session 2 for message `h2` using the **same** presignature shares (possible because `rerandomize_presign` does not consume them).
4. Recover the private key offline from the two resulting signatures.

No privileged access beyond coordinator participation is required. The `PresignOutput` struct is `pub`, `Clone`, and `Serialize`/`Deserialize`, making it straightforward to store and reuse across sessions. [5](#0-4) 

---

### Recommendation

Change both `rerandomize_presign` signatures to consume the presignature by value, leveraging Rust's ownership system to enforce single-use at compile time:

```rust
// Before (both schemes)
pub fn rerandomize_presign(
    presignature: &PresignOutput,
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError>

// After
pub fn rerandomize_presign(
    presignature: PresignOutput,   // consumed by value — cannot be reused
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError>
```

Additionally, remove the `Clone` derive from `PresignOutput` in both schemes to prevent callers from cloning the value before passing it in, which would otherwise circumvent the ownership-based protection. [3](#0-2) [6](#0-5) 

---

### Proof of Concept

```rust
// Attacker is the coordinator. After presigning:
let presign_out: PresignOutput = /* result of presigning */;

// Session 1: sign message h1
let args1 = RerandomizationArguments::new(pk, tweak1, h1_bytes, presign_out.big_r, participants.clone(), entropy1);
let rerand1 = RerandomizedPresignOutput::rerandomize_presign(&presign_out, &args1).unwrap();
// run signing → (R1, s1)

// Session 2: sign message h2 — presign_out is still alive, never consumed
let args2 = RerandomizationArguments::new(pk, tweak2, h2_bytes, presign_out.big_r, participants.clone(), entropy2);
let rerand2 = RerandomizedPresignOutput::rerandomize_presign(&presign_out, &args2).unwrap();
// run signing → (R2, s2)

// Both δ1, δ2 are deterministic from public args → attacker knows them.
// Solve: s1·δ1 = h1·k + Rx·σ
//        s2·δ2 = h2·k + Rx·σ
// Subtract → k = (s1·δ1 - s2·δ2) / (h1 - h2)
// Then recover x from any single signature equation.
``` [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

**File:** src/ecdsa/ot_based_ecdsa/mod.rs (L40-49)
```rust
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, ZeroizeOnDrop)]
pub struct PresignOutput {
    /// The public nonce commitment.
    #[zeroize[skip]]
    pub big_r: AffinePoint,
    /// Our share of the nonce value.
    pub k: Scalar,
    /// Our share of the sigma value.
    pub sigma: Scalar,
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

**File:** src/ecdsa/robust_ecdsa/mod.rs (L39-52)
```rust
/// The output of the presigning protocol.
/// Contains the signature precomputed elements
/// independently of the message
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

**File:** docs/ecdsa/robust_ecdsa/signing.md (L147-158)
```markdown
# Security considerations

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

**File:** docs/ecdsa/ot_based_ecdsa/orchestration.md (L64-79)
```markdown
## Discarding information

Each phase can be run many times in advance, recording the information
public information produced, as well as the list of parties which produced it.
Then, this output is consumed by having a set of parties use it
for a subsequent phase.
It's **critical** that the output is then destroyed, so that no other
group of parties attempts to re-use that output for another phase.
In particular, the parties need some way of agreeing on which
outputs have been created and used.
If the threshold $t_i$ is such that $N_{i} \leq 2t - 1$, then it's impossible
to have two non-overlapping quorums, so if each party locally registers the
fact that an output has been used, then agreement can be had not to
use a certain output.
Otherwise, you might have two independent groups of parties trying
to use the same output, which is bad.
```

**File:** src/ecdsa/mod.rs (L135-188)
```rust
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
