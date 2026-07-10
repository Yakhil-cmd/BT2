### Title
Caller-Controlled `entropy` in `RerandomizationArguments` Accepts Predictable Values, Defeating Wagner Attack Mitigation - (File: `src/ecdsa/mod.rs`)

---

### Summary

The `RerandomizationArguments` struct accepts a caller-supplied `entropy: [u8; 32]` field that is documented as needing to be "fresh, unpredictable, and public." However, the library performs no validation on this value. A malicious coordinator can supply a constant or fully predictable entropy (e.g., `[0u8; 32]`), making the rerandomization scalar `delta` entirely deterministic from public inputs. This defeats the Wagner attack mitigation that rerandomization is specifically designed to provide, and enables secret key extraction across multiple signing sessions.

---

### Finding Description

`RerandomizationArguments` is the struct used to derive the rerandomization scalar `delta` via `derive_randomness()`, which computes:

```
delta = HKDF(ikm=entropy, info=(pk, tweak, msg_hash, big_r, participants))
```

The library explicitly documents the security requirement:

```rust
/// *** Warning ***
/// Following [GS21], the entropy should
/// be public, freshly generated, and unpredictable.
/// Fresh, Unpredictable, and Public source of entropy
pub entropy: [u8; 32],
```

However, `RerandomizationArguments::new()` accepts any `[u8; 32]` without any validation:

```rust
pub fn new(
    pk: AffinePoint,
    tweak: Tweak,
    msg_hash: [u8; 32],
    big_r: AffinePoint,
    participants: ParticipantList,
    entropy: [u8; 32],   // ← no validation; caller can pass [0u8; 32] or any constant
) -> Self { ... }
```

And `derive_randomness()` uses it directly as HKDF IKM:

```rust
let hk = Hkdf::<sha3::Sha3_256>::new(Some(&Self::SALT), &self.entropy);
```

All other inputs to `derive_randomness()` — `pk`, `tweak`, `msg_hash`, `big_r`, `participants` — are public. Therefore, if `entropy` is constant or predictable, `delta` is fully determined by public data and is predictable to any observer before the signing session begins.

The coordinator is the party who constructs `RerandomizationArguments` and distributes the rerandomized presignatures to all participants. A malicious coordinator can set `entropy = [0u8; 32]` (or any fixed value) across all signing sessions.

---

### Impact Explanation

The rerandomization step (`delta * R`, `k * delta^{-1}`, `sigma * delta^{-1}`) is the library's explicit countermeasure against the **Wagner attack** on threshold ECDSA, as cited in the code comments referencing [GS21](https://eprint.iacr.org/2021/1330.pdf). The Wagner attack allows an adversary who can adaptively choose or predict nonce-related values across many signing sessions to reconstruct the aggregate secret key.

When `entropy` is constant, `delta` is fully predictable from public data before any signing session begins. The adversary (malicious coordinator) can:

1. Fix `entropy = [0u8; 32]` across all sessions.
2. For each presigning session, compute `delta = HKDF([0u8; 32], pk, tweak, msg_hash, R, participants)` in advance, since all inputs are public.
3. Observe the rerandomized `R' = delta * R` for each session.
4. Selectively choose sessions where `R'` satisfies the algebraic relations required by the Wagner attack.
5. Across sufficiently many sessions, extract the aggregate secret key.

This maps directly to the **Critical** allowed impact: **Extraction, reconstruction, or disclosure of private signing shares, aggregate secret material, presign secrets, nonce material, or confidential derived secrets.**

---

### Likelihood Explanation

The coordinator is a participant in the signing protocol and is the party responsible for constructing `RerandomizationArguments` and distributing rerandomized presignatures. The library's threat model explicitly considers malicious participants (via `MaxMalicious`). A malicious coordinator can trivially pass `entropy = [0u8; 32]` — there is no protocol-level check, no participant-side verification of entropy quality, and no mechanism for honest participants to detect or reject a predictable entropy value. The attack requires multiple signing sessions but no external capabilities beyond controlling the coordinator role.

---

### Recommendation

1. **Enforce entropy non-triviality at construction time**: Reject `entropy` values that are all-zero or otherwise trivially weak (e.g., check `entropy != [0u8; 32]`).
2. **Generate entropy internally**: Rather than accepting entropy as a caller-provided field, generate it internally using a `CryptoRng` inside `RerandomizationArguments::new()`, removing the ability for any caller to supply a predictable value.
3. **Alternatively, derive entropy from a multi-party coin-flip**: Require all participants to contribute randomness to the entropy value so no single party (including the coordinator) can control it unilaterally.

---

### Proof of Concept

```rust
// Malicious coordinator sets entropy to all-zeros
let entropy = [0u8; 32];

// All other inputs are public
let rerand_args = RerandomizationArguments::new(
    derived_pk.to_affine(),
    tweak,
    msg_hash_bytes,
    big_r,
    participants,
    entropy,  // ← constant, predictable
);

// delta = HKDF([0u8;32], pk, tweak, msg_hash, big_r, participants)
// is now fully determined by public data.
// The coordinator can compute delta for any future session in advance,
// enabling adaptive selection of sessions for the Wagner attack.
let delta = rerand_args.derive_randomness().unwrap();
// delta is predictable → Wagner attack mitigation is defeated
``` [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** src/ecdsa/mod.rs (L85-103)
```rust
/// The arguments used to derive randomness used for presignature rerandomization.
/// Presignature rerandomization has been thoroughly described in
/// \[GS21\] <https://eprint.iacr.org/2021/1330.pdf>
///
/// *** Warning ***
/// Following \[GS21\] <https://eprint.iacr.org/2021/1330.pdf>, the entropy should
/// be public, freshly generated, and unpredictable.
// Cannot derive Debug here because an external type inside Tweak does not implement it
#[derive(Clone)]
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

**File:** src/ecdsa/mod.rs (L117-133)
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
```

**File:** src/ecdsa/mod.rs (L161-188)
```rust
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
