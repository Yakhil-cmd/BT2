### Title
Same Beaver Triple Used for Both `triple0` and `triple1` in `PresignArguments` — (`File: src/ecdsa/ot_based_ecdsa/mod.rs`)

### Summary
The `PresignArguments` struct accepts two Beaver triples (`triple0`, `triple1`) that the OT-based ECDSA presign protocol requires to be cryptographically independent. No validation prevents a caller from supplying the same triple for both positions. Reusing the same triple breaks the independence assumption of the Cait-Sith protocol, corrupting the presign output and potentially enabling secret key extraction.

### Finding Description
In `src/ecdsa/ot_based_ecdsa/mod.rs`, the public `PresignArguments` struct is defined as:

```rust
pub struct PresignArguments {
    pub triple0: (TripleShare, TriplePub),
    pub triple1: (TripleShare, TriplePub),
    pub keygen_out: KeygenOutput,
    pub threshold: ReconstructionLowerBound,
}
``` [1](#0-0) 

The struct is constructed entirely by the caller and passed directly into the presign protocol. There is no check — neither at construction time nor at protocol entry — that `triple0` and `triple1` are distinct triples. The Cait-Sith protocol on which this implementation is based requires two **independent** Beaver triples: one to blind the nonce `k` and a second, independent one to blind `sigma = k·x`. If the same triple `(a, b, c)` with `c = a·b` is supplied for both positions, the two blinding layers become algebraically correlated, violating the security proof.

The analog to the external report is direct: just as `token0 == token1` is an unhandled edge case in the DeFi contract's constructor, `triple0 == triple1` is an unhandled edge case in `PresignArguments` — the condition is never prevented and never detected.

### Impact Explanation
When `triple0 == triple1`, the nonce share `k` and the sigma share `sigma` are derived from the same underlying randomness. The algebraic relationship `sigma = k·x + …` (where `x` is the secret signing key) becomes solvable with a single presign transcript because the two "independent" masking values collapse to one. An attacker who controls triple generation (a malicious coordinator or a compromised triple-generation phase) can supply the same triple twice, observe the resulting presign output, and solve for `x`. This maps to:

**Critical — Extraction, reconstruction, or disclosure of private signing shares / aggregate secret material.**

### Likelihood Explanation
`PresignArguments` is a public struct whose fields are set directly by the caller. A malicious coordinator orchestrating the presign phase, or a participant who controls triple distribution, can trivially set `triple0 = triple1`. No runtime guard exists anywhere in the call path from `PresignArguments` construction through `do_keyshare` or the presign protocol entry point to reject this input. Likelihood is **High** for any deployment where the triple-supply path is not fully trusted.

### Recommendation
Add an explicit equality check at the point where `PresignArguments` is consumed (or in a dedicated validation function analogous to `assert_key_invariants`):

```rust
if arguments.triple0.1 == arguments.triple1.1 {
    return Err(ProtocolError::AssertionFailed(
        "triple0 and triple1 must be distinct".to_string()
    ));
}
```

`TriplePub` (the public component) is the appropriate field to compare because it is the shared, serializable part that uniquely identifies a triple across all participants. This mirrors the pattern already used in `assert_key_invariants` and `assert_reshare_keys_invariants` in `src/dkg.rs`. [2](#0-1) 

### Proof of Concept
1. Caller generates one Beaver triple `T = (share, pub)` via the triple-generation protocol.
2. Caller constructs `PresignArguments { triple0: T.clone(), triple1: T.clone(), keygen_out, threshold }`.
3. The presign protocol proceeds without error, producing a `PresignOutput` whose `k` and `sigma` shares are derived from the same underlying randomness.
4. Because `sigma = k·x` (mod q) and both `k` and `sigma` are now masked by the same blinding factor, the ratio `sigma / k` directly yields `x` — the aggregate secret signing key — from a single presign transcript.
5. No existing check in `src/ecdsa/ot_based_ecdsa/mod.rs` or `src/dkg.rs` detects or rejects this input. [1](#0-0)

### Citations

**File:** src/ecdsa/ot_based_ecdsa/mod.rs (L24-34)
```rust
pub struct PresignArguments {
    /// The first triple's public information, and our share.
    pub triple0: (TripleShare, TriplePub),
    /// Ditto, for the second triple.
    pub triple1: (TripleShare, TriplePub),
    /// The output of key generation, i.e. our share of the secret key, and the public key package.
    /// This is of type `KeygenOutput<Secp256K1Sha256>` from Frost implementation
    pub keygen_out: KeygenOutput,
    /// The desired threshold for the presignature, which must match the original threshold
    pub threshold: ReconstructionLowerBound,
}
```

**File:** src/dkg.rs (L558-596)
```rust
pub fn assert_key_invariants(
    participants: &[Participant],
    me: Participant,
    threshold: impl Into<ReconstructionLowerBound>,
) -> Result<ParticipantList, InitializationError> {
    let threshold = usize::from(threshold.into());
    // need enough participants
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }

    // Step 1.1
    // validate threshold
    if threshold > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold,
            max: participants.len(),
        });
    }
    // Step 1.1
    if threshold < 2 {
        return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
    }

    // ensure uniqueness of participants in the participant list
    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;

    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }
    Ok(participants)
}
```
