### Title
Missing Lower-Bound Validation on `threshold` in FROST Presign and Sign Initialization Allows Corrupt Signing Outputs - (File: src/frost/mod.rs)

### Summary

The FROST `presign` and `assert_sign_inputs` functions validate only the upper bound of the `threshold` parameter (`threshold > participants.len()`), but omit the lower-bound check (`threshold >= 2`) that is enforced in DKG initialization. A malicious coordinator or library caller can supply `threshold = 0` or `threshold = 1` to FROST signing functions, bypassing the guard that DKG enforces, causing the signing protocol to proceed with a cryptographically insecure threshold and produce unusable or corrupted signature outputs that honest parties cannot use.

### Finding Description

`ReconstructionLowerBound` is a plain `usize` newtype with no invariant enforced at construction time: [1](#0-0) 

The DKG initialization path (`assert_key_invariants`) correctly enforces a minimum threshold of 2: [2](#0-1) 

However, the FROST `presign` function only checks the upper bound and omits the lower-bound check entirely: [3](#0-2) 

The same omission exists in `assert_sign_inputs`, which is the shared validation entry point for FROST EdDSA and RedJubjub signing: [4](#0-3) 

A caller supplying `threshold = 0` or `threshold = 1` passes both checks (`0 > N` is false) and the protocol proceeds. The presign phase (`do_presign`) does not use the threshold at all — it only collects nonce commitments — so it completes successfully: [5](#0-4) 

In the subsequent sign phase, the threshold governs Lagrange interpolation over participant shares. With `threshold = 1`, only one participant's share is used and the Lagrange coefficient evaluates to 1, meaning the aggregate signature scalar equals a single participant's share contribution rather than the reconstructed group secret. The resulting signature fails standard verification against the master public key. With `threshold = 0`, the behavior depends on frost_core internals but the guard that should prevent this is absent at the library boundary.

### Impact Explanation

**High — Corruption of sign outputs so honest parties accept unusable cryptographic outputs.**

When a malicious coordinator initiates a FROST signing session with `threshold = 1` (or `0`), all honest participants execute the protocol correctly under their own valid key shares, but the aggregate signature produced is cryptographically invalid (wrong Lagrange basis). Honest parties have no way to detect the bad threshold at the protocol level because the validation gate is missing. The signing round completes without error, but the output signature cannot be verified with the master public key, permanently denying the signing result for that session.

### Likelihood Explanation

**Medium.** The coordinator role is a reachable, documented participant role in the FROST protocol. A malicious coordinator — or any library integrator that accidentally passes an unvalidated `ReconstructionLowerBound(1)` — can trigger this path without any privileged key material. The `ReconstructionLowerBound` type accepts any `usize` via its `From<usize>` derive, so no special capability is required to construct the invalid value.

### Recommendation

Add the same lower-bound check present in `assert_key_invariants` to both `presign` and `assert_sign_inputs` in `src/frost/mod.rs`:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

Optionally, enforce the invariant at the `ReconstructionLowerBound` type level by replacing the `From<usize>` derive with a validated constructor that rejects values below 2, mirroring the pattern already used for `assert_key_invariants`.

### Proof of Concept

```rust
// Attacker-controlled coordinator constructs a threshold of 1
let bad_threshold = ReconstructionLowerBound::from(1usize);

// presign passes: 1 > participants.len() is false for any N >= 2
let presign_proto = frost::presign(
    &participants,   // e.g. [P0, P1, P2]
    me,
    &PresignArguments { keygen_out, threshold: bad_threshold },
    rng,
).unwrap(); // succeeds — no lower-bound check at src/frost/mod.rs:72-77

// assert_sign_inputs passes: 1 > 3 is false
let _ = frost::assert_sign_inputs(
    &participants,
    bad_threshold,
    me,
    coordinator,
).unwrap(); // succeeds — no lower-bound check at src/frost/mod.rs:144-150

// Signing proceeds; Lagrange interpolation uses only 1 share.
// Aggregate signature scalar ≠ group secret → signature fails verification.
// Honest parties have no indication of failure until external verification.
```

The root cause is the asymmetry between `assert_key_invariants` (which rejects `threshold < 2` at `src/dkg.rs:580-582`) and the FROST signing path (which has no equivalent guard at `src/frost/mod.rs:72-77` and `src/frost/mod.rs:144-150`).

### Citations

**File:** src/thresholds.rs (L9-24)
```rust
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, From, Into,
)]
pub struct ReconstructionLowerBound(usize);

// ----- MaxMalicious conversions -----
impl MaxMalicious {
    pub fn value(self) -> usize {
        self.0
    }
}

impl ReconstructionLowerBound {
    pub fn value(self) -> usize {
        self.0
    }
```

**File:** src/dkg.rs (L579-582)
```rust
    // Step 1.1
    if threshold < 2 {
        return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
    }
```

**File:** src/frost/mod.rs (L71-77)
```rust
    // validate threshold
    if args.threshold.value() > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: args.threshold.into(),
            max: participants.len(),
        });
    }
```

**File:** src/frost/mod.rs (L90-117)
```rust
async fn do_presign<C: Ciphersuite + Send>(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    signing_share: SigningShare<C>,
    mut rng: impl CryptoRngCore,
) -> Result<PresignOutput<C>, ProtocolError> {
    // Round 1
    let mut commitments_map: BTreeMap<Identifier<C>, SigningCommitments<C>> = BTreeMap::new();

    // Creating two commitments and corresponding nonces
    let (nonces, commitments) = commit(&signing_share, &mut rng);
    commitments_map.insert(me.to_identifier()?, commitments);

    let commit_waitpoint = chan.next_waitpoint();
    // Sending the commitments to all
    chan.send_many(commit_waitpoint, &commitments)?;

    // Collecting the commitments
    for (from, commitment) in recv_from_others(&chan, commit_waitpoint, &participants, me).await? {
        commitments_map.insert(from.to_identifier()?, commitment);
    }

    Ok(PresignOutput {
        nonces,
        commitments_map,
    })
}
```

**File:** src/frost/mod.rs (L144-150)
```rust
    // validate threshold
    if threshold.value() > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: threshold.value(),
            max: participants.len(),
        });
    }
```
