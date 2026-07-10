### Title
Presignature Reuse via Non-Consuming `rerandomize_presign` API Enables Secret Key Extraction - (File: src/ecdsa/robust_ecdsa/mod.rs)

### Summary
The `RerandomizedPresignOutput::rerandomize_presign` function accepts `&PresignOutput` (a shared reference) rather than consuming the presignature, and `PresignOutput` derives `Clone`. This means the same presignature can be rerandomized multiple times with different `RerandomizationArguments`. A malicious coordinator can exploit this by directing different participants to rerandomize the same presignature with different `(msg_hash, tweak)` pairs, causing nonce reuse across two signing sessions and enabling full secret key extraction. The signing protocol in `sign.rs` does not validate that all participants used the same rerandomization arguments before accepting their signature shares.

### Finding Description

**Root cause — `rerandomize_presign` does not consume the presignature:**

In `src/ecdsa/robust_ecdsa/mod.rs` (and identically in `src/ecdsa/ot_based_ecdsa/mod.rs`), the rerandomization function is:

```rust
pub fn rerandomize_presign(
    presignature: &PresignOutput,   // shared reference — NOT consumed
    args: &RerandomizationArguments,
) -> Result<Self, ProtocolError> {
    if presignature.big_r != args.big_r {
        return Err(ProtocolError::IncompatibleRerandomizationInputs);
    }
    let delta = args.derive_randomness()?;
    ...
}
```

The only guard is `big_r` equality. There is no:
- Ownership transfer or consumption of `PresignOutput` to enforce one-time use.
- Cross-participant commitment to `RerandomizationArguments` before signature shares are computed.
- Binding of the produced `RerandomizedPresignOutput` to the specific `(msg_hash, tweak, participants, entropy)` used.

`PresignOutput` also derives `Clone`:
```rust
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, ZeroizeOnDrop)]
pub struct PresignOutput {
    pub big_r: AffinePoint,
    pub k: Scalar,
    pub sigma: Scalar,
}
```

**Root cause — `sign` does not validate rerandomization consistency:**

In `src/ecdsa/robust_ecdsa/sign.rs`, the `sign` function accepts a `RerandomizedPresignOutput` that is already rerandomized by the caller:

```rust
pub fn sign(
    participants: &[Participant],
    coordinator: Participant,
    max_malicious: impl Into<MaxMalicious>,
    me: Participant,
    public_key: AffinePoint,
    presignature: RerandomizedPresignOutput,  // no validation of how this was produced
    msg_hash: Scalar,
) -> Result<impl Protocol<Output = SignatureOption>, InitializationError>
```

The function validates `participants.len() == 2t+1` and `msg_hash != 0`, but it does **not** validate that the `presignature` was rerandomized with the same `(msg_hash, tweak, participants, entropy)` that other participants used. There is no protocol round where participants broadcast a commitment to their rerandomization arguments and verify consistency.

**Attack path — malicious coordinator split-view:**

The coordinator's normal role is to distribute signing parameters `(msg_hash, tweak, entropy)` to participants. A malicious coordinator can:

1. Run presigning with participants `{A, B, C}` to produce `PresignOutput` with nonce `R`.
2. Send signing request to participant A with `(h₁, ε₁, ρ)` → A computes `delta₁ = HKDF(Y₁, ε₁, h₁, R, ρ)`, rerandomizes their presignature, computes share `s_A`, and sends it to the coordinator.
3. Send signing request to participant B with `(h₂, ε₂, ρ)` → B computes `delta₂ = HKDF(Y₂, ε₂, h₂, R, ρ)`, rerandomizes the **same** presignature, computes share `s_B`, and sends it to the coordinator.
4. The coordinator now holds two signature shares derived from the same underlying nonce `k` but with different rerandomization scalars `delta₁ ≠ delta₂`.
5. Using the known relationship between `delta₁` and `delta₂` (both derived from the same `R` and known public inputs), the coordinator solves for the secret key shares — a standard ECDSA nonce-reuse attack.

The `sign` function's final verification step (`assert (R, s) is a valid ECDSA signature`) is performed only by the coordinator, who is the attacker and will skip it.

This is the split-view