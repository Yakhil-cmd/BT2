### Title
Presignature Nonce Reuse via Cloneable `RerandomizedPresignOutput` and Unenforced `msg_hash` Binding Enables Private Key Extraction — (File: `src/ecdsa/ot_based_ecdsa/mod.rs`, `src/ecdsa/ot_based_ecdsa/sign.rs`, `src/ecdsa/mod.rs`)

---

### Summary

The OT-based ECDSA signing pipeline exposes a `RerandomizedPresignOutput` type that derives `Clone` and is accepted by value in the `sign` function with no nonce-use tracking. Simultaneously, the `msg_hash` embedded in `RerandomizationArguments` (used to derive the rerandomized nonce `delta`) is never enforced to match the `msg_hash` passed separately to `sign`. A malicious coordinator can clone a single `RerandomizedPresignOutput` and invoke `sign` twice with two distinct `msg_hash` values, producing two valid ECDSA signatures that share the same nonce `R = delta·G`. Classic nonce-reuse algebra then recovers the aggregate private key `x` in full.

---

### Finding Description

**Root cause 1 — `RerandomizedPresignOutput` is `Clone` with no use-tracking.**

`src/ecdsa/ot_based_ecdsa/mod.rs` lines 54–63:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct RerandomizedPresignOutput {
    pub big_r: AffinePoint,
    pub k: Scalar,
    pub sigma: Scalar,
}
```

The type is freely cloneable. The `sign` function at `src/ecdsa/ot_based_ecdsa/sign.rs` line 28 accepts it by value (`presignature: RerandomizedPresignOutput`), but because the caller can `.clone()` before the call, consumption provides no safety guarantee. No session ID, use-flag, or nonce registry exists anywhere in the library.

**Root cause 2 — `msg_hash` in `RerandomizationArguments` is decoupled from `msg_hash` in `sign`.**

`RerandomizationArguments::derive_randomness` (`src/ecdsa/mod.rs` lines 139–188) folds `self.msg_hash` into the HKDF input to make `delta` message-specific:

```rust
let encoded_msg_hash: &[u8] = &self.msg_hash;
// ...
concatenation.extend_from_slice(encoded_msg_hash);
let hk = Hkdf::<sha3::Sha3_256>::new(Some(&Self::SALT), &self.entropy);
```

This is the library's sole defence against nonce reuse: if the coordinator uses a different `msg_hash` in `RerandomizationArguments`, a different `delta` is produced and the rerandomized `big_r` changes. However, the `sign` function at `src/ecdsa/ot_based_ecdsa/sign.rs` line 29 accepts a completely independent `msg_hash: Scalar` that is never compared against the `msg_hash` baked into the `RerandomizedPresignOutput`. The library contains no assertion, no binding, and no documentation warning at the `sign` call-site that these two values must agree.

**Attack chain (malicious coordinator):**

1. Coordinator participates in `presign` and obtains `PresignOutput` (containing nonce shares `k_i`, `sigma_i`, and public nonce `big_r = R`).
2. Coordinator constructs `RerandomizationArguments { msg_hash: m_fixed, entropy: E, big_r: R, … }` and calls `RerandomizedPresignOutput::rerandomize_presign`, obtaining `out` with rerandomized nonce `R' = delta·R` where `delta = HKDF(E; m_fixed, R, …)`.
3. Coordinator clones `out` → `out2 = out.clone()`.
4. Coordinator calls `sign(…, presignature: out,  msg_hash: m1)` → participants contribute shares; coordinator assembles valid signature `σ1 = (R', s1)` for message `m1`.
5. Coordinator calls `sign(…, presignature: out2, msg_hash: m2)` → participants contribute shares again (they have no visibility into prior use); coordinator assembles valid signature `σ2 = (R', s2)` for message `m2`.
6. Both signatures share the same `R'`. Standard nonce-reuse recovery:
   - `s1 = m1·k' + Rx'·σ'` and `s2 = m2·k' + Rx'·σ'` (aggregate scalars)
   - `k' = (s1 − s2)/(m1 − m2)`
   - `x = (s1·k' − m1) / Rx'`

The aggregate private key `x` is fully recovered.

Participants cannot detect the reuse: the `sign` protocol gives each participant only their own presignature share and the coordinator-supplied `msg_hash`; there is no cross-session binding or nonce-use ledger.

---

### Impact Explanation

**Critical — Extraction of the aggregate private signing key.**

Two signatures produced under the same nonce `R'` but different messages `m1`, `m2` are sufficient to algebraically reconstruct the full private key `x`. This key underlies all threshold signatures produced by the group; its disclosure allows the attacker to forge arbitrary signatures unilaterally, without any further participation from honest parties.

---

### Likelihood Explanation

**High.** The coordinator role is a standard, documented participant in every signing session. A single malicious coordinator — or a coordinator whose signing-session orchestration layer is compromised — can execute this attack with no special cryptographic capability: it requires only calling `.clone()` on a public Rust type and invoking `sign` twice. The library's only intended defence (message-binding in `derive_randomness`) is silently bypassed because the `sign` API accepts an independent `msg_hash`. Honest participants have no mechanism to detect or refuse the second signing request.

---

### Recommendation

1. **Bind `msg_hash` at the type level.** Remove the standalone `msg_hash` parameter from `sign` and instead embed it inside `RerandomizedPresignOutput` at rerandomization time. The signing function should use only the `msg_hash` already committed to during rerandomization, making mismatch structurally impossible.

2. **Remove `Clone` from `RerandomizedPresignOutput` and `PresignOutput`.** Nonce-bearing types should be consumed on first use. If cloneability is required for serialization or storage, replace it with an explicit `into_bytes`/`from_bytes` round-trip that forces the caller to acknowledge the operation.

3. **Add a nonce-use flag or one-shot wrapper.** If the above changes are not feasible, wrap `RerandomizedPresignOutput` in a `OnceCell`-style type that panics or errors on second use.

4. **Add a call-site assertion in `sign`.** At minimum, assert that the `msg_hash` passed to `sign` matches the `msg_hash` stored in the rerandomization arguments used to produce the presignature, and document this invariant prominently.

---

### Proof of Concept

```rust
// Coordinator-side pseudocode demonstrating the attack

// Step 1: obtain presign output (normal protocol execution)
let presign_out: PresignOutput = run_presign_protocol(participants, keygen_out, triples);

// Step 2: rerandomize with msg_hash = m_fixed
let args = RerandomizationArguments::new(pk, tweak, m_fixed, presign_out.big_r, participants, entropy);
let rerandomized: RerandomizedPresignOutput =
    RerandomizedPresignOutput::rerandomize_presign(&presign_out, &args).unwrap();

// Step 3: clone — library permits this freely
let rerandomized_copy = rerandomized.clone();

// Step 4: sign message m1 — nonce R' = delta·R is used
let sig1: Signature = run_sign_protocol(participants, coordinator, rerandomized,      m1_hash);

// Step 5: sign message m2 with the SAME nonce — library has no guard
let sig2: Signature = run_sign_protocol(participants, coordinator, rerandomized_copy, m2_hash);

// Step 6: both signatures share sig1.big_r == sig2.big_r == R'
assert_eq!(sig1.big_r, sig2.big_r); // same nonce

// Step 7: recover private key
// k_prime = (s1 - s2) / (m1 - m2)
// x       = (s1 * k_prime - m1) / Rx
let k_prime = (sig1.s - sig2.s) * (m1_hash - m2_hash).invert().unwrap();
let rx      = x_coordinate(&sig1.big_r);
let x_recovered = (sig1.s * k_prime - m1_hash) * rx.invert().unwrap();
// x_recovered == aggregate private key
```

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** src/ecdsa/ot_based_ecdsa/mod.rs (L54-63)
```rust
#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct RerandomizedPresignOutput {
    /// The rerandomized public nonce commitment.
    #[zeroize[skip]]
    pub big_r: AffinePoint,
    /// Our rerandomized share of the nonce value.
    pub k: Scalar,
    /// Our rerandomized share of the sigma value.
    pub sigma: Scalar,
}
```

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L22-30)
```rust
pub fn sign(
    participants: &[Participant],
    coordinator: Participant,
    threshold: impl Into<ReconstructionLowerBound>,
    me: Participant,
    public_key: AffinePoint,
    presignature: RerandomizedPresignOutput,
    msg_hash: Scalar,
) -> Result<impl Protocol<Output = SignatureOption>, InitializationError> {
```

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L139-159)
```rust
fn compute_signature_share(
    participants: &ParticipantList,
    me: Participant,
    presignature: &RerandomizedPresignOutput,
    msg_hash: Scalar,
) -> Result<Scalar, ProtocolError> {
    // Round 1
    // Linearize ki
    // Spec 1.1
    let lambda = participants.lagrange::<Secp256K1Sha256>(me)?;
    let k_i = lambda * presignature.k;

    // Linearize sigmai
    // Spec 1.2
    let sigma_i = lambda * presignature.sigma;

    // Compute si = h * ki + Rx * sigmai
    // Spec 1.3
    let r = x_coordinate(&presignature.big_r);
    Ok(msg_hash * k_i + r * sigma_i)
}
```

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

**File:** src/ecdsa/mod.rs (L139-163)
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

```
