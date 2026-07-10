### Title
Missing Threshold Parameter in `ckd()` Causes Permanent Denial of CKD When Any Participant Withholds Share — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The `ckd()` function in `src/confidential_key_derivation/protocol.rs` does not accept a threshold parameter, unlike every other protocol entry point (`keygen`, `reshare`, `sign`). As a result, the CKD online phase unconditionally requires **all N participants** to respond — not just the threshold `t`. A single malicious participant within the documented `t-1` malicious-party tolerance can permanently deny CKD for all honest parties by simply withholding their share, violating the threshold security model established during DKG.

---

### Finding Description

Every other public protocol function in the library accepts a threshold parameter:

- `keygen()` — `threshold: impl Into<ReconstructionLowerBound>` [1](#0-0) 
- `reshare()` — `new_threshold: impl Into<ReconstructionLowerBound>` [2](#0-1) 
- `sign()` (OT-based) — `threshold: impl Into<ReconstructionLowerBound>` [3](#0-2) 

The `ckd()` function accepts no threshold parameter at all:

```rust
pub fn ckd(
    participants: &[Participant],
    coordinator: Participant,
    me: Participant,
    key_pair: KeygenOutput,
    app_id: impl Into<AppId>,
    app_pk: PublicKey,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = CKDOutputOption>, InitializationError>
``` [4](#0-3) 

Internally, `do_ckd_coordinator` calls `recv_from_others`, which blocks until **every** participant in the list has responded — there is no threshold-based early exit:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [5](#0-4) 

The root cause is in `compute_signature_share`, which computes Lagrange coefficients over the **full** participant set, making all N shares structurally necessary for a correct result:

```rust
let lambda_i = participants.lagrange::<BLS12381SHA256>(me)?;
let norm_big_y = big_y * lambda_i;
let norm_big_c = big_c * lambda_i;
``` [6](#0-5) 

This is the direct analog to the external report: just as `withdrawFromSUSDVault()` omits the `max_loss` parameter and silently defaults to the most restrictive value (0), `ckd()` omits the threshold parameter and silently defaults to the most restrictive value (N-of-N), making the protocol fragile to any single non-cooperating party.

---

### Impact Explanation

**High — Permanent denial of CKD for honest parties.**

The DKG phase establishes a `t`-of-`N` threshold key. The documented trust assumption is that at most `t-1` parties are malicious. However, the CKD online phase requires all `N` parties to contribute. A single malicious participant — fully within the documented trust budget — can permanently prevent CKD completion by refusing to send `(λ_i · Y_i, λ_i · C_i)` to the coordinator. No retry or timeout can recover from this: the protocol structurally requires all N shares, so the result can never be computed with fewer participants. This breaks the threshold availability guarantee for CKD.

---

### Likelihood Explanation

**High.** Any one of the `N` participants can trigger this unilaterally with zero cryptographic capability — they simply do not send their message. The attacker needs no privileged access, no leaked keys, and no coordination with other parties. The attack is silent and indistinguishable from a network partition until a caller-imposed timeout fires, at which point the CKD request must be abandoned entirely.

---

### Recommendation

Add a `threshold` parameter to `ckd()` mirroring the pattern used by `sign()`, `keygen()`, and `reshare()`. Modify `do_ckd_coordinator` to collect exactly `threshold` shares from any `threshold` willing participants, computing Lagrange coefficients over only those responding participants rather than the full set. This restores the `t`-of-`N` availability guarantee that DKG establishes.

---

### Proof of Concept

1. Run DKG with `N = 3`, `t = 2` (threshold = 2, so 1 malicious party is within tolerance).
2. Initiate a CKD request with all 3 participants listed.
3. Malicious participant `P_3` receives the CKD request but never sends `(λ_3 · Y_3, λ_3 · C_3)` to the coordinator.
4. `do_ckd_coordinator` blocks indefinitely at `recv_from_others` waiting for `P_3`'s message. [5](#0-4) 
5. Even after a caller-imposed timeout and retry with only `{P_1, P_2}`, the Lagrange coefficients are computed over the original full participant set, so the result would be cryptographically incorrect — CKD cannot succeed with fewer than all N participants as currently implemented. [6](#0-5) 
6. CKD is permanently denied for all honest parties as long as `P_3` withholds cooperation.

### Citations

**File:** src/lib.rs (L88-101)
```rust
pub fn keygen<C: Ciphersuite>(
    participants: &[Participant],
    me: Participant,
    threshold: impl Into<ReconstructionLowerBound> + Send + Copy + 'static,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = KeygenOutput<C>>, InitializationError>
where
    Element<C>: Send,
    Scalar<C>: Send,
{
    let comms = Comms::new();
    let participants = assert_key_invariants(participants, me, threshold)?;
    let fut = do_keygen::<C>(comms.shared_channel(), participants, me, threshold, rng);
    Ok(make_protocol(comms, fut))
```

**File:** src/lib.rs (L106-141)
```rust
pub fn reshare<C: Ciphersuite>(
    old_participants: &[Participant],
    old_threshold: impl Into<ReconstructionLowerBound> + Send + 'static,
    old_signing_key: Option<SigningShare<C>>,
    old_public_key: VerifyingKey<C>,
    new_participants: &[Participant],
    new_threshold: impl Into<ReconstructionLowerBound> + Copy + Send + 'static,
    me: Participant,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = KeygenOutput<C>>, InitializationError>
where
    Element<C>: Send,
    Scalar<C>: Send,
{
    let comms = Comms::new();
    let threshold = new_threshold;
    let (participants, old_participants) = assert_reshare_keys_invariants::<C>(
        new_participants,
        me,
        threshold,
        old_signing_key,
        old_threshold,
        old_participants,
    )?;
    let fut = do_reshare(
        comms.shared_channel(),
        participants,
        me,
        threshold,
        old_signing_key,
        old_public_key,
        old_participants,
        rng,
    );
    Ok(make_protocol(comms, fut))
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

**File:** src/confidential_key_derivation/protocol.rs (L50-55)
```rust
    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
```

**File:** src/confidential_key_derivation/protocol.rs (L66-74)
```rust
pub fn ckd(
    participants: &[Participant],
    coordinator: Participant,
    me: Participant,
    key_pair: KeygenOutput,
    app_id: impl Into<AppId>,
    app_pk: PublicKey,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = CKDOutputOption>, InitializationError> {
```

**File:** src/confidential_key_derivation/protocol.rs (L177-180)
```rust
    let lambda_i = participants.lagrange::<BLS12381SHA256>(me)?;
    // Normalize Y and C into  (λi . Y , λi . C)
    let norm_big_y = big_y * lambda_i;
    let norm_big_c = big_c * lambda_i;
```
