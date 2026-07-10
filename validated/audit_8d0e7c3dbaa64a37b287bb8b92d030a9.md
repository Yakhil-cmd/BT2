### Title
Malicious Coordinator Can Present Different `msg_hash`/`tweak` to Different Participants, Enabling Secret Key Extraction via Split-View Attack — (`File: src/ecdsa/robust_ecdsa/sign.rs`)

---

### Summary

The Robust ECDSA signing protocol in `src/ecdsa/robust_ecdsa/sign.rs` contains no in-protocol mechanism to ensure all participants agree on the same `(msg_hash, tweak)` before contributing their signature shares. A malicious coordinator — a reachable, unprivileged role — can present different message hashes or tweaks to different participants within a single signing session. Because the signing protocol is asymmetric (participants send shares only to the coordinator, never to each other), participants cannot detect the equivocation. The result is that two signing sessions over the same presignature with different `(h, ε)` values produce signatures with multiplicatively related nonces, enabling full secret key recovery via standard ECDSA nonce-reuse techniques.

---

### Finding Description

The `sign()` function in `src/ecdsa/robust_ecdsa/sign.rs` accepts `msg_hash` and a `RerandomizedPresignOutput` (which encodes the tweak) as independent, caller-supplied parameters for each participant:

```rust
pub fn sign(
    participants: &[Participant],
    coordinator: Participant,
    max_malicious: impl Into<MaxMalicious>,
    me: Participant,
    public_key: AffinePoint,
    presignature: RerandomizedPresignOutput,
    msg_hash: Scalar,
) -> Result<impl Protocol<Output = SignatureOption>, InitializationError>
``` [1](#0-0) 

Each participant independently calls `sign()` with their own `msg_hash` and `presignature`. The protocol's only communication is a one-way send from each participant to the coordinator:

```rust
fn do_sign_participant(...) -> Result<SignatureOption, ProtocolError> {
    let s_me = compute_signature_share(presignature, msg_hash, participants, me)?;
    let wait_round = chan.next_waitpoint();
    chan.send_private(wait_round, coordinator, &s_me)?;
    Ok(None)
}
``` [2](#0-1) 

There is no broadcast round where participants exchange and verify each other's `msg_hash` or `tweak`. The coordinator is the sole aggregator. A malicious coordinator can therefore instruct participant A to call `sign()` with `msg_hash = h1` and participant B with `msg_hash = h2`, collect both shares, and combine them.

The security documentation explicitly identifies this gap and states the constraint is the caller's responsibility:

> "Ensure all participants agree on (h, ε) and the signing set. The coordinator must not be able to present different message hashes, tweaks, or participant lists to different signers." [3](#0-2) 

The library enforces `N = 2t+1` and `msg_hash ≠ 0` in code: [4](#0-3) 

But it provides **no enforcement** of cross-participant agreement on `(msg_hash, tweak)`. The `RerandomizedPresignOutput` struct is opaque to the signing protocol — it carries the tweak-blinded nonce shares but no binding commitment that all participants rerandomized with the same arguments. [5](#0-4) 

The rerandomization step in `RerandomizedPresignOutput::rerandomize_presign` binds `delta` to `(pk, tweak, msg_hash, R, participants, entropy)` via HKDF, but this binding is computed locally by each participant with no cross-verification: [6](#0-5) 

---

### Impact Explanation

The security documentation states:

> "If different subsets of size at least 2t+1 sign different (h, ε) values using shares derived from the same presignature, the resulting signatures use multiplicatively related nonces and the secret key can be recovered using standard ECDSA nonce-reuse attacks." [7](#0-6) 

> "A novel split-view attack exists that can extract the secret key using as few as 2t+2 presigning participants, with as few as two signing sessions." [8](#0-7) 

The impact is **Critical**: full extraction of the aggregate private signing key from honest participants' secret shares, matching the allowed impact "Extraction, reconstruction, or disclosure of private signing shares, aggregate secret material."

---

### Likelihood Explanation

The coordinator is a standard participant role — reachable without any privileged key or external assumption. In any deployment where the coordinator is responsible for distributing the message to be signed (the common case), a malicious coordinator can trivially present `h1` to participant A and `h2` to participant B. The library provides no API or protocol mechanism for participants to independently verify the message hash before contributing their share. The attack requires only two signing sessions over the same presignature (which the library also does not prevent by code — `PresignOutput` is a plain cloneable struct with no usage tracking). [9](#0-8) 

---

### Recommendation

Add a mandatory broadcast round at the start of the signing protocol where each participant commits to their `(msg_hash, tweak, participants)` tuple and verifies that all other participants committed to the same values before computing and sending their signature share. This transforms the one-way participant→coordinator flow into a two-phase commit that prevents equivocation. Alternatively, require participants to receive the message hash via a reliable broadcast channel (not from the coordinator alone) before entering the signing protocol.

---

### Proof of Concept

**Setup**: `t = 1`, so `N = 2t+1 = 3` participants: `{P1 (coordinator/malicious), P2, P3}`. One presignature `(R, α_i, β_i, c_i, e_i)` is generated and distributed.

**Attack**:

1. Malicious coordinator `P1` instructs `P2` to call `sign(..., msg_hash = h1)` and `P3` to call `sign(..., msg_hash = h2)` where `h1 ≠ h2`.
2. `P2` computes `s_2 = λ_2 · (α_2·h1 + β_2·Rx + e_2)` and sends to `P1`.
3. `P3` computes `s_3 = λ_3 · (α_3·h2 + β_3·Rx + e_3)` and sends to `P1`.
4. `P1` computes its own share with either `h1` or `h2`.
5. `P1` now holds two signatures `(R, s)` and `(R', s')` over the same presignature nonce with different effective messages. By the nonce-reuse relation, the secret key `x` satisfies a linear equation solvable from the two `(R, s)` pairs.

No participant detects the inconsistency because `do_sign_participant` sends its share and immediately returns `None` with no further protocol interaction. [10](#0-9)

### Citations

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

**File:** src/ecdsa/robust_ecdsa/sign.rs (L110-124)
```rust
/// Performs signing from any participant's perspective (except the coordinator)
fn do_sign_participant(
    mut chan: SharedChannel,
    participants: &ParticipantList,
    coordinator: Participant,
    me: Participant,
    presignature: &RerandomizedPresignOutput,
    msg_hash: Scalar,
) -> Result<SignatureOption, ProtocolError> {
    let s_me = compute_signature_share(presignature, msg_hash, participants, me)?;
    let wait_round = chan.next_waitpoint();
    chan.send_private(wait_round, coordinator, &s_me)?;

    Ok(None)
}
```

**File:** docs/ecdsa/robust_ecdsa/signing.md (L150-154)
```markdown
be aware that it is vulnerable to **split-view attacks** in the robust setting when the
signing parameters are not globally consistent. If different subsets of size at least
$2t + 1$ sign different $(h, \epsilon)$ values using shares derived from the same
presignature, the resulting signatures use multiplicatively related nonces and the
secret key can be recovered using standard ECDSA nonce-reuse attacks.
```

**File:** docs/ecdsa/robust_ecdsa/signing.md (L156-158)
```markdown
Moreover, due to protocol modifications relative to [[DJNPO20](https://eprint.iacr.org/2020/501)] (notably signature-share
linearization), **a novel split-view attack exists that can extract the secret key using as
few as $2t + 2$ presigning participants**, with as few as two signing sessions.
```

**File:** docs/ecdsa/robust_ecdsa/signing.md (L172-174)
```markdown
2. **Ensure all participants agree on $(h, \epsilon)$ and the signing set.**
   The coordinator must not be able to present different message hashes, tweaks, or
   participant lists to different signers.
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

**File:** src/ecdsa/mod.rs (L139-162)
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
