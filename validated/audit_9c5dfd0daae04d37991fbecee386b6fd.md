### Title
Malicious Coordinator Can Present Different Participant Sets Per Signer in Robust ECDSA Signing, Enabling Secret Key Extraction — (File: `src/ecdsa/robust_ecdsa/sign.rs`, `src/ecdsa/robust_ecdsa/presign.rs`)

---

### Summary

The robust ECDSA signing protocol requires each participant to linearize their signature share using a Lagrange coefficient computed from the signing participant set `P2`. The code does not enforce that all participants receive the same participant set, nor that `|P1| = |P2| = 2t+1`. A malicious coordinator can present different participant sets (or different `(h, ε)` tuples) to different signers — a "split-view" — causing each signer to compute their Lagrange coefficient against a different "spot" participant set. The resulting signature shares, when combined across two such sessions, expose multiplicatively related nonces from which the aggregate secret key can be recovered.

---

### Finding Description

**Analog mapping:**
In `SynthVault`, the weight assigned to a depositor is computed from `calcSpotValueInBase(pool, amount)` — an instantaneous, manipulable price. An attacker inflates this spot price before depositing, inflating their weight and claiming a disproportionate share of rewards. The fix is to use a TWAP so the weight cannot be gamed by a momentary price manipulation.

In the robust ECDSA scheme, the analogous "spot value" is the **coordinator-provided signing participant set** `P2` used by each signer to compute their Lagrange coefficient `λi(P2)`. Each signer computes:

```
s_i ← λi(P2) · (αi · h + βi · Rx + ei)
``` [1](#0-0) 

The Lagrange coefficient `λi(P2)` is computed locally by each participant based on the participant set they were told by the coordinator. There is no broadcast or consistency check that forces all participants to use the **same** `P2`.

**Root cause — no enforcement of N = 2t+1 or participant-set consistency:**

The presign function accepts an arbitrary `participants: ParticipantList` and `args.max_malicious` without validating that `|participants| = 2 * threshold + 1`: [2](#0-1) 

The documentation explicitly acknowledges this is not enforced and provides only advisory recommendations: [3](#0-2) 

Specifically:
- Constraint 1 ("Use exactly N1 = N2 = 2t+1") is not validated in code.
- Constraint 2 ("Ensure all participants agree on (h, ε) and the signing set") is not enforced via any broadcast/consistency mechanism.

**Attack flow (split-view):**

1. Coordinator runs presigning with `N1 = 2t+2` participants (one more than required), producing presignature shares for all `2t+2` parties.
2. For signing session A, coordinator tells participants `{P1…P_{2t+1}}` that the signing set is `{P1…P_{2t+1}}`. Each computes `λi({P1…P_{2t+1}})`.
3. For signing session B (same presignature, same or different message), coordinator tells participants `{P2…P_{2t+2}}` that the signing set is `{P2…P_{2t+2}}`. Each computes `λi({P2…P_{2t+2}})`.
4. The two resulting signatures use nonces `k_A = Σ λi(P_A) · ki` and `k_B = Σ λi(P_B) · ki` — multiplicatively related because they share the same underlying `ki` values from the same presignature.
5. Standard ECDSA nonce-reuse recovery extracts the secret key from the two `(r, s_A)` and `(r, s_B)` pairs.

This is directly analogous to SynthVault: the "spot participant set" plays the role of the "spot price" — it is an unverified, coordinator-controlled instantaneous value used to compute a critical quantity (Lagrange coefficient / weight) that determines the protocol output.

---

### Impact Explanation

**Critical — secret key extraction.** A malicious coordinator with no leaked keys and no cryptographic breaks can extract the aggregate signing key by running two signing sessions with overlapping but distinct participant sets drawn from a presigning set of size `2t+2`. This matches the allowed impact: *"Extraction, reconstruction, or disclosure of private signing shares, aggregate secret material, presign secrets, nonce material, or confidential derived secrets."* [4](#0-3) 

---

### Likelihood Explanation

The coordinator role is an in-scope attacker profile per the prompt. The coordinator already controls which messages are sent to which participants and which participant sets are declared for each session. No external oracle manipulation, no leaked keys, and no cryptographic primitive break is required. The attack requires only two signing sessions and a presigning set of size `2t+2` instead of `2t+1` — a one-participant deviation that is not rejected by the code. [5](#0-4) 

---

### Recommendation

Enforce `|participants| = 2 * max_malicious + 1` as a hard invariant in both `presign` and `sign` entry points (analogous to using a TWAP instead of a spot price). Additionally, add a reliable broadcast round at the start of signing so all participants commit to the same `(h, ε, P2)` tuple before computing their Lagrange coefficients, preventing the coordinator from presenting different "spot" participant sets to different signers. [2](#0-1) 

---

### Proof of Concept

1. Run DKG with `N = 2t+2` participants, e.g. `t=1`, `N=4`: participants `{P1, P2, P3, P4}`.
2. Run presigning with all 4 participants, producing presignature shares `(αi, βi, ei)` for `i ∈ {1,2,3,4}`.
3. **Session A:** Coordinator tells `{P1, P2, P3}` the signing set is `{P1, P2, P3}` and message hash `h`. Each computes `si_A = λi({P1,P2,P3}) · (αi·h + βi·Rx + ei)`. Coordinator collects and sums to get signature `(R, sA)`.
4. **Session B:** Coordinator tells `{P2, P3, P4}` the signing set is `{P2, P3, P4}` and the same `h`. Each computes `si_B = λi({P2,P3,P4}) · (αi·h + βi·Rx + ei)`. Coordinator collects and sums to get signature `(R, sB)`.
5. Both signatures share the same `R` (same presignature nonce point). Apply standard ECDSA nonce-reuse key recovery: `x = (sA · kA - sB · kB) / (sA - sB)` (with the known linear relationship between `kA` and `kB` derived from the Lagrange coefficients), recovering the aggregate secret key `x`. [6](#0-5)

### Citations

**File:** docs/ecdsa/robust_ecdsa/signing.md (L96-98)
```markdown
1. Each $P_i$ computes its signature share $s_i \gets \alpha_i * h + \beta_i \cdot R_\mathsf{x} + e_i$ where $R_\mathsf{x}$ is the x coordinate of $R$.
2. Each $P_i$ linearizes its signature share $s_i \gets \lambda_i(\mathcal{P}_2) s_i$.
3. $\star$ Each $P_i$ sends $s_i$ **only to the coordinator**.
```

**File:** docs/ecdsa/robust_ecdsa/signing.md (L147-181)
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

3. **Never reuse a presignature**, even across failed, aborted, or partially completed
   signing sessions.

4. **Do not sign with $h = 0$** (the zero message hash).
   This input enables a related algebraic split-view attack in the modified scheme when
   $N_1 > 2t + 1$.
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L89-101)
```rust
async fn do_presign(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    args: PresignArguments,
    mut rng: impl CryptoRngCore,
) -> Result<PresignOutput, ProtocolError> {
    let rng = &mut rng;
    let threshold = args.max_malicious.value();
    // Round 1
    let degree = threshold
        .checked_mul(2)
        .ok_or(ProtocolError::IntegerOverflow)?;
```
