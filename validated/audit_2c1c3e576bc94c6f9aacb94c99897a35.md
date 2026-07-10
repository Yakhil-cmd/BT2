### Title
Malicious Coordinator Equivocates on Randomizer via Unauthenticated `send_many` in FROST RedJubjub Signing — (File: `src/frost/redjubjub/sign.rs`)

---

### Summary

The FROST RedJubjub signing protocol distributes the coordinator-chosen `Randomizer` to participants using `chan.send_many`, a primitive explicitly documented as having **"no security guarantees"** (peer-to-peer, no consistency or agreement). A malicious coordinator can send a different `Randomizer` to each participant. Because the `Randomizer` determines the effective randomized public key and thus the Fiat-Shamir challenge, participants compute signature shares under mutually inconsistent challenges. The resulting shares cannot be aggregated into a valid signature, and honest participants have no mechanism to detect the equivocation. This corrupts the signing output and constitutes a reachable, coordinator-triggered denial of signing.

---

### Finding Description

**Root cause — unauthenticated broadcast of the randomizer:**

In `do_sign_coordinator` (`src/frost/redjubjub/sign.rs`, line 150):

```rust
// Send the Randomizer to everyone
let wait_round_1 = chan.next_waitpoint();
chan.send_many(wait_round_1, &randomizer)?;
```

`send_many` is the unauthenticated, non-reliable primitive. The network-layer documentation (`docs/network-layer.md`, line 23) states explicitly:

> **`send_many`**: Sends a message to participants except the sender itself. This is a peer-to-peer sending with **no security guarantees** used by one sender in destination to multiple receivers.

The authenticated, consistency-guaranteeing primitive is `echo_broadcast`, which provides the **Agreement** property: if any correct process delivers a message `m`, every correct process eventually delivers the same `m`. `send_many` provides no such guarantee.

**Participant acceptance — no cross-participant consistency check:**

In `do_sign_participant` (`src/frost/redjubjub/sign.rs`, lines 216–223):

```rust
let wait_round_1 = chan.next_waitpoint();
let randomizer = loop {
    let (from, randomizer): (_, Randomizer) = chan.recv(wait_round_1).await?;
    if from != coordinator {
        continue;
    }
    break randomizer;
};
```

Each participant accepts the first message tagged as coming from the coordinator and uses it unconditionally. There is no mechanism for participants to verify that all other participants received the same `Randomizer`.

**How the randomizer affects signing:**

After receiving the randomizer, each participant computes:

```rust
let signing_package = SigningPackage::new(presignature.commitments_map, &message);
let signature_share = round2::sign(&signing_package, &nonces, &key_package, randomizer)
    .map_err(|_| ProtocolError::ErrorFrostSigningFailed)?;
```
(`src/frost/redjubjub/sign.rs`, lines 228–230)

The `Randomizer` enters the Fiat-Shamir challenge as `c = H(R, pk + r·G, message)`. If participant A receives `r_A` and participant B receives `r_B ≠ r_A`, they compute different challenges `c_A ≠ c_B` and thus produce signature shares that are cryptographically inconsistent with one another. The coordinator's `aggregate()` call will fail or produce an invalid signature.

---

### Impact Explanation

A malicious coordinator sends a distinct randomizer `r_i` to each participant `i`. Every participant computes its signature share `s_i = nonce_i + x_i · c_i` where `c_i = H(R, pk + r_i · G, message)`. Because `c_i` differs per participant, the shares do not satisfy the linear relation required for aggregation. The coordinator receives all shares but cannot produce a valid signature.

Honest participants have no way to detect this: they each return `Ok(None)` (non-coordinator output), believing the signing session completed normally. The presignature nonces are consumed. The coordinator can repeat this across all available presignatures, permanently exhausting the signing capability for honest parties without ever producing a valid signature.

This maps to: **High — Corruption of sign outputs so honest parties accept inconsistent transcripts or unusable cryptographic outputs**, and **High — Permanent denial of signing for honest parties under valid protocol inputs**.

Additionally, if participants are induced to reuse a presignature (e.g., because the coordinator falsely reports the first session as failed), the coordinator — knowing both `r_i^1` and `r_i^2` it sent — can solve for the private key share `x_i = (s_i^1 − s_i^2) / (c_i^1 − c_i^2)`, escalating to **Critical — extraction of private signing shares**.

---

### Likelihood Explanation

The coordinator role requires no privileged key material beyond being a listed participant. Any participant designated as coordinator can execute this attack. The attack requires only the ability to send different byte sequences to different peers, which is trivially achievable at the network layer (TLS authenticates the sender's identity but does not enforce that the same plaintext is sent to all recipients). The attack is silent: no honest participant raises an error.

---

### Recommendation

Replace `chan.send_many` with `echo_broadcast` for the randomizer distribution step. The `echo_broadcast` primitive (`src/protocol/echo_broadcast.rs`) provides the **Agreement** property, ensuring all honest participants deliver the same randomizer or all abort. This is the same primitive already used in the DKG protocol for commitment distribution, and it is the correct primitive whenever a single sender must convince multiple receivers of a consistent value.

```rust
// Replace:
chan.send_many(wait_round_1, &randomizer)?;

// With:
chan.echo_broadcast(wait_round_1, &randomizer)?;
```

Participants should then receive the randomizer via the echo broadcast delivery mechanism rather than a raw `recv`.

---

### Proof of Concept

1. A signing session is initiated with participants `{A, B, C}` and coordinator `C` (a malicious participant).
2. All participants run `sign(...)` in `src/frost/redjubjub/sign.rs` with a shared presignature.
3. Coordinator `C` reaches `do_sign_coordinator`, line 150: instead of calling `chan.send_many(wait_round_1, &randomizer)` with a single value, it injects two different messages at the network layer — `r_1` to participant `A` and `r_2 ≠ r_1` to participant `B`.
4. Participant `A` computes `s_A` using challenge `c_A = H(R, pk + r_1·G, message)`.
5. Participant `B` computes `s_B` using challenge `c_B = H(R, pk + r_2·G, message)`.
6. Coordinator `C` receives `s_A` and `s_B`. The `aggregate()` call at line 178 fails because the shares are inconsistent.
7. `A` and `B` each returned `Ok(None)`, believing the session completed. Their presignature nonces are consumed.
8. Coordinator `C` repeats across all presignatures, permanently denying signing.
9. If `A` or `B` is induced to reuse a presignature across two such sessions (with `r_1^1, r_1^2` sent to `A`), the coordinator solves `x_A = (s_A^1 − s_A^2) / (c_A^1 − c_A^2)`, extracting `A`'s private key share.