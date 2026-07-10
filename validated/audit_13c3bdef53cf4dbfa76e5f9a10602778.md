### Title
Unencrypted Transmission of Secret Signing Shares in `do_keyshare` — (File: `src/dkg.rs`)

### Summary
The `do_keyshare` function sends each participant's secret signing share via `chan.send_private()`, which performs no encryption — only serialization and routing. The library's own documentation acknowledges that encryption "might" be needed for private messages but does not enforce it, leaving secret share material transmitted in plaintext over the transport layer. Any party able to observe the outgoing `Action::SendPrivate` messages (e.g., a malicious coordinator, network observer, or integrator) can read and collect plaintext shares.

### Finding Description

**Root cause — `send_private` provides no confidentiality:**

In `src/protocol/internal.rs`, `Comms::send_private` only serializes the payload and enqueues it as `Message::Private(to, message_data)`:

```rust
fn send_private<T: Serialize>(
    &self,
    header: MessageHeader,
    to: Participant,
    data: &T,
) -> Result<(), ProtocolError> {
    let header_bytes = header.to_bytes();
    let message_data = encode_with_tag(&header_bytes, data)?;
    self.send_raw(Message::Private(to, message_data));  // plaintext
    Ok(())
}
``` [1](#0-0) 

No encryption, MAC, or key-agreement step is applied. The library's own `Action::SendPrivate` documentation acknowledges the gap but leaves it optional:

> "It's imperative that only this participant can read this message, so you **might** want to use some form of encryption." [2](#0-1) 

**Vulnerable call site — secret shares sent in plaintext:**

In `do_keyshare`, during Round 4 (Step 4.6), each participant's secret polynomial evaluation — the raw signing share — is sent via `send_private` with no encryption:

```rust
for p in participants.others(me) {
    let signing_share_to_p = secret_coefficients.eval_at_participant(p)?;
    chan.send_private(wait_round_3, p, &signing_share_to_p)?;
}
``` [3](#0-2) 

The `signing_share_to_p` value is a scalar evaluation of the secret polynomial — it is a direct secret share of the private key. It is serialized and emitted as a plaintext `Action::SendPrivate` message to the caller.

**Analogy to the reference vulnerability:**

Just as `ERC721.transferFrom()` sends an NFT without verifying the recipient can handle it (leading to frozen assets), `send_private()` sends secret key material without encrypting it (leading to exposed shares). The library uses the "unsafe" variant — unencrypted routing — where a "safe" variant — authenticated encryption — is required for secret material.

### Impact Explanation

**Critical — Extraction and reconstruction of private signing shares.**

An attacker who can observe `Action::SendPrivate` messages (e.g., a malicious coordinator who relays messages, a network-level observer, or any integrator who logs outgoing actions) receives plaintext `SigningShare` scalars. Collecting `threshold` such shares and applying Lagrange interpolation reconstructs the full private signing key:

```
x = Σ λ_i · x_i   (for any threshold-sized subset of participants)
```

This is exactly the computation performed in the test helper `compute_private_key` in `src/dkg.rs` (lines 701–715), confirming that threshold shares are sufficient for full key recovery. [4](#0-3) 

### Likelihood Explanation

Any deployment where the caller does not independently add authenticated encryption to `Action::SendPrivate` messages is fully vulnerable. The library provides no mechanism to enforce or detect missing encryption. A malicious coordinator (a documented trust boundary in threshold protocols) trivially observes all routed messages. The library's own comment uses "might" rather than "must," making it likely that integrators will omit encryption.

### Recommendation

1. **Enforce encryption internally**: The library should perform an authenticated key-exchange (e.g., ECDH + AEAD) between participant pairs before `do_keyshare` and encrypt all `send_private` payloads internally, removing the burden from callers.
2. **At minimum, change the documentation**: Replace "you might want to use some form of encryption" with a hard requirement and provide a reference implementation, analogous to how `safeTransferFrom()` enforces the recipient check that `transferFrom()` omits.

### Proof of Concept

1. Instantiate a DKG run with `n` participants and threshold `t`.
2. Act as the coordinator/relay layer. Intercept all `Action::SendPrivate(to, data)` messages emitted during Round 4 (waitpoint `wait_round_3`).
3. Deserialize each `data` payload (msgpack-encoded `SigningShare` scalar) — no decryption needed.
4. Collect any `t` shares `(participant_i, share_i)`.
5. Compute Lagrange interpolation at zero over the participant scalars (as done in `compute_private_key` in `src/dkg.rs`):
   ```
   x = Σ λ_i(0) · share_i
   ```
6. Verify: `x · G == public_key`. The full private signing key is recovered without any cryptographic break.

### Citations

**File:** src/protocol/internal.rs (L318-328)
```rust
    fn send_private<T: Serialize>(
        &self,
        header: MessageHeader,
        to: Participant,
        data: &T,
    ) -> Result<(), ProtocolError> {
        let header_bytes = header.to_bytes();
        let message_data = encode_with_tag(&header_bytes, data)?;
        self.send_raw(Message::Private(to, message_data));
        Ok(())
    }
```

**File:** src/protocol/mod.rs (L38-42)
```rust
    ///
    /// It's imperactive that only this participant can read this message,
    /// so you might want to use some form of encryption.
    SendPrivate(Participant, MessageData),
    /// End the protocol by returning a value.
```

**File:** src/dkg.rs (L499-506)
```rust
    for p in participants.others(me) {
        // securely send to each other participant a secret share
        // using the evaluation secret polynomial on the identifier of the recipient
        // should not panic as secret_coefficients are created internally
        let signing_share_to_p = secret_coefficients.eval_at_participant(p)?;
        // send the evaluation privately to participant p
        chan.send_private(wait_round_3, p, &signing_share_to_p)?;
    }
```

**File:** src/dkg.rs (L701-715)
```rust
    fn compute_private_key<C: Ciphersuite>(
        keygen_result: &GenOutput<C>,
    ) -> <<C::Group as Group>::Field as Field>::Scalar {
        let participants = keygen_result.iter().map(|p| p.0).collect::<Vec<_>>();
        let shares = keygen_result
            .iter()
            .map(|r| r.1.private_share.to_scalar())
            .collect::<Vec<_>>();

        let p_list = ParticipantList::new(&participants).unwrap();
        let mut x = <<C::Group as Group>::Field>::zero();
        for i in 0..participants.len() {
            x = x + p_list.lagrange::<C>(participants[i]).unwrap() * shares[i];
        }
        x
```
