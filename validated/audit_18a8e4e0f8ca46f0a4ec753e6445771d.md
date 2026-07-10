### Title
Unauthenticated `from` Parameter in `Protocol::message()` Enables Participant Impersonation and Protocol-Session DoS — (File: `src/protocol/mod.rs`, `src/protocol/helpers.rs`, `src/protocol/internal.rs`)

---

### Summary

The `Protocol::message()` entry point accepts a caller-supplied `from: Participant` identity with no cryptographic authentication. The internal message router stores and deduplicates messages keyed on this unauthenticated identity. Because `recv_from_others` silently discards every message after the first one received per sender, a malicious participant can front-run any honest participant's contribution by injecting a spoofed message first, causing the honest participant's real message to be permanently ignored for that protocol session and forcing a protocol abort.

---

### Finding Description

**Root cause — unauthenticated sender identity accepted at the public API boundary**

`Protocol::message()` is the sole external entry point for delivering network messages to a running protocol instance:

```rust
// src/protocol/mod.rs:64
fn message(&mut self, from: Participant, data: MessageData);
```

The `from` value is a plain `u32` wrapper (`Participant(u32)`). No signature, MAC, or any other proof that the message actually originated from that participant is required or checked. The concrete implementation forwards it directly into the message buffer:

```rust
// src/protocol/internal.rs:512-514
fn message(&mut self, from: Participant, data: MessageData) {
    self.comms.push_message(from, data);
}
```

`push_message` parses only the routing header and stores the message under the caller-supplied `from` identity:

```rust
// src/protocol/internal.rs:286-296
fn push_message(&self, from: Participant, message: MessageData) {
    if message.len() < MessageHeader::LEN { return; }
    let Some(header) = MessageHeader::from_bytes(&message) else { return; };
    self.incoming.push(header, from, message);
}
```

**Root cause — first-come-first-served deduplication in `recv_from_others`**

Every multi-party round that collects one contribution per participant uses `recv_from_others`:

```rust
// src/protocol/helpers.rs:6-26
pub async fn recv_from_others<T>(...) -> Result<Vec<(Participant, T)>, ProtocolError> {
    let mut seen = ParticipantCounter::new(participants);
    seen.put(me);
    ...
    while !seen.full() {
        let (from, msg) = chan.recv(waitpoint).await?;
        if seen.put(from) {          // returns false for any duplicate sender
            messages.push((from, msg));
        }
    }
    Ok(messages)
}
```

`ParticipantCounter::put` marks a slot as seen on the first call and returns `false` for every subsequent call for the same participant. There is no mechanism to prefer an authenticated message over an earlier unauthenticated one.

**Concrete attack path in DKG / Reshare / Refresh**

`do_keyshare` in `src/dkg.rs` calls `recv_from_others` in two critical rounds:

- **Round 1** (commitment-hash collection, line 422–426): each participant broadcasts a hash commitment; `recv_from_others` collects one per sender.
- **Round 5** (secret-share collection, line 514–528): each participant sends a private signing share; `recv_from_others` collects one per sender and immediately calls `validate_received_share` on it.

Attack on Round 5:
1. Malicious participant M is part of a DKG session with honest participants P₁…Pₙ.
2. Before P₁ sends its signing share to victim P₂, M sends `Protocol::message(P₁, crafted_bad_share)` to P₂'s protocol instance.
3. `recv_from_others` on P₂ accepts this as P₁'s share (`seen.put(P₁)` returns `true`).
4. P₁'s legitimate share arrives; `seen.put(P₁)` now returns `false` — the real share is silently dropped.
5. `validate_received_share` verifies the bad share against P₁'s public commitment and returns `ProtocolError::InvalidSecretShare(P₁)`.
6. P₂'s DKG instance aborts. The same attack can be replayed against every honest participant, aborting the entire session.

The same pattern applies to Reshare, Refresh, and any presign/sign round that uses `recv_from_others` over a shared channel.

---

### Impact Explanation

**High — Permanent denial of key generation, reshare, refresh, or signing for honest parties.**

A single malicious participant (or any network-level adversary who can inject messages before they are delivered) can abort any protocol session for any subset of honest participants by front-running their contributions. Because `recv_from_others` irrevocably marks a sender as seen on the first message, there is no recovery within the current session; all honest parties must restart from scratch. The attack is repeatable across every new session, making the denial effectively persistent.

---

### Likelihood Explanation

The attack requires only the ability to deliver a message to a victim's `Protocol::message()` before the legitimate sender does — a standard network-level race condition. Any participant already enrolled in the protocol can trivially do this because they share the same communication channel. No cryptographic capability is needed; the attacker only needs to know the target participant's `Participant` ID (a public `u32`) and the message format (deterministic, derived from public channel tags). The library provides no authentication layer and no documentation requiring the application to supply one.

---

### Recommendation

1. **Authenticate the `from` field.** Require each message to carry a signature under the sender's long-term or session key. Verify this signature inside `Comms::push_message` (or at the `Protocol::message` boundary) before routing the message. Reject any message whose claimed `from` identity does not match the verified signature.

2. **Document the trust assumption explicitly.** If authentication is intentionally delegated to the application layer, the `Protocol::message` API must carry a `# Safety` / `# Preconditions` doc comment stating that the caller guarantees the `from` parameter is authenticated, so integrators know they must provide this guarantee.

3. **Consider last-write-wins or authenticated-only semantics in `recv_from_others`.** At minimum, if a later message from the same sender arrives with a valid authenticator, it should be able to replace an earlier unauthenticated one.

---

### Proof of Concept

```
Participants: P1 (honest), P2 (honest), M (malicious), all enrolled in DKG.

1. DKG Round 5 begins. P1 prepares its signing share for P2.

2. M constructs a syntactically valid but cryptographically wrong share
   for P1's identity:
     bad_share = random scalar (not consistent with P1's commitment)

3. M calls:
     p2_protocol.message(P1, encode(bad_share))
   before P1's real share reaches P2.

4. recv_from_others on P2:
     seen.put(P1) → true  (first message for P1, accepted)
     messages.push((P1, bad_share))

5. P1's real share arrives:
     seen.put(P1) → false (already seen, silently dropped)

6. validate_received_share(me=P2, from=P1, bad_share, P1_commitment)
     → ProtocolError::InvalidSecretShare(P1)

7. P2's DKG instance returns Err, aborting the session.
   M repeats for every other honest participant → full session DoS.
```

**Key production locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** src/protocol/mod.rs (L63-64)
```rust
    /// Inform the protocol of a new message.
    fn message(&mut self, from: Participant, data: MessageData);
```

**File:** src/protocol/internal.rs (L286-296)
```rust
    fn push_message(&self, from: Participant, message: MessageData) {
        if message.len() < MessageHeader::LEN {
            return;
        }

        let Some(header) = MessageHeader::from_bytes(&message) else {
            return;
        };

        self.incoming.push(header, from, message);
    }
```

**File:** src/protocol/helpers.rs (L6-26)
```rust
pub async fn recv_from_others<T>(
    chan: &SharedChannel,
    waitpoint: u64,
    participants: &ParticipantList,
    me: Participant,
) -> Result<Vec<(Participant, T)>, ProtocolError>
where
    T: serde::de::DeserializeOwned,
{
    let mut seen = ParticipantCounter::new(participants);
    seen.put(me);
    let mut messages = Vec::with_capacity(participants.others(me).count());

    while !seen.full() {
        let (from, msg) = chan.recv(waitpoint).await?;
        if seen.put(from) {
            messages.push((from, msg));
        }
    }

    Ok(messages)
```

**File:** src/dkg.rs (L259-286)
```rust
fn validate_received_share<C: Ciphersuite>(
    me: Participant,
    from: Participant,
    signing_share_from: &SigningShare<C>,
    commitment: &VerifiableSecretSharingCommitment<C>,
) -> Result<(), ProtocolError> {
    let id = me.to_identifier::<C>()?;

    // The verification is exactly the same as the regular SecretShare verification;
    // however the required components are in different places.
    // Build a temporary SecretShare so what we can call verify().
    let secret_share = SecretShare::new(id, *signing_share_from, commitment.clone());

    // Verify the share. We don't need the result.
    // Identify the culprit if an InvalidSecretShare error is returned.
    secret_share.verify().map_err(|e| {
        if let Error::InvalidSecretShare { .. } = e {
            ProtocolError::InvalidSecretShare(from)
        } else {
            ProtocolError::AssertionFailed(format!(
                "could not
            extract the verification key matching the secret
            share sent by {from:?}"
            ))
        }
    })?;
    Ok(())
}
```

**File:** src/dkg.rs (L514-528)
```rust
    for (from, signing_share_from) in
        recv_from_others(&chan, wait_round_3, &participants, me).await?
    {
        // Verify the share
        // this deviates from the original FROST DKG paper
        // however it matches the FROST implementation of ZCash
        let full_commitment_from = all_full_commitments.index(from)?;
        // Step 5.2
        validate_received_share::<C>(me, from, &signing_share_from, full_commitment_from)?;

        // Compute the sum of all the owned secret shares
        // At the end of this loop, I will be owning a valid secret signing share
        // Step 5.3
        my_signing_share = my_signing_share + signing_share_from.to_scalar();
    }
```
