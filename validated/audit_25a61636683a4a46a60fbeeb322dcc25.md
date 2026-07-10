The exploit path is concrete and fully traceable. Here is the analysis:

---

### Title
Malicious Participant Aborts Honest Party's Presign via Malformed Round-1 Vec Length — (`src/ecdsa/robust_ecdsa/presign.rs`)

### Summary

In `robust_ecdsa/presign.rs`, the round-1 private message is sent as a `Vec<SerializableScalar<C>>` but deserialized on the receiving end as `Shares([SerializableScalar<C>; 5])`. A malicious participant can send a Vec with any number of elements other than 5. The msgpack deserialization of a wrong-length sequence into a fixed-size array of 5 fails, propagating a `ProtocolError` that permanently aborts the honest party's presign. The protocol is explicitly designed to tolerate up to `t` malicious participants, so this breaks the robustness invariant.

### Finding Description

**Sender side** — each honest participant collects 5 polynomial evaluations into a `Vec<SerializableScalar<C>>` and sends it privately: [1](#0-0) 

A malicious participant controls their own protocol instance and can substitute any payload — e.g., a `Vec` with 4 or 6 elements — at the same `wait_round_1` waitpoint.

**Receiver side** — the honest party calls `recv_from_others` with `T` inferred as `Shares` (because `shares.add_shares(&package)` requires `package: Shares`): [2](#0-1) 

`Shares` is a newtype wrapping a fixed-size array of exactly 5 elements: [3](#0-2) 

**Deserialization** — `Comms::recv` calls `rmp_serde::decode::from_slice` to decode the raw bytes into `Shares`. If the sequence length is not exactly 5, serde returns an error: [4](#0-3) 

The error is converted via `From<Box<dyn error::Error + Send + Sync>> for ProtocolError` → `ProtocolError::Other(...)`: [5](#0-4) 

It then propagates through `recv_from_others` via `?`: [6](#0-5) 

And finally out of `do_presign` via `?` at the `recv_from_others` call site, permanently aborting the honest party's presign.

### Impact Explanation

The `robust_ecdsa` presign protocol explicitly requires `N = 2t+1` participants and is documented to tolerate up to `t` malicious parties. A single malicious participant (well within the `t`-malicious budget) can target any honest party and cause their presign to return `Err`, permanently denying that party the ability to produce a presignature and thus a signature. There is no retry or recovery path. [7](#0-6) 

### Likelihood Explanation

The attack requires only one malicious participant in a valid `N = 2t+1` session. The malicious participant simply sends a `Vec` with 4 or 6 elements instead of 5 at `wait_round_1`. No cryptographic assumption needs to be broken. The attack is trivially reproducible in a unit test.

### Recommendation

Validate the length of the received package before or during deserialization. Options include:

1. Deserialize as `Vec<SerializableScalar<C>>` first, then convert to `[T; 5]` with an explicit length check that returns `ProtocolError::MaliciousParticipant(from)` on mismatch — identifying the offending party rather than aborting.
2. Add a pre-deserialization length field to the message and reject messages from the identified sender rather than aborting the entire protocol.

### Proof of Concept

```rust
// Malicious participant sends 4 scalars instead of 5 at wait_round_1
let malformed: Vec<SerializableScalar<C>> = vec![
    SerializableScalar(Scalar::one()),
    SerializableScalar(Scalar::one()),
    SerializableScalar(Scalar::one()),
    SerializableScalar(Scalar::one()),
    // missing 5th element
];
chan.send_private(wait_round_1, honest_party, &malformed)?;
// honest_party's recv_from_others returns Err(ProtocolError::Other("..."))
// do_presign returns Err, presign is permanently aborted for honest_party
```

### Citations

**File:** src/ecdsa/robust_ecdsa/presign.rs (L74-79)
```rust
    // To prevent split-view attacks documented in docs/ecdsa/robust_ecdsa/signing.md
    if participants.len() != robust_ecdsa_threshold {
        return Err(InitializationError::BadParameters(
            "the number of participants during presigning must be exactly 2*max_malicious+1 to avoid split view attacks".to_string(),
        ));
    }
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L120-126)
```rust
        let package = polynomials
            .iter()
            .map(|poly| poly.eval_at_participant(p))
            .collect::<Result<Vec<_>, _>>()?;

        // send the evaluation privately to participant p
        chan.send_private(wait_round_1, p, &package)?;
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L135-139)
```rust
    for (_, package) in recv_from_others(&chan, wait_round_1, &participants, me).await? {
        // Step 2.2
        // calculate the respective sum of the different shares received from each participant
        shares.add_shares(&package);
    }
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L345-346)
```rust
#[derive(serde::Deserialize, serde::Serialize)]
struct Shares([SerializableScalar<C>; 5]);
```

**File:** src/protocol/internal.rs (L338-340)
```rust
        let decoded: Result<T, Box<dyn error::Error + Send + Sync>> =
            rmp_serde::decode::from_slice(message_data).map_err(std::convert::Into::into);
        Ok((from, decoded?))
```

**File:** src/errors.rs (L100-103)
```rust
impl From<Box<dyn error::Error + Send + Sync>> for ProtocolError {
    fn from(err: Box<dyn error::Error + Send + Sync>) -> Self {
        Self::Other(err.to_string())
    }
```

**File:** src/protocol/helpers.rs (L20-20)
```rust
        let (from, msg) = chan.recv(waitpoint).await?;
```
