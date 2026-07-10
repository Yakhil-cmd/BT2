Looking at the code carefully to trace the exact attack path.

The attack path is concrete. Let me verify the exact mechanics:

**Sender side** (lines 67–68): `big_y = y*G`, `big_z = y^2*G` [1](#0-0) 

**Sender receives `big_x_i` with no validation beyond deserialization** (line 80): [2](#0-1) 

**Sender computes `y_big_x_i - big_z` and wraps it in `CoefficientCommitment::new()`** (lines 82–95): [3](#0-2) 

**`hash()` calls `.serialize()` on the third argument** (lines 41–44): [4](#0-3) 

---

### Title
Malicious OT Receiver Causes Sender Abort via Identity-Point Serialization Failure — (`src/ecdsa/ot_based_ecdsa/triples/batch_random_ot.rs`)

### Summary
A malicious OT receiver can send `big_x_i = big_y` (the point the sender just broadcast) for any iteration. The sender then computes `y * big_y - big_z = y^2*G - y^2*G = identity`, wraps it in `CoefficientCommitment::new(identity)`, and calls `hash()`, which immediately fails with `ProtocolError::PointSerialization` because the identity point cannot be serialized. The sender aborts, permanently denying triple generation for all honest parties in that session.

### Finding Description
The sender broadcasts `big_y = y*G` to the receiver at the start of the protocol. [5](#0-4) 

The receiver is then expected to send back `big_x_i` values derived from their own random scalars. There is **no validation** that the received `big_x_i` is not equal to `big_y`. Deserialization only rejects the identity point itself — a valid non-identity point like `big_y` passes through freely. [2](#0-1) 

When the attacker sends `big_x_i = big_y`:
- `y_big_x_i = y * (y*G) = y^2*G = big_z`
- `y_big_x_i - big_z = identity`
- `CoefficientCommitment::new(identity)` is constructed (this succeeds — `new()` is just a wrapper)
- `hash()` calls `.serialize()` on it, which fails because the identity point is not serializable in the secp256k1 group

The error propagates via `?` and the sender returns `Err(ProtocolError::PointSerialization)`. [6](#0-5) 

The comment at line 227 of the receiver side acknowledges that "deserialization prevents receiving the identity" for `big_y`, but no analogous protection exists for `big_x_i`. [7](#0-6) 

### Impact Explanation
The impact is **High: Permanent denial of triple generation for honest parties**. Triple generation is the prerequisite for all OT-based ECDSA presigning and signing. A malicious participant who is the OT receiver can abort every triple generation session by sending `big_x_i = big_y` for any one of the `SECURITY_PARAMETER` iterations. The attacker does not need to know `y` — they simply echo back the `big_y` they received. The claimed Critical impact (unauthorized signature creation) does not apply; the error is properly propagated and no malformed OT key is produced.

### Likelihood Explanation
The attack requires no cryptographic knowledge. The attacker only needs to be a participant acting as the OT receiver and to echo back the `big_y` point they received. It is trivially repeatable across every session, making denial effectively permanent as long as the attacker participates.

### Recommendation
Before calling `hash()`, the sender should check that `y_big_x_i != big_z` (equivalently, `big_x_i != big_y`). If the check fails, the sender should abort with a clear error attributing the fault to the receiver, rather than a generic `PointSerialization` error. Alternatively, the sender can check `(y_big_x_i - big_z).is_identity()` and return a dedicated `ProtocolError` that identifies the malicious receiver.

### Proof of Concept
```rust
// Sender has: y (secret), big_y = y*G, big_z = y^2*G
// Attacker (receiver) sends: big_x_i = big_y  (no knowledge of y needed)
let big_x_i_attacker = big_y; // just echo back what sender sent
// Sender computes:
let y_big_x_i = big_x_i_attacker * y; // = y^2*G = big_z
let diff = y_big_x_i - big_z;         // = identity
// hash() will call CoefficientCommitment::new(diff).serialize()
// -> ProtocolError::PointSerialization
// -> sender aborts, triple generation denied
```

### Citations

**File:** src/ecdsa/ot_based_ecdsa/triples/batch_random_ot.rs (L41-44)
```rust
    hasher.update(
        &p.serialize()
            .map_err(|_| ProtocolError::PointSerialization)?,
    );
```

**File:** src/ecdsa/ot_based_ecdsa/triples/batch_random_ot.rs (L67-68)
```rust
    let big_y = ProjectivePoint::GENERATOR * y;
    let big_z = big_y * y;
```

**File:** src/ecdsa/ot_based_ecdsa/triples/batch_random_ot.rs (L72-74)
```rust
    let ser_big_y = CoefficientCommitment::new(big_y);
    let wait0 = chan.next_waitpoint();
    chan.send(wait0, &ser_big_y)?;
```

**File:** src/ecdsa/ot_based_ecdsa/triples/batch_random_ot.rs (L80-80)
```rust
            let ser_big_x_i: CoefficientCommitment = chan.recv(wait0).await?;
```

**File:** src/ecdsa/ot_based_ecdsa/triples/batch_random_ot.rs (L82-95)
```rust
            let y_big_x_i = ser_big_x_i.value() * y;

            let big_k0 = hash(
                i,
                &ser_big_x_i,
                &ser_big_y,
                &CoefficientCommitment::new(y_big_x_i),
            )?;
            let big_k1 = hash(
                i,
                &ser_big_x_i,
                &ser_big_y,
                &CoefficientCommitment::new(y_big_x_i - big_z),
            )?;
```

**File:** src/ecdsa/ot_based_ecdsa/triples/batch_random_ot.rs (L226-228)
```rust
    let wait0 = chan.next_waitpoint();
    // deserialization prevents receiving the identity
    let big_y_verkey: CoefficientCommitment = chan.recv(wait0).await?;
```
