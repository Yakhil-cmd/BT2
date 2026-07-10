### Title
Missing Identity-Point Validation for `app_pk` in CKD Protocol Allows Disclosure of Confidential Derived Secret — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The public `ckd` entry-point accepts the caller-supplied ElGamal public key `app_pk: PublicKey` without checking whether it is the group identity element (`G1Projective::identity()`). When the identity is supplied, the ElGamal masking term collapses to zero, causing every node's ciphertext share `C_i` to equal its raw BLS signature share `S_i = x_i · H(pk, app_id)`. The coordinator then aggregates these into `C = msk · H(pk, app_id)` — the confidential derived secret — and returns it in plaintext inside `CKDOutput`.

---

### Finding Description

Inside `compute_signature_share`, the ElGamal ciphertext component is computed as:

```rust
// C <- S + y . A
let big_c = big_s + app_pk * y.0;
``` [1](#0-0) 

where `big_s = hash_point * private_share.to_scalar()` is the node's BLS signature share. [2](#0-1) 

If `app_pk = G1Projective::identity()`, then `app_pk * y.0 = identity`, so `big_c = big_s`. The masking term vanishes entirely.

The coordinator then aggregates every participant's `big_c`:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [3](#0-2) 

yielding `C =

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L50-55)
```rust
    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
```

**File:** src/confidential_key_derivation/protocol.rs (L170-171)
```rust
    // S <- x . H(app_id)
    let big_s = hash_point * private_share.to_scalar();
```

**File:** src/confidential_key_derivation/protocol.rs (L173-174)
```rust
    // C <- S + y . A
    let big_c = big_s + app_pk * y.0;
```
