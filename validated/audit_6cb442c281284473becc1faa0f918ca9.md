The vulnerability is real and concrete. The analysis is complete from the code already retrieved.

**Root cause:** `ckd()` accepts `app_pk: PublicKey` (which is `blstrs::G1Projective`) with no validation that it is a non-identity point. In `compute_signature_share`, line 174 computes:

```rust
let big_c = big_s + app_pk * y.0;
```

If `app_pk = G1Projective::identity()`, then `app_pk * y.0 = identity` (additive identity), so `big_c = big_s = x_i * H(pk || app_id)` — the ElGamal blinding term `y * A` vanishes entirely.

The coordinator then aggregates all participants' `norm_big_c` values and obtains `msk * H(pk || app_id)` directly in `CKDOutput.big_c`, which is exactly the secret `s` the protocol is designed to hide.

---

### Title
Missing Identity-Point Validation on `app_pk` Allows Coordinator to Learn Derived Key in Plaintext — (`src/confidential_key_derivation/protocol.rs`)

### Summary
The `ckd()` public API accepts `app_pk` without checking whether it is the G1 identity (point at infinity). Passing `app_pk = G1Projective::identity()` eliminates the ElGamal blinding, causing the coordinator to receive the confidential derived key `s = msk * H(pk || app_id)` in the clear.

### Finding Description
In `compute_signature_share`, each participant computes:

- `big_s = x_i * H(pk || app_id)` — their key share contribution
- `big_c = big_s + app_pk * y` — ElGamal-blinded contribution [1](#0-0) 

When `app_pk = G1Projective::identity()`, the scalar multiplication `identity * y = identity`, so `big_c = big_s`. After Lagrange normalization and aggregation by the coordinator: [2](#0-1) 

The resulting `norm_big_c = Σ λ_i * x_i * H(pk || app_id) = msk * H(pk || app_id)`, which is the secret `s` itself — no `app_sk` needed to unmask it.

The `ckd()` entry point performs only participant-list checks and has no validation of `app_pk`: [3](#0-2) 

### Impact Explanation
The coordinator directly obtains `s = msk * H(pk || app_id)` from `CKDOutput.big_c` without calling `unmask()`. This is an **unauthorized disclosure of the confidential derived key** — the primary secret the protocol is designed to protect. The security requirement states that no single node should be able to compute `s`: [4](#0-3) 

### Likelihood Explanation
`app_pk` is a caller-supplied argument to a public library function. Any entity that can submit a CKD request (i.e., any TEE app or contract calling `gen_app_private_key`) can supply `app_pk = G1Projective::identity()`. No cryptographic assumption needs to be broken — it is a trivial one-line change to the caller.

### Recommendation
Add an identity-point check at the start of `ckd()` (or inside `compute_signature_share`):

```rust
if app_pk.is_identity().into() {
    return Err(InitializationError::InvalidPublicKey);
}
```

This mirrors the standard practice of rejecting the identity point in ElGamal and ECDH schemes to prevent degenerate-key attacks.

### Proof of Concept
```rust
// All participants call ckd() with app_pk = G1Projective::identity()
let app_pk = G1Projective::identity();
let protocol = ckd(&participants, coordinator, *p, key_pair, app_id.clone(), app_pk, rng).unwrap();
// ...run protocol...
let ckd_output = /* coordinator output */;
// big_c IS msk * H(pk || app_id) — no app_sk needed
let expected = hash_app_id_with_pk(&pk, &app_id) * msk;
assert_eq!(ckd_output.big_c(), expected); // passes
```

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L50-56)
```rust
    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
```

**File:** src/confidential_key_derivation/protocol.rs (L66-101)
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
    // not enough participants
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }

    // kick out duplicates
    let Some(participants) = ParticipantList::new(participants) else {
        return Err(InitializationError::DuplicateParticipants);
    };

    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }

    // ensure the coordinator is a participant
    if !participants.contains(coordinator) {
        return Err(InitializationError::MissingParticipant {
            role: "coordinator",
            participant: coordinator,
        });
    }
```

**File:** src/confidential_key_derivation/protocol.rs (L170-174)
```rust
    // S <- x . H(app_id)
    let big_s = hash_point * private_share.to_scalar();

    // C <- S + y . A
    let big_c = big_s + app_pk * y.0;
```

**File:** docs/confidential_key_derivation/confidential-key-derivation.md (L101-104)
```markdown
- $`s`$ must be deterministic as a function of $`\texttt{app\_id}`$ and only
  known by *app*
- No single node in the *MPC network* should be capable of computing $`s`$. This
avoids key leakage in the case a single TEE is compromised
```
