### Title
Missing Private Share Consistency Check in CKD Allows Malicious Participant to Corrupt Derived Key Output — (`src/confidential_key_derivation/protocol.rs`)

### Summary

The `ckd()` protocol accepts a caller-supplied `KeygenOutput` and uses `private_share` directly in `compute_signature_share()` with no verification that it corresponds to the committed `public_key`. A malicious participant can pass `private_share = -x_i` (the negation of their actual DKG share) while supplying the correct aggregate `public_key`, causing the coordinator to aggregate a corrupted `CKDOutput` whose `unmask()` result is permanently wrong.

---

### Finding Description

`KeygenOutput<C>` is a plain public struct with public fields: [1](#0-0) 

A caller can freely construct any `KeygenOutput` with arbitrary `private_share`. Inside `compute_signature_share`, the share is consumed without any consistency check: [2](#0-1) 

Specifically:
- Line 157: `private_share` is taken verbatim from `key_pair`
- Line 168: `hash_point = H(pk || app_id)` uses the (correct) aggregate `public_key`
- Line 171: `big_s = hash_point * private_share` — if `private_share = -x_i`, this becomes `-x_i * H(pk||app_id)`
- Line 174: `big_c = big_s + app_pk * y`

There is **no zero-knowledge proof, no Pedersen commitment check, and no other mechanism** to verify that `private_share` is the participant's actual DKG share.

The coordinator aggregates blindly: [3](#0-2) 

No verification is performed on the received `(norm_big_y, norm_big_c)` pairs before summing.

---

### Impact Explanation

With participant `i` using `-x_i`:

```
Aggregated big_C = (msk - 2·λ_i·x_i)·H(pk||app_id) + a·Y
```

After `unmask(app_sk)` (i.e., `big_c - a·big_y`):

```
result = (msk - 2·λ_i·x_i)·H(pk||app_id)  ≠  msk·H(pk||app_id)
``` [4](#0-3) 

The coordinator and all honest parties silently accept a `CKDOutput` that produces the wrong derived key. The corruption is undetectable because there is no output verification step. This matches the **High** impact: *Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.*

---

### Likelihood Explanation

Any single participant in the CKD protocol can trigger this. The attack requires only constructing a `KeygenOutput` with a negated scalar — a trivial local operation on a public struct. No cryptographic assumption needs to be broken. The malicious participant does not need to be the coordinator.

---

### Recommendation

Add a zero-knowledge proof of knowledge (e.g., a Schnorr PoK) that the participant's `big_s` contribution is consistent with their individual public key commitment from DKG. Specifically:

1. During DKG, store each participant's individual public commitment `X_i = x_i · G2` alongside the aggregate key.
2. In `compute_signature_share`, require the participant to prove knowledge of `x_i` such that `big_s = x_i · H(pk||app_id)` is consistent with `X_i`.
3. The coordinator must verify each participant's proof before accepting their `(norm_big_y, norm_big_c)` contribution.

---

### Proof of Concept

```rust
// Malicious participant uses negated private share
let malicious_key_pair = KeygenOutput {
    public_key: honest_key_pair.public_key,  // correct aggregate pk
    private_share: SigningShare::new(-honest_key_pair.private_share.to_scalar()), // negated
};

// Run ckd() with malicious_key_pair for participant i, honest key_pairs for others
// ...

let derived = ckd_output.unmask(app_sk);
let expected = hash_app_id_with_pk(&pk, &app_id) * msk;

assert_ne!(derived, expected); // corruption confirmed — no error is raised
```

The existing test in `protocol.rs` (`test_ckd`) already constructs `KeygenOutput` manually with arbitrary scalars, confirming the struct is freely constructable and the protocol performs no share-consistency validation. [5](#0-4)

### Citations

**File:** src/lib.rs (L51-55)
```rust
pub struct KeygenOutput<C: Ciphersuite> {
    pub private_share: SigningShare<C>,
    #[zeroize[skip]]
    pub public_key: VerifyingKey<C>,
}
```

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

**File:** src/confidential_key_derivation/protocol.rs (L156-174)
```rust
    // Ensures the value is zeroized on drop
    let private_share = Zeroizing::new(key_pair.private_share);

    // y <- ZZq* , Y <- y * G
    let y = Scalar::random(rng);

    // Ensures the value is zeroized on drop
    let y = Zeroizing::new(super::scalar_wrapper::ScalarWrapper(y));

    let big_y = ElementG1::generator() * y.0;

    // H(pk || app_id) when H is a random oracle
    let hash_point = hash_app_id_with_pk(&key_pair.public_key, app_id);

    // S <- x . H(app_id)
    let big_s = hash_point * private_share.to_scalar();

    // C <- S + y . A
    let big_c = big_s + app_pk * y.0;
```

**File:** src/confidential_key_derivation/protocol.rs (L246-265)
```rust
        for (i, p) in participants.iter().enumerate() {
            let rng_p = MockCryptoRng::seed_from_u64(rng.next_u64());
            let key_pair = KeygenOutput {
                public_key: pk,
                private_share: private_shares[i],
            };

            let protocol = ckd(
                &participants,
                coordinator,
                *p,
                key_pair,
                app_id.clone(),
                app_pk,
                rng_p,
            )
            .unwrap();

            protocols.push((*p, Box::new(protocol)));
        }
```

**File:** src/confidential_key_derivation/mod.rs (L54-56)
```rust
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```
