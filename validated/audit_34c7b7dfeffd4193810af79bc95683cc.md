### Title
Missing Validation of Participant Set Against DKG Output in CKD Protocol - (File: src/confidential_key_derivation/protocol.rs)

### Summary
The `ckd()` function accepts a caller-supplied `participants` list without validating it against the participant set used during the DKG that produced the `key_pair`. Because `KeygenOutput` stores only `private_share` and `public_key` — not the original participant set — there is no mechanism to detect a mismatch. A wrong participant set causes incorrect Lagrange coefficients, corrupting the derived confidential key.

### Finding Description
`ckd()` in `src/confidential_key_derivation/protocol.rs` takes two independent inputs: a `participants: &[Participant]` slice and a `key_pair: KeygenOutput`. [1](#0-0) 

The only checks performed on `participants` are: minimum size ≥ 2, no duplicates, `me` is present, and `coordinator` is present. [2](#0-1) 

No check verifies that `participants` matches the participant set used in the DKG that produced `key_pair`. The `KeygenOutput` struct itself stores only `private_share` and `public_key`, making such a check impossible without external bookkeeping. [3](#0-2) 

Inside `compute_signature_share`, the Lagrange coefficient `lambda_i` is derived entirely from the caller-supplied `participants` list: [4](#0-3) 

The correctness of the CKD output depends on `sum(lambda_i * x_i) = msk`, which holds only when the `participants` list exactly matches the set used during DKG. Any deviation silently produces a wrong derived key.

### Impact Explanation
If a wrong `participants` list is supplied — either by a misconfigured caller or a malicious coordinator who orchestrates the session — the Lagrange interpolation is evaluated over the wrong domain. The coordinator aggregates the resulting shares and produces a `CKDOutput` that honest parties accept as valid but that does not equal `msk · H(pk ‖ app_id)`. The client's `unmask()` call yields a garbage value instead of the confidential derived key. This is a corruption of CKD output causing honest parties to accept an unusable cryptographic output.

**Allowed impact matched**: *High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.*

### Likelihood Explanation
The `ckd()` function is a public library API. Any caller — including a malicious coordinator who controls session setup — can supply an arbitrary `participants` list. There is no runtime binding between `key_pair` and the participant set, so the mismatch is undetectable by the library. Likelihood is **medium-high**: the attack requires only a single incorrect argument at the call site, with no cryptographic capability needed.

### Recommendation
Extend `KeygenOutput` to store the participant set (or a commitment to it, e.g., a sorted hash) used during DKG:

```rust
pub struct KeygenOutput<C: Ciphersuite> {
    pub private_share: SigningShare<C>,
    pub public_key: VerifyingKey<C>,
    pub participants: ParticipantList,   // add this
}
```

In `ckd()`, validate that the caller-supplied `participants` matches `key_pair.participants` before proceeding. Return an `InitializationError` on mismatch. Apply the same pattern to any other protocol entry point (`presign`, `sign`, etc.) that accepts a `participants` list alongside a `KeygenOutput`.

### Proof of Concept
1. Run DKG with participants `{P0, P1, P2}`, threshold 2. Each party obtains a `KeygenOutput` with `private_share = x_i` and `public_key = msk·G2`.
2. Call `ckd()` on each party but supply `participants = {P0, P1}` (omitting `P2`).
3. `compute_signature_share` computes `lambda_i` for the 2-party set instead of the 3-party set used in DKG.
4. The coordinator aggregates: `sum(lambda_i^{wrong} * x_i * H(pk ‖ app_id))` ≠ `msk · H(pk ‖ app_id)`.
5. `ckd_output.unmask(app_sk)` returns a value that is not the expected confidential key. All parties accept this output as the protocol completed without error. [5](#0-4)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L66-74)
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
```

**File:** src/confidential_key_derivation/protocol.rs (L75-101)
```rust
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

**File:** src/confidential_key_derivation/protocol.rs (L148-182)
```rust
fn compute_signature_share(
    participants: &ParticipantList,
    me: Participant,
    key_pair: &KeygenOutput,
    app_id: &AppId,
    app_pk: PublicKey,
    rng: &mut impl CryptoRngCore,
) -> Result<(ElementG1, ElementG1), ProtocolError> {
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

    // Compute  λi := λi(0)
    let lambda_i = participants.lagrange::<BLS12381SHA256>(me)?;
    // Normalize Y and C into  (λi . Y , λi . C)
    let norm_big_y = big_y * lambda_i;
    let norm_big_c = big_c * lambda_i;
    Ok((norm_big_y, norm_big_c))
}
```

**File:** src/lib.rs (L48-55)
```rust
#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq, ZeroizeOnDrop)]
#[serde(bound = "C: Ciphersuite")]
/// Generic type of key pairs
pub struct KeygenOutput<C: Ciphersuite> {
    pub private_share: SigningShare<C>,
    #[zeroize[skip]]
    pub public_key: VerifyingKey<C>,
}
```
