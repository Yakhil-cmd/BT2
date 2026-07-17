### Title
`DelegateAction` Signed Payload Lacks Chain/Network Identifier, Enabling Cross-Network Signature Replay — (`core/primitives/src/action/delegate.rs`, `core/primitives/src/signable_message.rs`)

---

### Summary

`DelegateAction` (meta-transaction) signatures in nearcore do not bind to any chain or network identifier. A malicious relayer who receives a user's `SignedDelegateAction` intended for testnet can replay it verbatim on mainnet (or any other NEAR network), executing the inner actions against the user's mainnet account without their consent.

---

### Finding Description

`DelegateAction` is the signed inner payload of a meta-transaction (NEP-366). The user signs it and hands it to a relayer, who wraps it in an outer `SignedTransaction` and submits it.

The struct contains no chain or network identifier: [1](#0-0) 

The hash that the user actually signs is produced by `get_nep461_hash()`: [2](#0-1) 

This calls `SignableMessage::new` with `SignableMessageType::DelegateAction`, which prepends a fixed 4-byte discriminant (`MIN_ON_CHAIN_DISCRIMINANT + 366 = 0x4000016E`) to the borsh-serialized `DelegateAction`: [3](#0-2) 

The discriminant is a compile-time constant, identical on every NEAR network (mainnet, testnet, betanet, any private chain): [4](#0-3) 

There is no `chain_id`, `genesis_hash`, or any other network-scoping field anywhere in the signed payload — confirmed by the absence of any such field in `DelegateAction`, `DelegateActionV2`, `VersionedDelegateActionPayload`, or `SignableMessage`. [5](#0-4) [6](#0-5) 

The outer `SignedTransaction` does include a `block_hash` that is chain-specific, but that is signed by the **relayer**, not by the user. The user's signature covers only the `DelegateAction` payload, which is network-agnostic.

---

### Impact Explanation

**Authorization invariant broken.** A user's `SignedDelegateAction` is intended to authorize a specific set of actions on a specific network. Without a chain identifier in the signed payload, the signature is valid on every NEAR network simultaneously.

**Exact corrupted value:** The user's mainnet account balance and state are modified by actions the user only authorized for testnet (or vice versa). For example, a `Transfer` action drains mainnet NEAR; a `FunctionCall` executes a contract call the user never intended on mainnet; an `AddKey` or `DeleteKey` modifies the user's mainnet access-key set.

**Scope:** Authorization (the user's signature is accepted as authorization for an action on a network they never consented to).

---

### Likelihood Explanation

The attack requires:
1. A malicious relayer — any account can act as a relayer; the relayer is not a validator, block producer, or node admin.
2. The user has the same account ID and the same key pair registered on both networks — extremely common practice (testnet mirrors mainnet accounts for development).
3. The nonce in the `DelegateAction` is greater than the current nonce of the user's access key on the target network — likely when a user is more active on one network than the other.

All three conditions are routinely satisfied in production. The relayer receives the signed payload directly from the user as part of the normal meta-transaction flow, so no interception is required — a malicious relayer service already has everything it needs.

---

### Recommendation

Add a `chain_id` (or equivalent network-scoping field, such as the genesis block hash) to the signed payload of `DelegateAction` and `DelegateActionV2`. This field must be included in the borsh-serialized bytes that are hashed and signed, and must be validated against the executing chain's identity during `apply_delegate_action`. This is the direct analog of adding `MarketplaceAddress` to the `Credit` struct in the external report.

The `SignableMessage` / `MessageDiscriminant` scheme in `signable_message.rs` is the natural place to introduce this: the discriminant could be extended to encode a network-specific genesis hash, or a separate `chain_id` field could be added to `SignableMessage`.

---

### Proof of Concept

1. Alice has account `alice.near` on both mainnet and testnet, with the same ED25519 key pair. Her mainnet access-key nonce is 4; her testnet nonce is 4 as well.
2. Alice constructs a `DelegateAction` on testnet: `sender_id = alice.near`, `receiver_id = bob.near`, `actions = [Transfer(100 NEAR)]`, `nonce = 5`, `max_block_height = testnet_height + 1000`, `public_key = alice_pubkey`.
3. Alice calls `get_nep461_hash()` and signs the result, producing `sig`. She sends `(DelegateAction, sig)` to a relayer service.
4. The malicious relayer ignores testnet. Instead it constructs a mainnet `SignedTransaction` with `receiver_id = alice.near` and `actions = [Delegate(SignedDelegateAction { delegate_action, signature: sig })]`, signs the outer transaction with its own mainnet key, and broadcasts it to mainnet.
5. The mainnet runtime calls `SignedDelegateAction::verify()`: [7](#0-6) 

   `get_nep461_hash()` recomputes the same hash (the discriminant and all fields are identical on mainnet), `sig` verifies, and the transfer of 100 mainnet NEAR from Alice to Bob executes — an action Alice never authorized on mainnet.

### Citations

**File:** core/primitives/src/action/delegate.rs (L46-64)
```rust
pub struct DelegateAction {
    /// Signer of the delegated actions
    pub sender_id: AccountId,
    /// Receiver of the delegated actions.
    pub receiver_id: AccountId,
    /// List of actions to be executed.
    ///
    /// With the meta transactions MVP defined in NEP-366, nested
    /// DelegateActions are not allowed. A separate type is used to enforce it.
    pub actions: Vec<NonDelegateAction>,
    /// Nonce to ensure that the same delegate action is not sent twice by a
    /// relayer and should match for given account's `public_key`.
    /// After this action is processed it will increment.
    pub nonce: Nonce,
    /// The maximal height of the block in the blockchain below which the given DelegateAction is valid.
    pub max_block_height: BlockHeight,
    /// Public key used to sign this delegated action.
    pub public_key: PublicKey,
}
```

**File:** core/primitives/src/action/delegate.rs (L83-90)
```rust
impl SignedDelegateAction {
    pub fn verify(&self) -> bool {
        let delegate_action = &self.delegate_action;
        let hash = delegate_action.get_nep461_hash();
        let public_key = &delegate_action.public_key;

        self.signature.verify(hash.as_ref(), public_key)
    }
```

**File:** core/primitives/src/action/delegate.rs (L119-133)
```rust
pub struct DelegateActionV2 {
    /// Signer of the delegated actions
    pub sender_id: AccountId,
    /// Receiver of the delegated actions.
    pub receiver_id: AccountId,
    /// List of actions to be executed.
    pub actions: Vec<NonDelegateAction>,
    /// Nonce of the signing key, advanced when this action is processed. For
    /// a gas key it also selects which of the parallel nonces to advance.
    pub nonce: TransactionNonce,
    /// The maximal height of the block in the blockchain below which the given DelegateActionV2 is valid.
    pub max_block_height: BlockHeight,
    /// Public key used to sign this delegated action.
    pub public_key: PublicKey,
}
```

**File:** core/primitives/src/action/delegate.rs (L159-184)
```rust
pub enum VersionedDelegateActionPayload {
    V2(DelegateActionV2) = 0,
}

impl VersionedDelegateActionPayload {
    pub fn public_key(&self) -> &PublicKey {
        match self {
            VersionedDelegateActionPayload::V2(delegate_action) => &delegate_action.public_key,
        }
    }

    pub fn get_actions(&self) -> Vec<Action> {
        match self {
            VersionedDelegateActionPayload::V2(delegate_action) => delegate_action.get_actions(),
        }
    }

    /// Delegate action hash used for NEP-461 signature scheme which tags
    /// different messages before hashing
    ///
    /// For more details, see: [NEP-461](https://github.com/near/NEPs/pull/461)
    pub fn get_nep461_hash(&self) -> CryptoHash {
        let signable = SignableMessage::new(&self, SignableMessageType::DelegateActionV2);
        let bytes = borsh::to_vec(&signable).expect("failed to serialize");
        hash(&bytes)
    }
```

**File:** core/primitives/src/action/delegate.rs (L353-357)
```rust
    pub fn get_nep461_hash(&self) -> CryptoHash {
        let signable = SignableMessage::new(&self, SignableMessageType::DelegateAction);
        let bytes = borsh::to_vec(&signable).expect("Failed to deserialize");
        hash(&bytes)
    }
```

**File:** core/primitives/src/signable_message.rs (L18-25)
```rust
const MIN_ON_CHAIN_DISCRIMINANT: u32 = 1 << 30;
const MAX_ON_CHAIN_DISCRIMINANT: u32 = (1 << 31) - 1;
const MIN_OFF_CHAIN_DISCRIMINANT: u32 = 1 << 31;
const MAX_OFF_CHAIN_DISCRIMINANT: u32 = u32::MAX;

// NEPs currently included in the scheme
const NEP_366_META_TRANSACTIONS: u32 = 366;
const NEP_611_GAS_KEYS: u32 = 611;
```

**File:** core/primitives/src/signable_message.rs (L97-107)
```rust
impl<'a, T: BorshSerialize> SignableMessage<'a, T> {
    pub fn new(msg: &'a T, ty: SignableMessageType) -> Self {
        let discriminant = ty.into();
        Self { discriminant, msg }
    }

    pub fn sign(&self, signer: &Signer) -> Signature {
        let bytes = borsh::to_vec(&self).expect("Failed to deserialize");
        let hash = hash(&bytes);
        signer.sign(hash.as_bytes())
    }
```
