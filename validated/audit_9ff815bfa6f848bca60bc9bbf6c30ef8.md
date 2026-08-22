<title>NEP-366 `DelegateAction` Signatures Lack Chain/Network Binding, Enabling Cross-Chain Replay</title>

### Summary
NEAR's meta-transaction scheme (NEP-366) signs a `DelegateAction` using `SignableMessage`, whose signed payload consists only of a NEP discriminant plus the `DelegateAction` fields (`sender_id`, `receiver_id`, `actions`, `nonce`, `max_block_height`, `public_key`). It contains no chain-identifying data (no `chain_id`, genesis hash, or network identifier), analogous to the `ERC20Permit` report where the signed permit omitted `chainID`. A `SignedDelegateAction` signed by a user for one NEAR network can be replayed verbatim by any relayer on a different NEAR-protocol network (e.g., a forked/derivative chain or another deployment sharing the same account state layout), as long as the target account's on-chain nonce for that key has not yet advanced past the signed value.

### Finding Description
`DelegateAction` is defined without any chain-scoping field: [1](#0-0) 

Verification of the signature is done purely against `get_nep461_hash()`/`SignableMessage`, which only mixes in a NEP discriminant constant, not any chain identifier: [2](#0-1) 

The discriminant only encodes the NEP number (366) to prevent a delegate-action signature from being confused with a different signed-message type; it carries no chain-specific salt: [3](#0-2) 

The unit tests for the NEP-366 scheme confirm the signed payload is limited to `sender_id`, `receiver_id`, `actions`, `nonce`, `max_block_height`, and `public_key` — no chain or genesis identifier is present: [4](#0-3) 

By contrast, regular `Transaction`s include a `block_hash` field that is checked to be a recent block on the actual local chain (`chain_validate` in the runtime), which provides both expiry and same-chain binding for ordinary transactions: [5](#0-4) 

`DelegateAction` deliberately does not use `block_hash`; instead it only has `max_block_height` (an expiry bound) and a `nonce` checked against the signer's on-chain access-key nonce for replay protection within a single chain: [6](#0-5) 

Because `sender_id`/`public_key` pairs (especially NEAR "implicit accounts", whose `AccountId` is deterministically derived from the public key and is therefore identical across any network using the same account model) and access-key nonces can coincide across two networks — for example testnet vs. mainnet, a hard fork, or a private/derivative deployment initialized from the same genesis/state snapshot — a `SignedDelegateAction` that is valid on chain A remains fully valid on chain B: the signature check only depends on the NEP-366 discriminant and the action content, not on which chain it is being submitted to.

### Impact Explanation
An attacker (a relayer, or anyone who obtains a `SignedDelegateAction` — these are explicitly designed to be handed to untrusted relayers before being wrapped in a transaction) can replay a user's meta-transaction on any other NEAR-protocol network where the same account/key/nonce state exists, causing the delegated actions (transfers, function calls, key management, etc.) to execute against the user's account on that other network without renewed authorization. This is an unauthorized state/balance change reachable purely from a submitted signed message and normal `Action::Delegate`/`Action::DelegateV2` transaction processing — no validator or node-privilege is required.

### Likelihood Explanation
Likelihood depends on the existence of a second network where the signer's account/key state coincidentally matches (e.g., testnet/mainnet with the same implicit account and an unused matching nonce, or a chain split/fork event). This is a non-trivial but realistic precondition (mirrored explicitly by the original report's exploit scenario involving a post-deployment hard fork), and is entirely out of the signer's control since nothing in the signed payload lets them scope the authorization to a specific network.

### Recommendation
Short term: include a chain-identifying value (e.g., the genesis hash or a protocol-level `chain_id` equivalent) in the `SignableMessage`/`DelegateAction` payload that is verified during `SignedDelegateAction::verify`/`VersionedSignedDelegateAction::verify`, so a signature is only valid on the intended network.

Long term: as NEP-461 is standardized, ensure all off-chain signable-message schemes (delegate actions, gas-key messages, wallet-contract style relayed transactions) explicitly bind to the network they were signed for, and document this requirement for any future signature scheme added to nearcore.

### Proof of Concept
1. On Network A (e.g., testnet), Alice signs a `DelegateAction { sender_id: alice, receiver_id: bob, actions: [...], nonce: N, max_block_height: H, public_key: pk }` via `SignedDelegateAction::sign` / `VersionedSignedDelegateAction::sign`, per [7](#0-6) , and hands it to a relayer.
2. Assume Network B is a chain sharing the same implicit-account derivation and where Alice's account exists with the same public key and access-key nonce still at `N-1` (e.g., a fork, a mirrored deployment, or coincidental state via `tools/mirror`-style state copy).
3. The relayer wraps the identical `SignedDelegateAction` bytes into an `Action::Delegate`/`Action::DelegateV2` inside a normal `SignedTransaction` submitted to Network B.
4. `VersionedSignedDelegateAction::verify` (or `SignedDelegateAction::verify`) succeeds because the signed hash never encoded which network it targeted, per [8](#0-7) , and the nonce check on Network B passes since its stored nonce is still `N-1`.
5. Alice's delegated actions execute on Network B without her renewed consent, replicating the ERC20Permit-style chain-split replay.

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

**File:** core/primitives/src/action/delegate.rs (L83-96)
```rust
impl SignedDelegateAction {
    pub fn verify(&self) -> bool {
        let delegate_action = &self.delegate_action;
        let hash = delegate_action.get_nep461_hash();
        let public_key = &delegate_action.public_key;

        self.signature.verify(hash.as_ref(), public_key)
    }

    pub fn sign(singer: &Signer, delegate_action: DelegateAction) -> Self {
        let signature = singer.sign(delegate_action.get_nep461_hash().as_bytes());
        Self { delegate_action, signature }
    }
}
```

**File:** core/primitives/src/action/delegate.rs (L210-220)
```rust
impl VersionedSignedDelegateAction {
    pub fn verify(&self) -> bool {
        let hash = self.delegate_action.get_nep461_hash();
        self.signature.verify(hash.as_ref(), self.delegate_action.public_key())
    }

    pub fn sign(signer: &Signer, delegate_action: VersionedDelegateActionPayload) -> Self {
        let signature = signer.sign(delegate_action.get_nep461_hash().as_bytes());
        Self { delegate_action, signature }
    }
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

**File:** core/primitives/src/signable_message.rs (L61-107)
```rust
#[derive(BorshSerialize)]
pub struct SignableMessage<'a, T> {
    pub discriminant: MessageDiscriminant,
    pub msg: &'a T,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum SignableMessageType {
    /// A delegate action, intended for a relayer to included it in an action list of a transaction.
    DelegateAction,
    /// A delegate action with gas key support, intended for a relayer to include it in an action
    /// list of a transaction.
    DelegateActionV2,
}

#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum ReadDiscriminantError {
    #[error("does not fit any known categories")]
    UnknownMessageType,
    #[error("NEP {0} does not have a known on-chain use")]
    UnknownOnChainNep(u32),
    #[error("NEP {0} does not have a known off-chain use")]
    UnknownOffChainNep(u32),
    #[error("discriminant is in the range for transactions")]
    TransactionFound,
}

#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum CreateDiscriminantError {
    #[error("nep number {0} is too big")]
    NepTooLarge(u32),
}

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

**File:** core/primitives/src/signable_message.rs (L286-300)
```rust
    fn delegate_action(
        sender_id: AccountId,
        receiver_id: AccountId,
        public_key: PublicKey,
    ) -> DelegateAction {
        let delegate_action = DelegateAction {
            sender_id,
            receiver_id,
            actions: vec![],
            nonce: 0,
            max_block_height: 1000,
            public_key,
        };
        delegate_action
    }
```

**File:** chain/chain/src/runtime/mod.rs (L1044-1049)
```rust
                // Verifying the transaction is on the same chain and hasn't expired yet.
                if !chain_validate(&validated_tx.to_signed_tx()) {
                    tracing::trace!(target: "runtime", tx=?validated_tx.get_hash(), "discarding transaction that failed chain validation");
                    rejected_invalid_for_chain += 1;
                    continue;
                }
```

**File:** docs/RuntimeSpec/Actions.md (L416-428)
```markdown
- If the `nonce` does match the `public_key` for the `sender_id`

```rust
/// Nonce must be greater sender[public_key].nonce
DelegateActionInvalidNonce
```

- If `nonce` is too large

```rust
/// DelegateAction nonce is larger than the upper bound given by the block height (block_height * 1e6)
DelegateActionNonceTooLarge
```
```
