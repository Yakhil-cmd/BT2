### Title
DelegateAction Signed Payload Lacks Chain Binding, Enabling Cross-Fork Signature Replay — (`core/primitives/src/action/delegate.rs`, `core/primitives/src/signable_message.rs`)

---

### Summary

`DelegateAction` (NEP-366 meta transactions) is signed by the user with no chain-specific identifier in the payload. The `SignableMessage` wrapper adds only a fixed NEP-number discriminant (`366`), which is identical on every NEAR network. Unlike regular `Transaction` objects — which include a `block_hash` that binds them to a specific chain — a `DelegateAction` is bound only by `max_block_height` (a block number, not a chain-specific hash). Any party who obtains a signed `DelegateAction` can replay it on a fork or on a different NEAR network (e.g., testnet) where the same account exists with a valid nonce.

---

### Finding Description

**Regular transactions** include a `block_hash` field in the signed body:

```rust
// core/primitives/src/transaction.rs (TransactionV0)
pub block_hash: CryptoHash,
```

This hash is checked at chunk-production time via `chain_validate`, which verifies the transaction is on the same chain and has not expired. [1](#0-0) 

**`DelegateAction`** has no equivalent field:

```rust
pub struct DelegateAction {
    pub sender_id: AccountId,
    pub receiver_id: AccountId,
    pub actions: Vec<NonDelegateAction>,
    pub nonce: Nonce,
    pub max_block_height: BlockHeight,   // block number, not a chain-specific hash
    pub public_key: PublicKey,
}
``` [2](#0-1) 

The user signs the `DelegateAction` via `get_nep461_hash`, which wraps it in a `SignableMessage` whose only distinguishing prefix is the constant `NEP_366_META_TRANSACTIONS = 366`:

```rust
pub fn get_nep461_hash(&self) -> CryptoHash {
    let signable = SignableMessage::new(&self, SignableMessageType::DelegateAction);
    let bytes = borsh::to_vec(&signable).expect("Failed to deserialize");
    hash(&bytes)
}
``` [3](#0-2) 

The `MessageDiscriminant` is computed as `MIN_ON_CHAIN_DISCRIMINANT + 366` — a compile-time constant, identical on mainnet, testnet, and any fork: [4](#0-3) [5](#0-4) 

The `SignableMessage` struct itself contains no chain ID, genesis hash, or any other network-specific field: [6](#0-5) 

---

### Impact Explanation

After a NEAR chain fork (or when the same account with the same keypair exists on mainnet and testnet), a `SignedDelegateAction` produced by a user is cryptographically valid on every NEAR network simultaneously. Any party who has seen the signed payload — including the relayer, an on-chain observer after the first submission, or a network-level eavesdropper — can submit it on the parallel chain. The inner actions (token transfers, key additions, contract calls) execute on the second chain, consuming the user's nonce and draining funds or mutating state without the user's intent.

The outer `Transaction` wrapping the `DelegateAction` is chain-bound (via its own `block_hash`), but that binding covers only the **relayer's** signature. The **user's** `DelegateAction` signature is the one that authorizes the sensitive inner actions, and it carries no chain binding.

---

### Likelihood Explanation

Exploitation requires either (a) a contentious NEAR protocol fork where both chains continue with the same account state, or (b) a user who has the same account ID, keypair, and a valid nonce on both mainnet and testnet. Scenario (b) is uncommon but not impossible for developers or power users. Scenario (a) is low-probability but non-zero, and the protocol provides no defense against it for meta transactions. The nonce prevents replay on the **same** chain but offers no protection across chains.

---

### Recommendation

Include a chain-specific binding in the `DelegateAction` signed payload. Two options:

1. **Add a `block_hash` field** to `DelegateAction` (mirroring regular transactions). The runtime already validates `max_block_height`; adding a `block_hash` check analogous to `chain_validate` would close the gap.
2. **Add a `chain_id` or genesis hash field** to `DelegateAction` and verify it against the node's known genesis hash during `apply_delegate_action`.

Either change is a protocol-level modification requiring a protocol version bump and a new `DelegateAction` variant (e.g., `DelegateActionV3`).

---

### Proof of Concept

1. Alice signs a `DelegateAction` on NEAR mainnet to transfer 100 NEAR to Eve, with `nonce = N` and `max_block_height = H`.
2. Alice sends the `SignedDelegateAction` off-chain to a relayer.
3. The relayer submits it on mainnet inside a `Transaction` with a mainnet `block_hash`. It executes; Alice's nonce advances to `N+1` on mainnet.
4. A fork occurs at block `F < H`. Both chains share Alice's account state at block `F`, so Alice's nonce on the fork is still `N`.
5. Any observer who saw the `SignedDelegateAction` (e.g., from the mempool or on-chain data) wraps it in a new `Transaction` with a fork-chain `block_hash` and submits it on the fork.
6. `apply_delegate_action` verifies the user's signature (valid — no chain binding), checks `nonce == N` (valid — fork state), checks `block_height <= max_block_height` (valid). The transfer executes again on the fork, draining Alice's funds a second time. [2](#0-1) [7](#0-6)

### Citations

**File:** chain/chain/src/runtime/mod.rs (L1044-1049)
```rust
                // Verifying the transaction is on the same chain and hasn't expired yet.
                if !chain_validate(&validated_tx.to_signed_tx()) {
                    tracing::trace!(target: "runtime", tx=?validated_tx.get_hash(), "discarding transaction that failed chain validation");
                    rejected_invalid_for_chain += 1;
                    continue;
                }
```

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

**File:** core/primitives/src/signable_message.rs (L61-108)
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
}
```

**File:** core/primitives/src/signable_message.rs (L217-228)
```rust
impl From<SignableMessageType> for MessageDiscriminant {
    fn from(ty: SignableMessageType) -> Self {
        // unwrapping here is ok, we know the constant NEP numbers used are in range
        match ty {
            SignableMessageType::DelegateAction => {
                MessageDiscriminant::new_on_chain(NEP_366_META_TRANSACTIONS).unwrap()
            }
            SignableMessageType::DelegateActionV2 => {
                MessageDiscriminant::new_on_chain(NEP_611_GAS_KEYS).unwrap()
            }
        }
    }
```
