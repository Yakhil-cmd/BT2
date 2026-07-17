### Title
`DelegateAction` Signature Lacks Chain-Fork Binding, Enabling Cross-Fork Replay — (File: `core/primitives/src/action/delegate.rs`)

---

### Summary

`DelegateAction` (meta transaction) signatures are computed over a payload that contains no chain-specific context — no `block_hash`, no `chain_id`, only a fixed NEP-number discriminant. Unlike a regular `SignedTransaction`, which includes a `block_hash` that is validated as an ancestor of the current chain head, a `SignedDelegateAction` is bound only to a block-height ceiling (`max_block_height`) and a nonce. In the event of a hard fork where both chains share the same initial state, a `SignedDelegateAction` that was created for one chain is cryptographically valid on the other chain and can be replayed there by any party who observed the off-chain message.

---

### Finding Description

`DelegateAction.get_nep461_hash()` computes the signed digest as:

```
hash( borsh( MessageDiscriminant(NEP_366_constant) ‖ DelegateAction ) )
``` [1](#0-0) 

`MessageDiscriminant` is a fixed `u32` derived from the NEP number (366), not from any chain identifier: [2](#0-1) [3](#0-2) 

The `DelegateAction` payload itself contains `{sender_id, receiver_id, actions, nonce, max_block_height, public_key}`: [4](#0-3) 

None of these fields are chain-specific. `max_block_height` is a block *height*, not a block *hash*; block heights are identical on both sides of a fork.

By contrast, a regular `SignedTransaction` includes a `block_hash` field: [5](#0-4) 

That hash is validated by `check_transaction_validity_period`, which walks the chain to confirm the referenced block is an *ancestor* of the current head — providing fork-specific binding that `DelegateAction` entirely lacks: [6](#0-5) 

`apply_delegate_action` verifies the signature, checks `max_block_height`, and validates the nonce, but performs no chain-ancestry check: [7](#0-6) 

---

### Impact Explanation

At the moment of a hard fork both chains share identical account state (same nonces, same balances). A `SignedDelegateAction` created before the fork is cryptographically valid on both chains simultaneously. Any party who has seen the off-chain message (e.g., a malicious or compromised relayer, or a network observer) can submit it on the unintended fork. The inner actions — token transfers, `AddKey`, `DeployContract`, etc. — execute against the user's account on that fork, advancing the nonce and consuming the user's balance or granting unauthorized key access.

---

### Likelihood Explanation

Exploitation requires a NEAR hard fork where both resulting chains retain the same genesis/account state at the fork point, and an attacker who has observed a `SignedDelegateAction` that has not yet been consumed on the target fork. Hard forks are rare but not impossible; the off-chain transmission of `SignedDelegateAction` to relayers is the normal meta-transaction flow, making interception plausible. Likelihood is **Low**, impact is **High** (token loss, unauthorized key addition).

---

### Recommendation

**Short-term**: Add a chain-specific field to the `DelegateAction` signed payload. The simplest option is a `block_hash` field (mirroring `SignedTransaction`) that is validated as an ancestor of the current chain head inside `apply_delegate_action`. This binds the signature to a specific chain lineage.

**Long-term**: Incorporate the genesis `chain_id` string into the `MessageDiscriminant` or into a wrapper struct serialized before the `DelegateAction` body, so that signatures produced for mainnet, testnet, or any fork are cryptographically disjoint.

---

### Proof of Concept

1. Alice signs a `DelegateAction` with `nonce = N`, `max_block_height = H + 1000`, containing `Action::Transfer { deposit: 100 NEAR }` to Bob. She sends it off-chain to a relayer.
2. NEAR hard-forks at block height `H`, producing chains **A** and **B** with identical account state (Alice's access-key nonce is `N-1` on both).
3. The relayer submits the `SignedDelegateAction` on chain **A**; `apply_delegate_action` verifies the NEP-461 signature, confirms `block_height ≤ max_block_height`, advances Alice's nonce to `N`, and executes the transfer.
4. Eve (who intercepted the off-chain message) submits the identical `SignedDelegateAction` on chain **B** via any willing relayer.
5. On chain **B**, Alice's nonce is still `N-1`; `signed_delegate_action.verify()` passes (the hash is chain-agnostic); `max_block_height` is not exceeded; the nonce check passes. The transfer executes, draining 100 NEAR from Alice's account on chain **B** without her consent. [8](#0-7) [9](#0-8)

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

**File:** core/primitives/src/action/delegate.rs (L83-95)
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
```

**File:** core/primitives/src/action/delegate.rs (L349-357)
```rust
    /// Delegate action hash used for NEP-461 signature scheme which tags
    /// different messages before hashing
    ///
    /// For more details, see: [NEP-461](https://github.com/near/NEPs/pull/461)
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

**File:** core/primitives/src/transaction.rs (L291-296)
```rust
        if !signed_tx
            .signature
            .verify(signed_tx.get_hash().as_ref(), signed_tx.transaction.public_key())
        {
            return Err((InvalidTxError::InvalidSignature, signed_tx));
        }
```

**File:** chain/chain/src/store/utils.rs (L56-75)
```rust
pub fn check_transaction_validity_period(
    chain_store: &ChainStoreAdapter,
    prev_block_header: &BlockHeader,
    base_block_hash: &CryptoHash,
    transaction_validity_period: BlockHeightDelta,
) -> Result<(), InvalidTxError> {
    let base_header =
        chain_store.get_block_header(base_block_hash).map_err(|_| InvalidTxError::Expired)?;

    metrics::CHAIN_VALIDITY_PERIOD_CHECK_DELAY
        .observe(prev_block_header.height().saturating_sub(base_header.height()) as f64);

    // First check the distance between blocks
    if prev_block_header.height() > base_header.height() + transaction_validity_period {
        return Err(InvalidTxError::Expired);
    }

    // Then check if there is a path between the blocks (`base` is an ancestor of `prev`)
    validity_period_validate_is_ancestor(&base_header, prev_block_header, chain_store)
}
```

**File:** runtime/runtime/src/actions.rs (L422-453)
```rust
pub(crate) fn apply_delegate_action(
    state_update: &mut TrieUpdate,
    apply_state: &ApplyState,
    action_receipt: &VersionedActionReceipt,
    sender_id: &AccountId,
    signed_delegate_action: VersionedSignedDelegateActionRef<'_>,
    result: &mut ActionResult,
) -> Result<(), RuntimeError> {
    if !signed_delegate_action.verify() {
        result.result = Err(ActionErrorKind::DelegateActionInvalidSignature.into());
        return Ok(());
    }
    let delegate_action = signed_delegate_action.delegate_action();
    if apply_state.block_height > delegate_action.max_block_height() {
        result.result = Err(ActionErrorKind::DelegateActionExpired.into());
        return Ok(());
    }
    if delegate_action.sender_id().as_str() != sender_id.as_str() {
        result.result = Err(ActionErrorKind::DelegateActionSenderDoesNotMatchTxReceiver {
            sender_id: delegate_action.sender_id().clone(),
            receiver_id: sender_id.clone(),
        }
        .into());
        return Ok(());
    }

    validate_delegate_action_key(state_update, apply_state, delegate_action, result)?;
    if result.result.is_err() {
        // Validation failed. Need to return Ok() because this is not a runtime error.
        // "result.result" will be return to the User as the action execution result.
        return Ok(());
    }
```
