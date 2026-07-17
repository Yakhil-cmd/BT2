### Title
`DelegateAction` Signed Digest Lacks Chain Identity — Cross-Chain Replay of Meta Transactions - (File: `core/primitives/src/action/delegate.rs`)

### Summary

`DelegateAction` (NEP-366) and `DelegateActionV2` (NEP-611) compute their signed digest without committing to any chain-specific context. An attacker who obtains a valid `SignedDelegateAction` from one NEAR chain can wrap it in a fresh relayer transaction on a different NEAR chain and have the inner actions execute without the original signer's intent.

### Finding Description

`DelegateAction::get_nep461_hash()` constructs the signed payload as:

```
SHA256( discriminant_le_u32 || borsh(delegate_action) )
```

where `discriminant` is the compile-time constant `(1 << 30) + 366` and `delegate_action` contains `sender_id`, `receiver_id`, `actions`, `nonce`, `max_block_height`, `public_key`. [1](#0-0) 

No chain identifier is folded into the digest. The `SignableMessage` wrapper adds only a NEP-number discriminant, not a chain ID. [2](#0-1) 

`VersionedDelegateActionPayload::get_nep461_hash()` for `DelegateActionV2` has the identical structure, substituting discriminant `(1 << 30) + 611`. [3](#0-2) 

`apply_delegate_action` verifies the signature, checks `max_block_height` (a plain integer), and validates the nonce — but never checks chain identity: [4](#0-3) 

`ApplyState`, the runtime context passed to `apply_delegate_action`, carries `block_height`, `prev_block_hash`, `epoch_id`, etc., but **no `chain_id` field**: [5](#0-4) 

**Contrast with regular transactions.** `TransactionV0` and `TransactionV1` include a `block_hash` field in the signed body: [6](#0-5) 

The runtime enforces that this `block_hash` refers to a block within `transaction_validity_period` of the current chain, which implicitly binds the signature to a specific chain's block history. `DelegateAction` has no equivalent binding — only `max_block_height`, a bare integer that is identical across all NEAR chains at the same height.

### Impact Explanation

An attacker who intercepts a `SignedDelegateAction` from chain A (e.g., testnet) constructs a fresh outer `Transaction` on chain B (e.g., mainnet) with a valid `block_hash` for chain B, embedding the original `SignedDelegateAction` unchanged. Because the inner digest is chain-agnostic, `SignedDelegateAction::verify()` passes on chain B. If the signer's account and key exist on chain B with a lower nonce and the `max_block_height` is still valid, the inner actions — which may include `Transfer`, `FunctionCall`, `AddKey`, `DeleteKey`, or `DeleteAccount` — execute on chain B without the signer's authorization. The signer's nonce on chain B is consumed, and any token transfers or state mutations take effect. [7](#0-6) 

### Likelihood Explanation

Developers routinely use the same account names and key pairs on both mainnet and testnet. A `DelegateAction` signed on testnet for testing purposes (e.g., an FT transfer) can be replayed on mainnet if the account and key exist there and the nonce on mainnet is lower than the testnet nonce. The `max_block_height` is typically set to `current_height + 100` or more, giving an attacker a window of several minutes to hours. The attacker only needs to observe the off-chain relayer channel (or any public mempool/indexer that logs `SignedDelegateAction` payloads) to obtain the signed payload.

### Recommendation

Introduce chain identity into the `DelegateAction` signed digest. The minimal fix is to add `chain_id` to `DelegateAction` and `DelegateActionV2` as a signed field, or to fold the chain ID into the `SignableMessage` discriminant/prefix before hashing. A protocol-version-gated migration can require the new field for all `DelegateAction` submissions once the feature is enabled, analogous to how `TransactionV1` was introduced alongside `TransactionV0`.

Alternatively, add a `block_hash` field to `DelegateAction` (mirroring regular transactions) and enforce that it refers to a recent block on the executing chain, providing the same implicit chain binding that regular transactions already have.

### Proof of Concept

1. Alice signs a `DelegateAction` on testnet: `sender_id = "alice.near"`, `receiver_id = "ft.near"`, `actions = [FunctionCall("ft_transfer", ...)]`, `nonce = 5`, `max_block_height = 200000000`.
2. The `SignedDelegateAction` is transmitted off-chain to a testnet relayer. An attacker observes it.
3. Attacker constructs a mainnet `Transaction` with `receiver_id = "alice.near"`, `block_hash = <recent mainnet block hash>`, `actions = [Action::Delegate(signed_delegate_action_from_testnet)]`, signed by the attacker as relayer.
4. On mainnet, `apply_delegate_action` calls `signed_delegate_action.verify()`:
   - Recomputes `hash((1<<30)+366 || borsh(delegate_action))` — identical to testnet because no chain ID is included.
   - Signature check passes.
5. `apply_state.block_height (e.g. 150000000) < max_block_height (200000000)` — expiry check passes.
6. `validate_delegate_action_key` finds Alice's key on mainnet with nonce 3 < 5 — nonce check passes.
7. `ft_transfer` executes on mainnet's `ft.near` contract, draining Alice's mainnet FT balance without her consent. [8](#0-7) [9](#0-8)

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

**File:** core/primitives/src/action/delegate.rs (L180-184)
```rust
    pub fn get_nep461_hash(&self) -> CryptoHash {
        let signable = SignableMessage::new(&self, SignableMessageType::DelegateActionV2);
        let bytes = borsh::to_vec(&signable).expect("failed to serialize");
        hash(&bytes)
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

**File:** runtime/runtime/src/lib.rs (L163-217)
```rust
#[derive(Debug)]
pub struct ApplyState {
    /// Points to a phase of the chain lifecycle that we want to run apply for.
    pub apply_reason: ApplyChunkReason,
    /// Currently building block height.
    pub block_height: BlockHeight,
    /// Prev block hash
    pub prev_block_hash: CryptoHash,
    /// To which shard the applied chunk belongs.
    pub shard_id: ShardId,
    /// Current epoch id
    pub epoch_id: EpochId,
    /// Current epoch height
    pub epoch_height: EpochHeight,
    /// Price for the gas.
    pub gas_price: Balance,
    /// The current block timestamp (number of non-leap-nanoseconds since January 1, 1970 0:00:00 UTC).
    pub block_timestamp: u64,
    /// Gas limit for a given chunk.
    /// If None is given, assumes there is no gas limit.
    pub gas_limit: Option<Gas>,
    /// Current random seed (from current block vrf output).
    pub random_seed: CryptoHash,
    /// Current Protocol version when we apply the state transition
    pub current_protocol_version: ProtocolVersion,
    /// The Runtime config to use for the current transition.
    pub config: Arc<RuntimeConfig>,
    /// If `Some`, the next epoch's `wasm_config` differs from the current one
    /// in ways that would invalidate the compiled-contract cache (e.g., a VM-kind
    /// upgrade is scheduled for the next epoch boundary). Hooks throughout the
    /// runtime use this to pre-warm the cache for the upcoming VM, so the boundary
    /// doesn't trigger a re-compile avalanche. `None` in steady state.
    pub next_wasm_config: Option<Arc<VmConfig>>,
    /// Cache for compiled contracts.
    pub cache: Option<Box<dyn ContractRuntimeCache>>,
    /// Cache for trie node accesses.
    pub trie_access_tracker_state: Arc<ext::AccountingState>,
    /// Whether the chunk being applied is new.
    pub is_new_chunk: bool,
    /// Whether to record receipt-to-transaction origin mappings.
    pub save_receipt_to_tx: bool,
    /// Congestion level on each shard based on the latest known chunk header of each shard.
    ///
    /// The map must be empty if congestion control is disabled in the previous
    /// chunk. If the next chunks is the first with congestion control enabled,
    /// the congestion info needs to be computed while applying receipts.
    /// TODO(congestion_info) - verify performance of initialization when congested
    pub congestion_info: BlockCongestionInfo,
    /// Bandwidth requests from all shards, generated at the previous height.
    /// Each shard requests some bandwidth to other shards and then the bandwidth scheduler
    /// decides how much each shard is allowed to send.
    pub bandwidth_requests: BlockBandwidthRequests,
    /// Callback to be called when the post-state is ready.
    pub on_post_state_ready: Option<PostStateReadyCallback>,
}
```

**File:** core/primitives/src/transaction.rs (L33-48)
```rust
pub struct TransactionV0 {
    /// An account on which behalf transaction is signed
    pub signer_id: AccountId,
    /// A public key of the access key which was used to sign an account.
    /// Access key holds permissions for calling certain kinds of actions.
    pub public_key: PublicKey,
    /// Nonce is used to determine order of transaction in the pool.
    /// It increments for a combination of `signer_id` and `public_key`
    pub nonce: Nonce,
    /// Receiver account for this transaction
    pub receiver_id: AccountId,
    /// The hash of the block in the blockchain on top of which the given transaction is valid
    pub block_hash: CryptoHash,
    /// A list of actions to be applied
    pub actions: Vec<Action>,
}
```
