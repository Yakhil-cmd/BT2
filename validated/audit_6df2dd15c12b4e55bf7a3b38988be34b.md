### Title
Meta-transaction (`DelegateAction`/`DelegateActionV2`) signatures omit chain/network identifiers, permitting cross-chain replay - (File: core/primitives/src/action/delegate.rs)

### Summary
NEP-366 meta-transactions let a relayer submit an action on behalf of a user who only produces a `SignedDelegateAction`/`VersionedSignedDelegateAction`. The signed payload is bound only to `sender_id`, `receiver_id`, `actions`, `nonce`/`TransactionNonce`, `max_block_height`, and `public_key` — it contains no chain/genesis identifier. This mirrors the reported bug class: an authentication artifact that encodes "a user's address and a counter" but nothing that scopes it to a specific chain, so it can be replayed on another chain sharing the same account/key state.

### Finding Description
`DelegateAction::get_nep461_hash()` hashes a `SignableMessage` wrapping only the `DelegateAction` fields plus a fixed NEP discriminant: [1](#0-0) [2](#0-1) 

None of these fields, nor the `SignableMessage` discriminant scheme, include a chain ID or genesis hash: [3](#0-2) [4](#0-3) 

Verification (`validate_delegate_action_key` in the runtime) only checks the access key's presence, its current nonce, and `max_block_height` — all of which are chain-local state, not chain identity: [5](#0-4) 

This differs from ordinary `SignedTransaction`s, which are anchored to a recent, chain-specific `block_hash` that expires quickly and cannot be trivially replayed cross-chain. `DelegateAction` deliberately avoids that mechanism (relying on `nonce` + `max_block_height` instead) to let relayers hold transactions without needing a fresh block hash, which is exactly the design trade-off that removes the implicit chain-binding that regular transactions have.

By contrast, nearcore's own ETH-wallet-contract meta-transaction path (`rlp_execute`, NEP for ETH-implicit accounts) explicitly checks `tx.chain_id != Some(CHAIN_ID)` and bans a relayer who violates it: [6](#0-5) 
This shows nearcore is aware of and mitigates exactly this class of bug for the ETH-wallet path, but the native NEP-366/NEP-611 `DelegateAction` signing scheme has no equivalent binding.

### Impact Explanation
If any two chains derived from nearcore (mainnet vs. testnet, mainnet vs. a fork/appchain, or two independent forks of the protocol) ever end up with the same `account_id` + `public_key` + access-key nonce state (e.g., because the second chain was created via a genesis/state export of the first, via `fork-network` tooling, or because a user reuses the same seed phrase to create identically-named accounts on both networks), a `SignedDelegateAction`/`VersionedSignedDelegateAction` signed for use on chain A could be submitted and would validate on chain B, since nothing in the signed bytes ties it to a specific network. This would let a relayer or observer authorize actions (transfers, function calls, access-key changes) on the victim account on the "wrong" chain without the user's consent for that chain. Given the tool explicitly supports `fork-network` for creating chain copies with identical account state, this scenario is realistic rather than purely theoretical.

### Likelihood Explanation
This requires: (1) capturing a valid `SignedDelegateAction` (which, per NEP-366 design, is passed to relayers and is not secret), and (2) the existence of a second nearcore-based chain where the sender's account/access-key/nonce state coincides with the origin chain. Condition (2) is not automatic on arbitrary independent chains, but is trivially satisfied for chains created via state fork/replication (e.g. `tools/fork-network`), or for accounts whose implicit-account derivation from the same key is reused across chains. This is a design gap rather than an active exploit against current mainnet/testnet in isolation, since those two networks do not share account state by default — but the signing scheme provides no defense-in-depth once such state overlap exists, unlike the ETH-wallet-contract path which explicitly checks `chain_id`.

### Recommendation
Include a chain/network-binding value (e.g. `genesis_hash` or a protocol-level `chain_id`) inside the signed payload of `DelegateAction`/`DelegateActionV2` (via `SignableMessage` or a new field), and validate it against the executing chain's own identifier in `validate_delegate_action_key`/`apply_delegate_action`, analogous to the `InvalidChainId` check already implemented in the ETH-wallet contract's `validate_tx_relayer_data`.

### Proof of Concept
Conceptual (protocol-level, not runnable against a single chain in isolation):
1. On chain A, user `alice.near` (public key `pk`) signs a `DelegateAction { sender_id: alice.near, receiver_id: victim_contract, actions: [FunctionCall(...)], nonce: N, max_block_height: H, public_key: pk }` via `SignedDelegateAction::sign`, per `core/primitives/src/action/delegate.rs:92-95`.
2. Chain B is created from chain A's state (e.g. via `tools/fork-network`) or independently ends up with an account `alice.near` holding the same access key `pk` with nonce `< N`.
3. A relayer submits the same `SignedDelegateAction` bytes as an `Action::Delegate` on chain B.
4. `SignedDelegateAction::verify()` (`core/primitives/src/action/delegate.rs:84-90`) succeeds because the signature check has no chain-binding, and `validate_delegate_action_key` (`runtime/runtime/src/actions.rs:535-622`) only checks local nonce/access-key state, so the delegated action executes on chain B even though the user only intended to authorize it on chain A.

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

**File:** core/primitives/src/action/delegate.rs (L344-357)
```rust
impl DelegateAction {
    pub fn get_actions(&self) -> Vec<Action> {
        self.actions.iter().map(|a| a.clone().into()).collect()
    }

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

**File:** core/primitives/src/signable_message.rs (L61-65)
```rust
#[derive(BorshSerialize)]
pub struct SignableMessage<'a, T> {
    pub discriminant: MessageDiscriminant,
    pub msg: &'a T,
}
```

**File:** core/primitives/src/signable_message.rs (L97-108)
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
}
```

**File:** runtime/runtime/src/actions.rs (L535-622)
```rust
fn validate_delegate_action_key(
    state_update: &mut TrieUpdate,
    apply_state: &ApplyState,
    delegate_action: VersionedDelegateActionRef<'_>,
    result: &mut ActionResult,
) -> Result<(), RuntimeError> {
    let sender_id = delegate_action.sender_id();
    let public_key = delegate_action.public_key();
    // 'sender_id' account existence must be checked by a caller
    let mut access_key = match get_access_key(state_update, sender_id, public_key)? {
        Some(access_key) => access_key,
        None => {
            result.result = Err(ActionErrorKind::DelegateActionAccessKeyError(
                InvalidAccessKeyError::AccessKeyNotFound {
                    account_id: sender_id.clone(),
                    public_key: public_key.clone().into(),
                },
            )
            .into());
            return Ok(());
        }
    };

    // A plain nonce advances the single access_key.nonce and forbids gas keys;
    // a gas key nonce advances one of the gas key's nonces selected by
    // nonce_index.
    let delegate_nonce = delegate_action.nonce();
    let (current_nonce, nonce_update) = match delegate_nonce {
        TransactionNonce::Nonce { .. } => {
            if access_key.gas_key_info().is_some() {
                result.result = Err(ActionErrorKind::DelegateActionAccessKeyError(
                    InvalidAccessKeyError::DelegateActionRequiresNonGasKey,
                )
                .into());
                return Ok(());
            }
            (access_key.nonce, DelegateNonceUpdate::AccessKey)
        }
        TransactionNonce::GasKeyNonce { nonce_index, .. } => {
            let Some(gas_key_info) = access_key.gas_key_info() else {
                result.result = Err(ActionErrorKind::DelegateActionAccessKeyError(
                    InvalidAccessKeyError::DelegateActionRequiresGasKey,
                )
                .into());
                return Ok(());
            };
            if nonce_index >= gas_key_info.num_nonces {
                result.result = Err(ActionErrorKind::DelegateActionInvalidNonceIndex {
                    nonce_index,
                    num_nonces: gas_key_info.num_nonces,
                }
                .into());
                return Ok(());
            }
            // The index is range-checked above and gas keys initialize every
            // nonce row at creation, so a missing row is inconsistent state.
            let current_nonce =
                get_gas_key_nonce(state_update, sender_id, public_key, nonce_index)?.ok_or_else(
                    || {
                        StorageError::StorageInconsistentState(format!(
                            "gas key nonce row missing for {} {} at in-range index {nonce_index} (num_nonces {})",
                            sender_id, public_key, gas_key_info.num_nonces,
                        ))
                    },
                )?;
            (current_nonce, DelegateNonceUpdate::GasKey { nonce_index })
        }
    };

    if delegate_nonce.nonce() <= current_nonce {
        result.result = Err(ActionErrorKind::DelegateActionInvalidNonce {
            delegate_nonce: delegate_nonce.nonce(),
            ak_nonce: current_nonce,
        }
        .into());
        return Ok(());
    }

    let upper_bound = apply_state.block_height
        * near_primitives::account::AccessKey::ACCESS_KEY_NONCE_RANGE_MULTIPLIER;
    if delegate_nonce.nonce() >= upper_bound {
        result.result = Err(ActionErrorKind::DelegateActionNonceTooLarge {
            delegate_nonce: delegate_nonce.nonce(),
            upper_bound,
        }
        .into());
        return Ok(());
    }
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/internal.rs (L324-330)
```rust
    if tx.address.raw() != context.current_address {
        return Err(Error::Relayer(RelayerError::InvalidSender));
    }

    if tx.chain_id != Some(CHAIN_ID) {
        return Err(Error::Relayer(RelayerError::InvalidChainId));
    }
```
