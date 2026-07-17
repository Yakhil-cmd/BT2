### Title
`DelegateAction` Signed Payload Contains No Chain-Specific Identifier, Enabling Cross-Network Replay by a Malicious Relayer — (`core/primitives/src/action/delegate.rs`)

---

### Summary

`DelegateAction` (NEP-366 meta transactions) signs a payload that contains no chain ID, genesis hash, or any other network-specific field. A malicious relayer who receives a user-signed `DelegateAction` intended for NEAR testnet can replay it verbatim on NEAR mainnet (or any other NEAR network) if the same account exists on both networks with the same key, the mainnet nonce is lower than the delegate nonce, and the mainnet block height is below `max_block_height`. The result is unauthorized execution of the user's actions — including token transfers — on the unintended network.

---

### Finding Description

`DelegateAction::get_nep461_hash()` constructs the signed payload as:

```
SignableMessage { discriminant: NEP_366 (= 366), msg: &DelegateAction }
``` [1](#0-0) 

The `DelegateAction` struct contains:

```rust
pub struct DelegateAction {
    pub sender_id: AccountId,
    pub receiver_id: AccountId,
    pub actions: Vec<NonDelegateAction>,
    pub nonce: Nonce,
    pub max_block_height: BlockHeight,
    pub public_key: PublicKey,
}
``` [2](#0-1) 

The `MessageDiscriminant` is the constant `NEP_366_META_TRANSACTIONS = 366`, identical on every NEAR network: [3](#0-2) [4](#0-3) 

Neither the discriminant nor any field of `DelegateAction` encodes the chain ID, genesis block hash, or network name. The signed blob is therefore identical across all NEAR networks for the same logical action.

At execution time, `validate_delegate_action_key` checks only:
1. Signature validity against the NEP-461 hash (network-agnostic)
2. Nonce strictly greater than the current access-key nonce
3. Nonce below `block_height × ACCESS_KEY_NONCE_RANGE_MULTIPLIER`
4. `max_block_height` not yet exceeded [5](#0-4) 

None of these checks are network-specific. There is no guard that rejects a `DelegateAction` signed on a different NEAR network.

---

### Impact Explanation

A malicious relayer who obtains a user-signed `DelegateAction` (e.g., a `Transfer` or `FunctionCall`) intended for testnet can submit it on mainnet. If the user holds the same account name and key on mainnet, and the mainnet nonce and block height satisfy the two numeric guards, the action executes on mainnet without the user's consent. The user's mainnet balance is debited and the transfer recipient (which may be the attacker's account) receives the funds. The corrupted value is the sender's mainnet `account.amount` and the access-key nonce.

---

### Likelihood Explanation

NEAR account names are human-readable and frequently identical across mainnet and testnet (e.g., `alice.near` / `alice.testnet` share the same key in many wallet setups). Relayers are permissionless — any party can operate one. A user who signs a DelegateAction for a testnet relayer and later deposits funds on mainnet is immediately at risk. The nonce and height conditions are easily satisfiable: the attacker simply waits until the mainnet nonce is below the delegate nonce and the block height is within `max_block_height`.

---

### Recommendation

Include a network-specific binding in the `DelegateAction` signed payload. The canonical approach is to add a `chain_id` or `genesis_block_hash` field to `DelegateAction` (and `DelegateActionV2`) and incorporate it into the NEP-461 hash. Alternatively, the `SignableMessage` discriminant could be extended to encode the genesis hash, making the signing domain disjoint across networks. Any solution must be a protocol change gated behind a new `ProtocolFeature`.

---

### Proof of Concept

1. User `alice.near` exists on both mainnet (nonce = 5, balance = 100 NEAR) and testnet.
2. User signs a `DelegateAction` on testnet: transfer 10 NEAR to `bob.near`, nonce = 6, `max_block_height` = testnet_height + 100.
3. User gives the `SignedDelegateAction` to a relayer.
4. Malicious relayer checks: mainnet nonce for `alice.near` = 5 < 6 ✓; mainnet block height < `max_block_height` ✓.
5. Relayer wraps the unchanged `SignedDelegateAction` in a mainnet `SignedTransaction` (relayer pays gas) and submits it.
6. `validate_delegate_action_key` on mainnet verifies the signature against `get_nep461_hash()` — passes, because the hash is network-agnostic.
7. Nonce and height checks pass. The action executes: 10 NEAR is transferred from `alice.near` to `bob.near` on mainnet without Alice's consent. [1](#0-0) [6](#0-5) [7](#0-6)

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

**File:** core/primitives/src/action/delegate.rs (L353-357)
```rust
    pub fn get_nep461_hash(&self) -> CryptoHash {
        let signable = SignableMessage::new(&self, SignableMessageType::DelegateAction);
        let bytes = borsh::to_vec(&signable).expect("Failed to deserialize");
        hash(&bytes)
    }
```

**File:** core/primitives/src/signable_message.rs (L24-25)
```rust
const NEP_366_META_TRANSACTIONS: u32 = 366;
const NEP_611_GAS_KEYS: u32 = 611;
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

**File:** core/primitives/src/signable_message.rs (L221-223)
```rust
            SignableMessageType::DelegateAction => {
                MessageDiscriminant::new_on_chain(NEP_366_META_TRANSACTIONS).unwrap()
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
