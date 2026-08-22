### Title
Front-runnable `DelegateAction` nonce invalidation causes relayer-submitted meta-transactions to revert - ([File: runtime/runtime/src/actions.rs])

### Summary
The `Permit2` bug class described in the external report (an off-chain, pre-signed authorization whose consumable nonce can be invalidated by anyone who observes it before the intended party submits it) has a structural analog in nearcore's NEP-366 meta-transaction (`DelegateAction`) flow. A `SignedDelegateAction` is signed off-chain by a `sender_id` and then wrapped into a transaction and submitted on-chain by an arbitrary relayer, exactly like a `Permit2.permit` signature is handed to a spender/relayer for later submission.

### Finding Description
A `DelegateAction` is signed by the sender off-chain and forwarded to a relayer, who wraps it in a `Transaction` and pays gas/fees on the sender's behalf [1](#0-0) . On-chain validation of the delegate action is performed by `apply_delegate_action`, which checks the signature, expiry, and sender match, and then calls `validate_delegate_action_key` to validate and advance the nonce tied to the sender's own access key (or gas key) [2](#0-1) . The nonce validation/advance logic itself lives in `validate_delegate_action_key`, which reads the current nonce from the sender's access key (or gas-key nonce row) and compares it against `delegate_action.nonce()` [3](#0-2) .

Critically, nothing in this validation binds the `DelegateAction` to a specific relayer/outer transaction signer — only `sender_id`, `receiver_id`, signature, `max_block_height`, and nonce are checked. This means any party who obtains a copy of a valid, not-yet-included `SignedDelegateAction` (e.g., observed via a relayer's public submission channel, mempool, or a leaked/replayed copy) can wrap it in their own transaction and submit it first. Since delegate-action nonces share the same monotonic/strict counter space as the sender's regular access-key nonce (as nearcore's own docs acknowledge: "a meta transaction sent by Bob may invalidate a meta transaction signed by Alice ... created and sent to the relayer at the same time") [4](#0-3) , the first-included copy consumes/advances the nonce, and the intended relayer's transaction is rejected during nonce verification (`verify_nonce` / delegate nonce check) with a nonce-mismatch error [5](#0-4) , or with `DelegateActionInvalidNonceIndex`/nonce errors for the gas-key nonce path [6](#0-5) .

This is the direct structural analog of the reported `Permit2` issue: an off-chain-signed, nonce-gated authorization intended for submission by one relayer can be front-run and invalidated by any third party who observes it, causing the intended transaction to revert.

### Impact Explanation
This does not by itself cause fund loss or state corruption — the relayer's transaction fails cleanly with a nonce-related `InvalidTxError`/`ActionErrorKind` and gas already spent by the front-runner (or wasted by the relayer on `SEND` costs before the receipt reaches the sender's shard) is the primary cost. However, it enables griefing: an adversary can reliably deny/invalidate a specific user's meta-transaction by racing to submit the intercepted `SignedDelegateAction` first, causing denial of service for that relay flow, wasted gas for the legitimate relayer, and potential loss of trust/compensation flows built on top of meta-transactions (e.g., relayer fee-payment patterns described in the meta-tx docs). This matches "medium" severity: real griefing/DoS impact without direct fund theft, contingent on an attacker being able to observe the pending `SignedDelegateAction` before inclusion.

### Likelihood Explanation
Likelihood depends on an attacker being able to observe a `SignedDelegateAction` before it is included on-chain (e.g., through a public relayer API, network observation, or a leaked copy) — this is explicitly acknowledged as an accepted MVP limitation by the NEP-366 documentation itself [4](#0-3) , indicating the nearcore team is aware nonce sharing/front-running of delegate actions is possible in the current MVP.

### Recommendation
Where feasible for relayer-facing applications, avoid using a shared, globally-visible nonce space for meta-transactions; consider binding a `DelegateAction`'s validity to the specific relayer (e.g., via an intended-relayer field checked in `apply_delegate_action`), or provide gas keys with per-relayer nonce indices (as already partially supported by the gas-key `nonce_index` mechanism in `validate_delegate_action_key`) to reduce nonce contention between independent relay flows. At minimum, relayer implementations should treat a nonce-invalidation failure as retryable rather than fatal, and re-fetch the current nonce before resubmitting, analogous to the try-catch mitigation recommended for `Permit2.permit`.

### Proof of Concept
1. Alice signs a `DelegateAction` with `nonce = N` intended for relayer R1 and sends it off-chain to R1.
2. Attacker observes this `SignedDelegateAction` (e.g., via R1's public submission endpoint) before R1's transaction is included.
3. Attacker wraps the same `SignedDelegateAction` in their own transaction (any account can be the outer transaction's signer/relayer) and submits it first.
4. `apply_delegate_action` → `validate_delegate_action_key` validates the signature and nonce successfully (attacker's tx included first), advancing Alice's access-key nonce to `N` [2](#0-1) .
5. R1's later transaction wrapping the same `SignedDelegateAction` now fails nonce verification since the access key's nonce has already advanced to `N` [5](#0-4) , causing R1's transaction/receipt to fail and any gas R1 already spent (send-side costs) to be wasted.

### Citations

**File:** docs/architecture/how/meta-tx.md (L40-52)
```markdown
With meta transactions, Alice can create a `DelegateAction`, which is very
similar to a transaction. It also contains a list of actions to execute and a
single receiver for those actions. She signs the `DelegateAction` and forwards
it (off-chain) to a relayer. The relayer wraps it in a transaction, of which the
relayer is the signer and therefore pays the gas costs. If the inner actions
have an attached token balance, this is also paid for by the relayer.

On chain, the `SignedDelegateAction` inside the transaction is converted to an
action receipt with the same `SignedDelegateAction` on the relayer's shard. The
receipt is forwarded to the account from `Alice`, which will unpacked the
`SignedDelegateAction` and verify that it is signed by Alice with a valid Nonce
etc. If all checks are successful, a new action receipt with the inner actions
as body is sent to `FT`. There, the `ft_transfer` call finally executes.
```

**File:** docs/architecture/how/meta-tx.md (L161-168)
```markdown
An alternative solution discussed is to do NONCE checks on the relayer's access
key. This prevents replay attacks and allows implicit accounts to be used in
meta transactions without even initializing them. The downside is that meta
transactions share the same NONCE counter(s). That means, a meta transaction
sent by Bob may invalidate a meta transaction signed by Alice that was created
and sent to the relayer at the same time. Multiple access keys by the relayer
and coordination between relayer and user could potentially alleviate this
problem. But for the MVP, nothing along those lines has been approved.
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

**File:** runtime/runtime/src/actions.rs (L530-602)
```rust
/// Validate access key which was used for signing DelegateAction:
///
/// - Checks whether the access key is present fo given public_key and sender_id.
/// - Validates nonce and updates it if it's ok.
/// - Validates access key permissions.
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
```

**File:** runtime/runtime/src/verifier.rs (L210-237)
```rust
/// Verify that the transaction nonce is valid.
fn verify_nonce(
    tx_nonce: Nonce,
    current_nonce: Nonce,
    block_height: Option<BlockHeight>,
    nonce_mode: NonceMode,
) -> Result<(), InvalidTxError> {
    match nonce_mode {
        NonceMode::Monotonic => {
            if tx_nonce <= current_nonce {
                return Err(InvalidTxError::InvalidNonce { tx_nonce, ak_nonce: current_nonce });
            }
        }
        NonceMode::Strict => {
            if !current_nonce.checked_add(1).is_some_and(|expected| tx_nonce == expected) {
                return Err(InvalidTxError::InvalidNonce { tx_nonce, ak_nonce: current_nonce });
            }
        }
    }
    if let Some(height) = block_height {
        let upper_bound = height
            .saturating_mul(near_primitives::account::AccessKey::ACCESS_KEY_NONCE_RANGE_MULTIPLIER);
        if tx_nonce >= upper_bound {
            return Err(InvalidTxError::NonceTooLarge { tx_nonce, upper_bound });
        }
    }
    Ok(())
}
```
