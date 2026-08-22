### Title
Front-runnable meta transactions allow anyone to extract and replay a `SignedDelegateAction` from the mempool, invalidating the legitimate relayer's transaction via nonce consumption - (File: `runtime/runtime/src/actions.rs`)

### Summary
NEP-366 meta transactions (`DelegateAction`/`SignedDelegateAction`) are the nearcore analog of the `permit()` pattern described in the report. A user signs a `DelegateAction` off-chain and hands it to a relayer, who wraps it in a `SignedTransaction` and broadcasts it. Because the signature only covers `sender_id`, `receiver_id`, `actions`, `nonce`, `max_block_height`, and `public_key` — and not the identity of the outer transaction's signer (the relayer) — anyone who observes this pending transaction in the mempool can copy the embedded `SignedDelegateAction`, wrap it in their own outer transaction (paying gas themselves), and get it included first. This consumes the sender's access-key nonce, causing the legitimate relayer's original transaction to fail with `DelegateActionInvalidNonce` when it is later processed — exactly the "front-run and burn the nonce/one-time token" DOS pattern described for `permit()`.

### Finding Description
`SignedDelegateAction::verify` only checks the signature over the NEP-461 hash of the `DelegateAction` fields themselves: [1](#0-0) 

The `DelegateAction` struct binds a `nonce` to the sender's access key (`public_key`), but nowhere binds the delegate action to a specific relayer/outer signer: [2](#0-1) 

At execution time, `validate_delegate_action_key` in `runtime/runtime/src/actions.rs` validates the nonce strictly against the sender's on-chain access-key nonce and rejects if it isn't strictly greater — with no check that the same relayer that would eventually submit it is the one submitting it now: [3](#0-2) 

The design document explicitly acknowledges this "any relayer can wrap any DelegateAction" behavior, and even warns about the risk that a competing meta transaction can invalidate another one via nonce collision, though it discusses this only in the context of a shared relayer, not a malicious third party observing the mempool: [4](#0-3) 

The nearcore test suite confirms the exact mechanic: replaying the same `SignedDelegateAction`/nonce after it has already been consumed causes `DelegateActionInvalidNonce`: [5](#0-4) 

This is the direct analog of the `permit()` front-running bug: the reusable/replayable authorization data (`SignedDelegateAction`) is broadcast publicly before inclusion, is not bound to a specific submitter, and consuming it once (by anyone) invalidates all other pending copies signed with the same nonce.

### Impact Explanation
Any third party monitoring the mempool/transaction relay can extract a pending `SignedDelegateAction` and resubmit it wrapped in their own transaction ahead of the intended relayer. This:
- Causes the legitimate relayer's transaction to fail (`DelegateActionInvalidNonce`), wasting relayer effort and potentially relayer-side accounting/state that assumed the transaction would succeed.
- Can be used to selectively grief a specific relayer's meta-transaction business (denial of service against a competitor or a specific user flow) at negligible attacker cost (the attacker pays only the gas for wrapping the action, and if the user attached any relayer-fee payment action, the *attacker* — not the intended relayer — could collect it).
- Undermines the trust assumption relayers rely on (per NEP-366 design notes) that they exclusively control submission timing/ordering of a `SignedDelegateAction` they have committed gas/business logic around.

This does not directly cause fund theft from users' balances (the inner actions still execute correctly against the correct sender/receiver), but it is a legitimate transaction-DOS and relayer-griefing vector consistent with the reported bug class ("unauthorized" consumption of a signed authorization causing legitimate submission to fail).

### Likelihood Explanation
High reachability: any observer of the public mempool (RPC nodes, block producers' pending pools) can see `Action::Delegate`/`Action::DelegateV2` transactions before inclusion, since near transactions are broadcast plaintext once submitted. Extracting the `SignedDelegateAction`, re-wrapping it in a new outer `SignedTransaction` (self-signed, self-paid gas, correct `receiver_id` = `delegate_action.sender_id`), and submitting it requires no special permission and is straightforward to automate — the same class of "copy and front-run" attack described in the source report.

### Recommendation
- Consider binding the `DelegateAction` to a specific intended relayer (e.g., include an optional `relayer_id` field that must match the outer transaction's `signer_id`), so the signed authorization cannot be redirected/consumed by an unintended party.
- Alternatively/additionally, document and mitigate at the relayer level (similar to the report's recommendation): relayers should treat submission races defensively (e.g., re-check on-chain nonce immediately before submission, and not treat a `DelegateActionInvalidNonce` failure as fatal to their business logic — analogous to using try/catch around `permit()`), but the protocol-level mitigation (binding relayer identity) is the durable fix.

### Proof of Concept
1. Alice signs a `DelegateAction { sender_id: Alice, receiver_id: Bob, actions: [...], nonce: N, public_key: Alice_pk }` and sends the resulting `SignedDelegateAction` off-chain to Relayer R.
2. R wraps it: `SignedTransaction { signer_id: R, receiver_id: Alice, actions: [Action::Delegate(signed_delegate_action)] }`, signs, and broadcasts it. This transaction sits in the mempool/relay before inclusion.
3. Attacker M observes the pending transaction, extracts `signed_delegate_action` unchanged, and constructs their own `SignedTransaction { signer_id: M, receiver_id: Alice, actions: [Action::Delegate(signed_delegate_action)] }`, signs with M's own key, and submits it with sufficient gas priority to be included first.
4. On execution, `validate_delegate_action_key` (`runtime/runtime/src/actions.rs`) accepts M's wrapped transaction because it only checks that `delegate_nonce.nonce() > current_nonce` for Alice's access key — it succeeds and increments Alice's access-key nonce.
5. When R's original transaction is later processed with the same `nonce: N`, `validate_delegate_action_key` now finds `delegate_nonce.nonce() <= current_nonce` and returns `ActionErrorKind::DelegateActionInvalidNonce`, exactly as demonstrated by the "replay" assertion in the existing test: [5](#0-4) 
R's transaction fails, denying the legitimate relayer's service despite R having done nothing wrong.

### Citations

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

**File:** docs/RuntimeSpec/Actions.md (L340-360)
```markdown
```rust
/// The struct a user creates and signs to create a meta transaction.
struct DelegateAction {
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

**File:** runtime/runtime/src/actions.rs (L561-611)
```rust
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

**File:** test-loop-tests/src/tests/gas_keys.rs (L274-296)
```rust
    // Replaying the same delegate (same gas key nonce) is rejected.
    let block_hash = get_shared_block_hash(&env.node_datas, &env.test_loop.data);
    let replay_tx = SignedTransaction::from_actions(
        next_relayer_nonce(),
        relayer.clone(),
        sender.clone(),
        &relayer_signer,
        vec![Action::DelegateV2(Box::new(signed_delegate))],
        block_hash,
    );
    let replay_outcome = env.rpc_runner().execute_tx(replay_tx, Duration::seconds(5)).unwrap();
    assert!(
        matches!(
            replay_outcome.status,
            FinalExecutionStatus::Failure(TxExecutionError::ActionError(ActionError {
                kind: ActionErrorKind::DelegateActionInvalidNonce { .. },
                ..
            }))
        ),
        "expected DelegateActionInvalidNonce on replay, got {:?}",
        replay_outcome.status,
    );
}
```
