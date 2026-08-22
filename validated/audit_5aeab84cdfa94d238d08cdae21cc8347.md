Based on the investigation, there is a valid structural analog in nearcore's meta-transaction (NEP-366) nonce handling, exposed via `validate_delegate_action_key` in `runtime/runtime/src/actions.rs`.

### Title
Front-runnable, permission-less consumption of a `DelegateAction`'s one-time nonce allows anyone to burn a user's signed meta-transaction before the intended relayer submits it - (File: `runtime/runtime/src/actions.rs`)

### Summary
`DelegateAction`/`DelegateActionV2` (NEP-366 meta transactions) rely on a nonce tied to the sender's access key (or gas key) to prevent replay, exactly like `PrincipalToken.permitCollector`'s nonce. The nonce is validated and unconditionally advanced by `validate_delegate_action_key` as soon as the receipt containing the `Delegate` action is processed - regardless of which account submitted the wrapping outer transaction. Because nothing binds the outer transaction's signer ("relayer") to a specific authorized relayer, any account that obtains a copy of a valid, not-yet-included `SignedDelegateAction` (e.g., by observing it in the transaction pool before the intended relayer's transaction is included) can wrap it in its own transaction and get it processed first, consuming the nonce ahead of the intended submission - mirroring the reported `permitCollector`/`TwoCryptoZap.collectWithPermit` front-running issue.

### Finding Description
`validate_delegate_action_key` reads the current access-key (or gas-key) nonce, checks `delegate_nonce.nonce() <= current_nonce`, and if the check passes, immediately writes the new nonce back to state before any of the inner actions are executed: [1](#0-0) [2](#0-1) 

This validation only checks the sender's signature over the `DelegateAction` payload and its nonce; it performs no check on the identity of the outer transaction's signer (the "relayer"). The docs confirm the relayer is just whoever wraps and submits the delegate action, with only informal/off-chain trust expected between sender and relayer: [3](#0-2) [4](#0-3) 

Because the nonce bump happens unconditionally for any wrapping transaction (regardless of submitter identity or of gas/deposit sufficiency for the inner actions), once *any* party — including one that never received authorization to relay — submits the intercepted `SignedDelegateAction`, a resubmission of the same signed action by the intended relayer is permanently rejected with `DelegateActionInvalidNonce`, exactly as demonstrated by the existing replay test: [5](#0-4) 

This is structurally identical to the reported bug: a public, permission-less function (`permitCollector` / here, the outer wrapping transaction submission path) that consumes a signature-authorized, monotonically-increasing nonce meant to gate a specific downstream flow (`TwoCryptoZap.collectWithPermit` / here, the intended relayer's submission), which any third party can trigger ahead of the legitimate caller.

### Impact Explanation
An attacker who observes a pending `SignedDelegateAction` (via mempool/gossip visibility of the outer transaction before it lands on chain, or via off-chain leakage) can front-run the intended relayer by submitting their own wrapping transaction first. This:
- Denies the intended relayer the ability to ever submit that specific signed delegate action again (permanent invalidation, since the nonce cannot be reused and a brand-new signature from the sender is required to recover) - a stronger DoS than the temporary one in the original report.
- Can be combined with the relayer-pays-cost design (`docs/architecture/how/meta-tx.md`, `nonce advances regardless of the relayer's own balance/deposit sufficiency`) so that if the front-runner deliberately submits with insufficient balance, the inner actions fail while the nonce is still consumed, permanently burning the sender's intended meta-transaction and any expected relayer compensation logic bundled inside its actions.

### Likelihood Explanation
This requires no privileged role: any account able to submit a `Delegate`/`DelegateV2` action receipt referencing a captured `SignedDelegateAction` can trigger it. The main precondition is visibility of the not-yet-included `SignedDelegateAction` (e.g., transaction-pool observation window), which is a realistic condition for relayer-based flows since the signed payload must at some point traverse the network as part of an outer transaction before inclusion.

### Recommendation
Consider binding a specific authorized relayer identity into what is being validated (e.g., requiring `predecessor_id`/outer signer to match an expected relayer recorded off-chain-and-enforced-on-chain, or a short-lived commitment/reservation scheme), or make nonce consumption conditional on successful execution of the inner actions so an unauthorized or underfunded submitter cannot permanently burn the sender's authorization. At minimum, document this front-running/DoS risk explicitly in the meta-transaction relayer trust model in `docs/architecture/how/meta-tx.md`, since the current text does not call out third-party (non-relayer) front-running of the nonce.

### Proof of Concept
1. Alice signs a `DelegateAction` (`sender_id = alice`, `nonce = N+1`) authorizing `FunctionCall` actions and hands the `SignedDelegateAction` to relayer R off-chain, or R broadcasts an outer transaction wrapping it.
2. Before R's transaction is included, attacker M observes the `SignedDelegateAction` bytes (e.g., via transaction-pool gossip) and wraps the *same* `SignedDelegateAction` in M's own outer transaction (M as signer/relayer), submitting it with a higher priority so it lands first.
3. `validate_delegate_action_key` (`runtime/runtime/src/actions.rs:535-702`) validates Alice's signature and nonce successfully and immediately bumps `access_key.nonce` to `N+1`.
4. R's original transaction, once processed, fails validation with `DelegateActionInvalidNonce { delegate_nonce: N+1, ak_nonce: N+1 }` — identical error-class behavior already covered by the existing test `test_gas_key_delegate_v2_meta_transaction`'s replay check [5](#0-4) .
5. Alice must produce a brand-new signed `DelegateAction` to retry — a permanent invalidation of the original meta-transaction caused entirely by an unauthorized third party.

### Citations

**File:** runtime/runtime/src/actions.rs (L560-611)
```rust
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
```

**File:** runtime/runtime/src/actions.rs (L685-701)
```rust
    match nonce_update {
        DelegateNonceUpdate::AccessKey => {
            access_key.nonce = delegate_nonce.nonce();
            set_access_key(state_update, sender_id.clone(), public_key.clone(), &access_key);
        }
        DelegateNonceUpdate::GasKey { nonce_index } => {
            set_gas_key_nonce(
                state_update,
                sender_id.clone(),
                public_key.clone(),
                nonce_index,
                delegate_nonce.nonce(),
            );
        }
    }

    Ok(())
```

**File:** docs/architecture/how/meta-tx.md (L40-53)
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

**File:** docs/architecture/how/meta-tx.md (L72-80)
```markdown
Note that the payment to the relayer is still not guaranteed. It could be that
Alice does not have sufficient $FT and the transfer fails. To mitigate, the
relayer should check the $FT balance of Alice first.

Unfortunately, this still does not guarantee that the balance will be high
enough once the meta transaction executes. The relayer could waste NEAR gas
without compensation if Alice somehow reduces her \$FT balance in just the right
moment. Some level of trust between the relayer and its user is therefore
required.
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
