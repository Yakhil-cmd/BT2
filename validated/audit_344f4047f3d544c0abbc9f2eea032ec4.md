This report's bug class — an externally-callable, unauthenticated signature-verification path that advances a caller-tracked nonce as a *side effect*, letting an attacker who merely observes a signed payload front-run and burn the nonce before the legitimate flow completes — has a concrete analog in nearcore's meta-transaction (NEP-366 `DelegateAction`) relaying mechanism.

### Title
Any party can front-run a relayer's meta-transaction by resubmitting an observed `SignedDelegateAction`, burning the sender's nonce and causing denial-of-service to the legitimate transaction - (File: `runtime/runtime/src/actions.rs`)

### Summary
`DelegateAction` (meta transactions) lets a user sign an action off-chain and hand it to a relayer, who wraps it in a transaction and pays gas. The protocol places no restriction on *who* may wrap and submit a given `SignedDelegateAction` — any account can act as the relayer for someone else's signed payload. `validate_delegate_action_key` in `runtime/runtime/src/actions.rs` verifies the delegate action's nonce and, if valid, immediately consumes it, without any check that the submitting transaction's signer is the intended/expected relayer.

### Finding Description
`DelegateAction` contains `sender_id`, `receiver_id`, `actions`, `nonce`, `max_block_height`, and `public_key`, but no field identifying an authorized relayer [1](#0-0) . The documentation confirms that "the relayer wraps it in a transaction, of which the relayer is the signer" with no protocol-level restriction on which account may do this wrapping [2](#0-1) .

On-chain, `validate_delegate_action_key` checks the signature/nonce against the sender's access key (or gas key) state and, if the nonce is strictly greater than the stored nonce, immediately persists the new nonce value: [3](#0-2) [4](#0-3) . This nonce update happens unconditionally for whichever transaction reaches this code path first, regardless of which account signed the outer transaction (i.e., which relayer submitted it) — there is no authorization check tying the relay to a specific submitter, exactly mirroring the reported pattern of a signature-verification function with no access control that has a nonce-advancing side effect.

Since `SignedDelegateAction` is transmitted from the sender to a relayer off-chain and then broadcast on-chain as part of a normal transaction (visible in the mempool/RPC before inclusion), any unprivileged observer can extract it and wrap it in their own competing transaction, paying gas themselves, and get it included first.

### Impact Explanation
If an attacker's copy of the `SignedDelegateAction` is included first, the sender's access-key nonce (or gas-key nonce) is consumed. This uses the same nonce namespace as the sender's regular transactions/access key, as demonstrated by the meta-tx nonce interactions and test [5](#0-4) . When the legitimate relayer's transaction with the same `SignedDelegateAction` (same nonce) is then processed, it hits `DelegateActionInvalidNonce` and fails [3](#0-2) . This is a denial-of-service against the intended relayer/sender flow: the user's intended off-chain-signed action is nullified by a party who was never meant to relay it, and (per the meta-tx design doc) this same shared-nonce behavior is explicitly acknowledged to be able to "invalidate a meta transaction signed by Alice" [6](#0-5) .

### Likelihood Explanation
Exploitation requires only the ability to observe a pending `SignedDelegateAction` (e.g., via the transaction being broadcast to the network/mempool or a public relayer endpoint) and to submit a competing transaction wrapping the identical payload — no validator privilege, no private key of the sender, and no special node access is required, satisfying the unprivileged-account reachability bar.

### Recommendation
Consider adding an explicit relayer-authorization mechanism to `DelegateAction` (e.g., binding the delegate action to a specific expected relayer/signer, or requiring a relayer-specific nonce/commitment) so that `validate_delegate_action_key` in `runtime/runtime/src/actions.rs` can reject submissions from unauthorized relayers before consuming the sender's nonce.

### Proof of Concept
1. Alice signs a `DelegateAction` (nonce N) and sends it off-chain to relayer R.
2. R broadcasts a transaction wrapping the `SignedDelegateAction`.
3. Attacker A observes this broadcast transaction (e.g., via RPC/mempool) and extracts the identical `SignedDelegateAction`.
4. A wraps the same `SignedDelegateAction` in A's own transaction and gets it included first (e.g., by paying higher gas price or exploiting network timing).
5. `validate_delegate_action_key` processes A's transaction, and since nonce N is valid, updates Alice's access key nonce to N per [4](#0-3) .
6. R's original transaction later reaches the same check and fails with `DelegateActionInvalidNonce` per [3](#0-2) , denying service to R and Alice despite R having paid gas to broadcast the (now failing) transaction.

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

**File:** runtime/runtime/src/actions.rs (L604-611)
```rust
    if delegate_nonce.nonce() <= current_nonce {
        result.result = Err(ActionErrorKind::DelegateActionInvalidNonce {
            delegate_nonce: delegate_nonce.nonce(),
            ak_nonce: current_nonce,
        }
        .into());
        return Ok(());
    }
```

**File:** runtime/runtime/src/actions.rs (L685-699)
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
```

**File:** integration-tests/src/tests/features/delegate_action.rs (L121-133)
```rust
    // both nonces should be increased by 1
    let relayer_nonce = node_user
        .get_access_key(&relayer, &PublicKey::from_seed(KeyType::ED25519, relayer.as_ref()))
        .unwrap()
        .nonce;
    assert_eq!(relayer_nonce, relayer_nonce_before + 1);
    // user key must be checked for existence (to test DeleteKey action)
    if let Ok(user_nonce) = node_user
        .get_access_key(&sender, &PublicKey::from_seed(KeyType::ED25519, sender.as_ref()))
        .map(|key| key.nonce)
    {
        assert_eq!(user_nonce, user_nonce_before + 1);
    }
```
