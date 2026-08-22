### Title
Attached NEAR deposit is silently absorbed by the Wallet Contract instead of being forwarded or refunded when the emulated action does not consume it - (File: `runtime/near-wallet-contract/implementation/wallet-contract/src/types.rs`, `runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs`, `runtime/near-wallet-contract/implementation/wallet-contract/src/internal.rs`)

### Summary
`WalletContract::rlp_execute` is `#[payable]` and accepts an arbitrary `attached_deposit` from an external predecessor (e.g. a relayer or another contract acting on the user's behalf) independent of the value actually needed by the Ethereum-emulated action it decodes. The amount that is actually forwarded to the target of the action is derived only from the RLP transaction's `value`/`yocto_near` fields via `Action::try_into_near_action`, and for `AddKey`/`DeleteKey` actions that value is discarded entirely. The only path that returns the caller's `attached_deposit` is `rlp_execute_callback` when the underlying promise fails; on success, any unused portion of `attached_deposit` (including the entire deposit for `AddKey`/`DeleteKey`) is retained by the wallet's own account balance with no mechanism for the paying caller to reclaim it.

### Finding Description
The bug class from the report is: a contract accepts a value transfer intended to be routed to a specific destination based on an input parameter, but an internal computation zeroes/ignores that intended amount for certain parameter values, so the value is retained by the receiving contract with no retrieval path.

The same pattern exists here:

- `WalletContract::rlp_execute` (`lib.rs:88-128`) is `#[payable]`; the predecessor account's `attached_deposit` is captured via `env::attached_deposit()` in `inner_rlp_execute` (`lib.rs:340-345`).
- `CallerDeposit::new` (`types.rs:180-191`) records this attached deposit only for the purpose of a *failure* refund:
```rust
impl CallerDeposit {
    pub fn new(context: &ExecutionContext) -> Option<Self> {
        if context.current_account_id == context.predecessor_account_id {
            return None;
        }
        NonZeroU128::new(context.attached_deposit.as_yoctonear()).map(|yocto_near| Self {
            account_id: context.predecessor_account_id.clone(),
            yocto_near,
        })
    }
}
```
- The value that is actually attached to the emitted Near action comes from a *separate* source: the RLP-decoded Ethereum transaction's `value`/`yocto_near` fields, computed in `parse_rlp_tx_to_action` (`internal.rs:159-165`) and merged in `Action::try_into_near_action` (`types.rs:238-300`). For `AddKey`/`DeleteKey` this additional value is never referenced at all:
```rust
Action::AddKey { public_key_kind, public_key, nonce, is_full_access, is_limited_allowance,
    allowance, receiver_id, method_names } => { ... /* additional_value unused */ }
Action::DeleteKey { public_key_kind, public_key } => { ... /* additional_value unused */ }
```
- `rlp_execute_callback` (`lib.rs:276-317`) only issues a refund transfer of the *entire* `caller_deposit` when `PromiseResult::Failed`; on `PromiseResult::Successful`, no refund of any kind is performed, regardless of whether the actual action consumed the deposit:
```rust
match env::promise_result(0) {
    PromiseResult::Failed => {
        if let Some(CallerDeposit { account_id, yocto_near }) = caller_deposit {
            let refund_promise = env::promise_batch_create(&account_id);
            env::promise_batch_action_transfer(refund_promise, NearToken::from_yoctonear(yocto_near.into()));
        }
        ...
    }
    PromiseResult::Successful(value) => { /* no refund logic at all */ }
}
```

Because Near credits `attached_deposit` to the receiving account's balance before contract logic executes, any `attached_deposit` sent by an external predecessor that is not consumed by the resulting action (e.g. because the decoded action is `AddKey`/`DeleteKey`, or because the caller attaches more than the RLP tx's `value` requires) becomes a permanent, unrefundable increase to the wallet's own account balance on success — money that belonged to the calling relayer/contract, not the wallet owner, with no code path to reclaim it.

### Impact Explanation
An external caller (a relayer using a `FunctionCall` access key, or any contract invoking `rlp_execute` cross-contract) that attaches NEAR expecting it to be used for, or refunded from, the emulated Ethereum action can permanently lose that NEAR to the wallet-contract account on any successful `AddKey`/`DeleteKey` transaction, or whenever it over-attaches relative to the RLP tx's `value` field for any action type. This is an unauthorized balance change: funds move from the payer to the wallet's own balance without consent or corresponding accounting, and there is no user-facing function to retrieve mis-attached deposits. The severity depends on how attached deposits are chosen/enforced by relayers in practice, but the code path itself provides no safeguard or refund for the success case.

### Likelihood Explanation
This requires only an unprivileged, standard interaction: any predecessor account (a relayer with a `FunctionCall` access key on the wallet, or another contract) calling the public `#[payable]` method `rlp_execute` with a nonzero `attached_deposit` on a transaction whose decoded action is `AddKey`/`DeleteKey` (trivial to construct, since these are user-signable Ethereum-emulated actions per the ABI selectors in `types.rs`), or simply attaching more `attached_deposit` than the RLP tx's `value` field specifies. No validator or node-internal privilege is needed; this is reachable purely through normal contract calls.

### Recommendation
- Validate that `attached_deposit` is exactly consumed by the resulting `near_action`'s value (fail the call otherwise), or
- Track precisely how much of `attached_deposit` was actually used to construct the outgoing action, and refund the unused remainder to `predecessor_account_id` regardless of whether the underlying promise succeeds or fails (not only on failure).
- For `AddKey`/`DeleteKey` actions specifically, reject any nonzero `attached_deposit`/`tx.value` up front rather than silently discarding it.

### Proof of Concept
1. Deploy `WalletContract` at an eth-implicit account `0xabc...` and grant a relayer account `relayer.near` a `FunctionCall` access key on it (or have `relayer.near` be a contract that calls `rlp_execute` cross-contract).
2. Construct and sign (with the wallet owner's key) an RLP Ethereum transaction whose calldata matches `ADD_KEY_SELECTOR` (`types.rs:28`), targeting the wallet's own account, with `tx.value = 0`.
3. Have `relayer.near` call `rlp_execute(target, tx_bytes_b64)` on the wallet contract while attaching, e.g., `1 NEAR` as `attached_deposit`.
4. The transaction succeeds: `address_check_callback`/direct path builds `action_to_promise` for `AddKeyAction` (no deposit field used), then `rlp_execute_callback` is invoked with `PromiseResult::Successful`. No refund transfer is created.
5. Observe that the wallet's own account balance increased by the `1 NEAR` that `relayer.near` attached, and `relayer.near`'s balance decreased accordingly with no way to recover it — `1 NEAR` has been irrecoverably transferred from the relayer to the wallet owner outside of any explicit `Transfer` action.