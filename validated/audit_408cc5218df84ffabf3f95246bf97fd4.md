### Title
Function-call access key allowance restriction is bypassable via meta-transactions (delegate actions) - ([File: docs/architecture/how/meta-tx.md], [File: runtime/runtime/src/actions.rs])

### Summary
Function-call access keys are meant to restrict what an account's key holder can do: they cap spend via `allowance`, and restrict `receiver_id`/`method_names` [1](#0-0) . When a transaction is signed directly with such a key, `verify_function_call_permission` enforces the receiver, method name and (elsewhere) the allowance limit [2](#0-1) . However, when the same access key is used to sign a `DelegateAction` (NEP-366 meta-transaction), the runtime's `validate_delegate_action_key` path re-checks the action count, deposit, `receiver_id`, and `method_names`, but performs **no check of the allowance at all** [3](#0-2) . This is explicitly documented: "For allowance, however, there is no check... if someone were to limit a function access key to one trivial action by setting a very small allowance, that is circumventable by going through a relayer." [4](#0-3) 

### Finding Description
This mirrors the reported bug class exactly: a restriction meant to constrain what a party can do with a delegated/limited-permission credential (`onlyApprovedContracts` for NFTs vs. `allowance` for function-call access keys) is only enforced on one execution path and can be routed around through an alternate path that reaches the same underlying capability (OTC trades vs. relayer-submitted meta-transactions).

Concretely:
- A user creates a function-call access key with a small `allowance`, intending that whoever holds/uses this key can spend at most that much of the account's balance on gas/fees for calls to a specific `receiver_id`/`method_names`. This is the documented security model of `FunctionCallPermission` [5](#0-4) .
- Direct transactions signed with this key are gas/fee-limited by the allowance, enforced in `verify_function_call_permission` and the broader verifier logic (`NotEnoughAllowance`) [6](#0-5) .
- If the same key is used to sign a `SignedDelegateAction` and submitted by a relayer, `validate_delegate_action_key` in `runtime/runtime/src/actions.rs` validates action count, zero deposit, receiver match, and method-name match — but never touches `allowance` [3](#0-2) . All gas/fee costs in this flow are instead paid by the relayer, so the allowance limit that the key owner relied on to bound the key's blast radius has no effect in this path.
- The nearcore team itself documents this as a known, intentional gap rather than something that is checked: "This behavior is in the spirit of allowance limiting how much financial resources the user can use from a given account. But if someone were to limit a function access key to one trivial action by setting a very small allowance, that is circumventable by going through a relayer." [7](#0-6) 

### Impact Explanation
The impact is limited compared to the original NFT report because the meta-transaction path still enforces `receiver_id` and `method_names` restrictions [8](#0-7) , and the relayer — not the account — pays for gas/fees in this path, so there is no direct token theft or balance drain of the owner's account through this specific gap. The only broken guarantee is the "allowance" as a hard cap on what the key can be used for financially; an app or key-issuer that relies on "this key can spend at most X" as a security boundary (e.g., giving a third party a heavily-capped key expecting it can only ever trigger one cheap call) can have that assumption defeated if the holder finds any relayer willing to submit the inner action as a meta-transaction. This is a control/assumption bypass, not unauthorized state or balance change of the granting account's own funds, so impact is moderate rather than high.

### Likelihood Explanation
Low-to-moderate. It requires: (1) an application relying specifically on `allowance` (rather than `method_names`/`receiver_id`) as its security boundary for a function-call access key, and (2) availability of a relayer/meta-transaction submission path (which is a supported, documented NEAR feature, not privileged). As with the original report, likelihood is reduced because the behavior is explicitly documented by the protocol team, so well-informed integrators are expected to already know allowance is not meta-tx safe.

### Recommendation
Either (a) enforce the access key's `allowance` against the relayer-covered cost of the inner action in `validate_delegate_action_key`/the meta-transaction charging path so that allowance remains a real bound regardless of submission path, or (b) explicitly document (as already partially done) that `allowance` MUST NOT be relied upon as a security boundary when a key could be used within a meta-transaction, and provide method-name/receiver-based restriction as the only supported hard boundary.

### Proof of Concept
1. Account `alice` creates a function-call access key `K` with `allowance = 1 yoctoNEAR` (or any negligible balance), `receiver_id = "app.near"`, `method_names = ["do_something"]`, intending `K` to be usable for at most a trivial, low-cost interaction.
2. Directly submitting a transaction signed with `K` calling `do_something` fails/limits once the tiny allowance is exhausted (`NotEnoughAllowance`), matching `verify_function_call_permission` checks [2](#0-1) .
3. Instead, the holder of `K` signs a `SignedDelegateAction` targeting `app.near::do_something` and hands it to any relayer, who submits it as a meta-transaction.
4. `validate_delegate_action_key` validates action count, deposit, receiver, and method name, but never inspects `allowance` [3](#0-2) , and the relayer (not `alice`) pays the gas cost [9](#0-8) .
5. The call succeeds repeatedly (as many times as nonce/relayer availability allow) despite the trivial allowance on `K`, confirming the allowance boundary that `alice` relied on is not enforced on this path.

### Citations

**File:** core/primitives-core/src/account.rs (L608-644)
```rust
/// Grants limited permission to make transactions with FunctionCallActions
/// The permission can limit the allowed balance to be spent on the prepaid gas.
/// It also restrict the account ID of the receiver for this function call.
/// It also can restrict the method name for the allowed function calls.
#[derive(
    BorshSerialize,
    BorshDeserialize,
    serde::Serialize,
    serde::Deserialize,
    PartialEq,
    Eq,
    Hash,
    Clone,
    Debug,
    ProtocolSchema,
)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct FunctionCallPermission {
    /// Allowance is a balance limit to use by this access key to pay for function call gas and
    /// transaction fees. When this access key is used, both account balance and the allowance is
    /// decreased by the same value.
    /// `None` means unlimited allowance.
    /// NOTE: To change or increase the allowance, the old access key needs to be deleted and a new
    /// access key should be created.
    pub allowance: Option<Balance>,

    // This isn't an AccountId because already existing records in testnet genesis have invalid
    // values for this field (see: https://github.com/near/nearcore/pull/4621#issuecomment-892099860)
    // we accommodate those by using a string, allowing us to read and parse genesis.
    /// The access key only allows transactions with the given receiver's account id.
    pub receiver_id: String,

    /// A list of method names that can be used. The access key only allows transactions with the
    /// function call of one of the given method names.
    /// Empty list means any method name can be used.
    pub method_names: Vec<String>,
}
```

**File:** runtime/runtime/src/verifier.rs (L161-208)
```rust
/// Validates FunctionCall permission constraints:
/// - Transaction must have exactly one action
/// - Action must be FunctionCall with zero deposit
/// - Receiver must match permission's receiver
/// - Method name must be in allowed list (if list is non-empty)
fn verify_function_call_permission(
    function_call_permission: &FunctionCallPermission,
    tx: &Transaction,
) -> Result<(), InvalidTxError> {
    if tx.actions().len() != 1 {
        return Err(InvalidTxError::InvalidAccessKeyError(
            InvalidAccessKeyError::RequiresFullAccess,
        ));
    }
    let Some(Action::FunctionCall(function_call)) = tx.actions().get(0) else {
        return Err(InvalidTxError::InvalidAccessKeyError(
            InvalidAccessKeyError::RequiresFullAccess,
        ));
    };
    if function_call.deposit > Balance::ZERO {
        return Err(InvalidTxError::InvalidAccessKeyError(
            InvalidAccessKeyError::DepositWithFunctionCall,
        ));
    }
    let tx_receiver = tx.receiver_id();
    let ak_receiver = &function_call_permission.receiver_id;
    if tx_receiver != ak_receiver {
        return Err(InvalidTxError::InvalidAccessKeyError(
            InvalidAccessKeyError::ReceiverMismatch {
                tx_receiver: tx_receiver.clone(),
                ak_receiver: ak_receiver.clone(),
            },
        ));
    }
    if !function_call_permission.method_names.is_empty()
        && function_call_permission
            .method_names
            .iter()
            .all(|method_name| &function_call.method_name != method_name)
    {
        return Err(InvalidTxError::InvalidAccessKeyError(
            InvalidAccessKeyError::MethodNameMismatch {
                method_name: function_call.method_name.clone(),
            },
        ));
    }
    Ok(())
}
```

**File:** runtime/runtime/src/actions.rs (L624-683)
```rust
    let actions = delegate_action.get_actions();

    // The restriction of "function call" access keys:
    // the transaction must contain the only `FunctionCall` if "function call" access key is used
    if let Some(function_call_permission) = access_key.permission.function_call_permission() {
        if actions.len() != 1 {
            result.result = Err(ActionErrorKind::DelegateActionAccessKeyError(
                InvalidAccessKeyError::RequiresFullAccess,
            )
            .into());
            return Ok(());
        }
        if let Some(Action::FunctionCall(function_call)) = actions.get(0) {
            if function_call.deposit > Balance::ZERO {
                result.result = Err(ActionErrorKind::DelegateActionAccessKeyError(
                    InvalidAccessKeyError::DepositWithFunctionCall,
                )
                .into());
                // Before this fix, the missing early return allowed execution
                // to fall through to the receiver_id and method_name checks,
                // which could overwrite this error with a different one.
                if ProtocolFeature::FixDelegateActionDepositWithFunctionCallError
                    .enabled(apply_state.current_protocol_version)
                {
                    return Ok(());
                }
            }
            if delegate_action.receiver_id() != &function_call_permission.receiver_id {
                result.result = Err(ActionErrorKind::DelegateActionAccessKeyError(
                    InvalidAccessKeyError::ReceiverMismatch {
                        tx_receiver: delegate_action.receiver_id().clone(),
                        ak_receiver: function_call_permission.receiver_id.clone(),
                    },
                )
                .into());
                return Ok(());
            }
            if !function_call_permission.method_names.is_empty()
                && function_call_permission
                    .method_names
                    .iter()
                    .all(|method_name| &function_call.method_name != method_name)
            {
                result.result = Err(ActionErrorKind::DelegateActionAccessKeyError(
                    InvalidAccessKeyError::MethodNameMismatch {
                        method_name: function_call.method_name.clone(),
                    },
                )
                .into());
                return Ok(());
            }
        } else {
            // There should Action::FunctionCall when "function call" permission is used
            result.result = Err(ActionErrorKind::DelegateActionAccessKeyError(
                InvalidAccessKeyError::RequiresFullAccess,
            )
            .into());
            return Ok(());
        }
    };
```

**File:** docs/architecture/how/meta-tx.md (L225-242)
```markdown
## Balance refunds in meta transactions

Unlike gas refunds, the protocol sends balance refunds to the predecessor
(a.k.a. sender) of the receipt. This makes sense, as we deposit the attached
balance to the receiver, who has to explicitly reattach a new balance to new
receipts they might spawn.

In the world of meta transactions, this assumption is also challenged. If an
inner action requires an attached balance (for example a transfer action) then
this balance is taken from the relayer.

The relayer can see what the cost will be before submitting the meta transaction
and agrees to pay for it, so nothing wrong so far. But what if the transaction
fails execution on Bob's shard? At this point, the predecessor is `Alice` and
therefore she receives the token balance refunded, not the relayer. This is
something relayer implementations must be aware of since there is a financial
incentive for Alice to submit meta transactions that have high balances attached
but will fail on Bob's shard.
```

**File:** docs/architecture/how/meta-tx.md (L244-266)
```markdown
## Function access keys in meta transactions

Assume alice sends a meta transaction and signs with a function access key.
How exactly are permissions applied in this case?

Function access keys can limit the allowance, the receiving contract, and the
contract methods. The allowance limitation acts slightly strange with meta
transactions.

But first, both the methods and the receiver will be checked as expected. That
is, when the delegate action is unwrapped on Alice's shard, the access key is
loaded from the DB and compared to the function call. If the receiver or method
is not allowed, the function call action fails.

For allowance, however, there is no check. All costs have been covered by the
relayer. Hence, even if the allowance of the key is insufficient to make the call
directly, indirectly through meta transaction it will still work.

This behavior is in the spirit of allowance limiting how much financial
resources the user can use from a given account. But if someone were to limit a
function access key to one trivial action by setting a very small allowance,
that is circumventable by going through a relayer. An interesting twist that
comes with the addition of meta transactions.
```

**File:** docs/RuntimeSpec/Transactions.md (L170-185)
```markdown
#### Access Key is allowed to cover transaction cost

If the transaction is signed by a function call access key and the function call access key does not have enough
allowance to cover the cost of the transaction, a

```rust
/// Access Key does not have enough allowance to cover transaction cost
NotEnoughAllowance {
    account_id: AccountId,
    public_key: PublicKey,
    allowance: Balance,
    cost: Balance,
}
```

error is returned.
```
