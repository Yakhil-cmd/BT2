### Title
Wallet Contract `rlp_execute` never validates that `attached_deposit` matches the action's actual NEAR value, allowing excess deposits to be permanently absorbed into the account and later drained by an unrelated relayer/transaction - (File: runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs)

### Summary
`WalletContract::rlp_execute` is a `#[payable]` entry point that lets any relayer attach an arbitrary NEAR deposit while submitting an RLP-encoded Ethereum transaction on behalf of an eth-implicit account. The NEAR amount that is actually transferred/deposited by the resulting action is computed exclusively from the decoded Ethereum transaction fields (`tx.value` and `yocto_near`), completely independent of `env::attached_deposit()`. There is no check anywhere that the attached deposit equals (or even bounds) the value ultimately consumed by the action, mirroring the reported `Router.sol` bug where `msg.value` is decoupled from the validated `amount`.

### Finding Description
`rlp_execute` is marked `#[payable]` and forwards `env::attached_deposit()` into `ExecutionContext` purely to compute a `CallerDeposit` used only for a *failure*-path refund: [1](#0-0) [2](#0-1) 

The actual value moved by the resulting Near action (`Transfer.deposit` / `FunctionCall.deposit`) is derived solely from the RLP transaction's `tx.value` and the ABI-encoded `yocto_near` field, with no reference to `context.attached_deposit`: [3](#0-2) [4](#0-3) 

The only place `attached_deposit` is used again is `CallerDeposit`, which is refunded to the predecessor **only if the resulting cross-contract promise fails**: [5](#0-4) [6](#0-5) 

Since NEAR protocol semantics credit `attached_deposit` to the receiver account's balance unconditionally when a `FunctionCall` action runs (independent of what the callee's code does with it), any surplus between what the relayer attaches and what the decoded action actually spends is **not refunded on success** — it simply becomes part of the eth-implicit wallet contract account's own persistent balance. That balance is not tied to the depositing relayer; it is fungible with the account's balance and can be spent by any future valid Ethereum transaction signed by the address owner (submitted by any relayer), exactly as the excess-WETH scenario in the report describes: the depositor's excess funds end up controlled by, and spendable by, a party other than the one that provided them.

### Impact Explanation
A relayer (or a buggy/naive client) that attaches more NEAR than the actual `tx.value`/`yocto_near` requires permanently loses that excess to the wallet contract's balance on success, with no code path to reclaim it. That balance can subsequently be moved out by any transaction the eth-address owner signs (via `Action::Transfer`/`FunctionCall` with an appropriate `tx.value`), effectively letting a different party consume funds contributed by a previous, unrelated caller. This is a concrete unauthorized balance transfer / token theft pattern, matching the "Excess ETH from deposits" bug class, though it is scoped to relayer-provided NEAR deposits for a single eth-implicit account rather than a shared pool.

### Likelihood Explanation
Likelihood is Low: it requires a relayer to actually attach more NEAR than the encoded action needs (e.g., a naive/buggy relayer overestimating gas/fee requirements, or fee-refund logic miscalculating), and it depends on the account owner (or any relayer relaying the owner's next signed transaction) subsequently draining the balance. There is no automated way for an unrelated third party to trigger the drain without a validly-signed Ethereum transaction from the wallet owner.

### Recommendation
In `inner_rlp_execute` (or in `try_into_near_action`), validate that `context.attached_deposit` exactly matches (or is fully consumed by) the value ultimately used in the derived Near action, and refund any excess to `predecessor_account_id` immediately rather than allowing it to silently merge into the account's balance. Alternatively, disallow `attached_deposit` from being greater than the computed action value, returning a `UserError`/`RelayerError` when they diverge — analogous to enforcing `amount == msg.value` in the referenced `Router.sol` fix.

### Proof of Concept
1. Relayer A calls `rlp_execute(target, tx_bytes)` where the RLP transaction decodes to `Action::Transfer { yocto_near: 0, .. }` (or any action with `tx.value = 0`), but Relayer A attaches `5 NEAR` as `attached_deposit` (e.g., due to overestimating fees).
2. `CallerDeposit::new` records the 5 NEAR only for refund-on-failure purposes: [7](#0-6) .
3. `try_into_near_action` computes the actual transfer deposit as `additional_value.saturating_add(yocto_near)` = `0`, ignoring the 5 NEAR entirely: [8](#0-7) .
4. The inner promise (a 0-value transfer) succeeds, so `rlp_execute_callback` returns success without refunding `caller_deposit`: [9](#0-8) .
5. The 5 NEAR that Relayer A attached now permanently sits in the eth-implicit wallet contract account's balance.
6. Later, the eth address owner signs (and any relayer, e.g. Relayer B, submits) a new transaction with `tx.value` corresponding to that balance, transferring it to an address of the owner's choosing — funds originally supplied by Relayer A end up fully controlled and spent by a transaction unrelated to Relayer A's original call, with no validation ever having tied the two together.

### Citations

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L88-114)
```rust
    #[payable]
    pub fn rlp_execute(
        &mut self,
        target: AccountId,
        tx_bytes_b64: String,
    ) -> PromiseOrValue<ExecuteResponse> {
        // To ensure user actions are executed in the desired order,
        // having multiple transactions in flight at the same time is
        // not allowed.
        if self.has_in_flight_tx {
            return PromiseOrValue::Value(ExecuteResponse {
                success: false,
                success_value: None,
                error: Some(
                    "Error: transaction already in progress, please try again later.".into(),
                ),
            });
        }
        let current_account_id = env::current_account_id();
        let predecessor_account_id = env::predecessor_account_id();
        let result = inner_rlp_execute(
            current_account_id.clone(),
            predecessor_account_id,
            target,
            tx_bytes_b64,
            &mut self.nonce,
        );
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L296-317)
```rust
        match env::promise_result(0) {
            PromiseResult::Failed => {
                // The cross-contract call failed, refund the caller if needed
                if let Some(CallerDeposit { account_id, yocto_near }) = caller_deposit {
                    let refund_promise = env::promise_batch_create(&account_id);
                    env::promise_batch_action_transfer(
                        refund_promise,
                        NearToken::from_yoctonear(yocto_near.into()),
                    );
                }

                ExecuteResponse {
                    success: false,
                    success_value: None,
                    error: Some("Failed Near promise".into()),
                }
            }
            PromiseResult::Successful(value) => {
                ExecuteResponse { success: true, success_value: Some(value), error: None }
            }
        }
    }
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L330-346)
```rust
fn inner_rlp_execute(
    current_account_id: AccountId,
    predecessor_account_id: AccountId,
    target: AccountId,
    tx_bytes_b64: String,
    nonce: &mut u64,
) -> Result<Promise, Error> {
    if *nonce == u64::MAX {
        return Err(Error::AccountNonceExhausted);
    }
    let context = ExecutionContext::new(
        current_account_id.clone(),
        predecessor_account_id,
        env::attached_deposit(),
    )?;
    let caller_deposit = CallerDeposit::new(&context);

```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/internal.rs (L159-165)
```rust
    validate_tx_value(&tx)?;

    // Call to `low_u128` here is safe because of the validation done in `validate_tx_value`
    let near_action = action
        .try_into_near_action(tx.value.raw().low_u128().saturating_mul(MAX_YOCTO_NEAR.into()))?;

    Ok((near_action, transaction_kind))
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/types.rs (L172-192)
```rust
/// A data type to keep track of the deposit given by an external caller.
/// This allows us to refund the caller's deposit if the cross-contract call fails.
#[derive(Debug, PartialEq, Eq, Clone, serde::Serialize, serde::Deserialize)]
pub struct CallerDeposit {
    pub account_id: AccountId,
    pub yocto_near: NonZeroU128,
}

impl CallerDeposit {
    pub fn new(context: &ExecutionContext) -> Option<Self> {
        // Only track for external (non-self) callers
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

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/types.rs (L238-260)
```rust
    pub fn try_into_near_action(
        self,
        additional_value: u128,
    ) -> Result<near_action::Action, Error> {
        let action = match self {
            Action::FunctionCall { receiver_id: _, method_name, args, gas, yocto_near } => {
                let action = FunctionCallAction {
                    method_name,
                    args,
                    gas: Gas::from_gas(gas),
                    deposit: NearToken::from_yoctonear(
                        additional_value.saturating_add(yocto_near.into()),
                    ),
                };
                near_action::Action::FunctionCall(action)
            }
            Action::Transfer { receiver_id: _, yocto_near } => {
                let action = TransferAction {
                    deposit: NearToken::from_yoctonear(
                        additional_value.saturating_add(yocto_near.into()),
                    ),
                };
                near_action::Action::Transfer(action)
```
