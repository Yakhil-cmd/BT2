## Title
Wallet Contract silently keeps excess attached deposit on successful relayed transactions instead of refunding it to the caller - (File: `runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs`)

## Summary
The `WalletContract::rlp_execute` entry point is `#[payable]` and accepts an arbitrary NEAR deposit from any predecessor (typically a relayer acting on behalf of the eth-implicit account owner). This deposit is tracked in `CallerDeposit` purely to support a "refund on failure" path in `rlp_execute_callback`. However, the actual value moved by the resulting Near action (`Transfer`/`FunctionCall` deposit) is computed independently from the Ethereum transaction's `value`/`yocto_near` fields, not from the attached deposit amount. If the predecessor attaches more NEAR than the derived action actually needs, and the downstream promise **succeeds**, none of the excess is refunded — mirroring the reported bug class where the developer assumed a refund path exists for every "not fully consumed" scenario, but only wired it up for one branch (failure) and not the other (success with leftover funds).

## Finding Description
`rlp_execute` is payable and builds a `CallerDeposit` snapshot of the full attached deposit for any external (non-self) predecessor: [1](#0-0) 

This `caller_deposit` is threaded through the callback chain (`address_check_callback`, `nep_141_storage_balance_callback`, `rlp_execute_callback`): [2](#0-1) 

In the terminal callback, the *entire* tracked deposit is refunded only when the downstream promise fails; on success, nothing is returned to the caller at all: [3](#0-2) 

Crucially, the deposit amount actually consumed by the generated Near action (`Transfer`/`FunctionCall`) is computed from the Ethereum transaction's `value` field and the small `yocto_near` sub-field encoded in the calldata — entirely independent of how much NEAR the caller attached to the `rlp_execute` call itself: [4](#0-3) [5](#0-4) 

Because the `#[payable]` deposit is deposited straight into the wallet contract's own account balance (this is standard Near payable-call semantics — the deposit becomes part of `current_account_id`'s balance before contract logic runs) and the outgoing action's deposit is drawn from that balance using the independently-computed `tx.value`/`yocto_near`, there is no code path that computes or refunds `attached_deposit - value_actually_used` when the promise succeeds. The developer's model implicitly assumes: "either the whole deposit is needed (success) or none of it is (failure, so refund all)" — exactly the same flawed either/or assumption flagged in the source report, where a partial/excess amount case was never accounted for.

## Impact Explanation
Any relayer or third party (`predecessor_account_id != current_account_id`) that attaches more NEAR to `rlp_execute` than the value encoded in the user's signed Ethereum transaction permanently loses the excess to the wallet contract's own balance whenever the underlying action succeeds. There is no sweep/withdraw mechanism for this excess exposed elsewhere in the contract's public API (only `get_nonce`, `rlp_execute`, and the private callbacks exist). This is an unauthorized/unintended balance transfer from the relayer to the wallet account and a genuine loss of funds for the party that over-attached, reachable by any account submitting a normal transaction to a deployed wallet-contract instance.

## Likelihood Explanation
This is reachable through the contract's only public entry point (`rlp_execute`) with a standard signed transaction — no privileged access or validator/node behavior is required. It requires only that a caller (accidentally or due to a fee/gas estimation buffer) attaches more deposit than the transaction's `value` field strictly requires, which is a plausible relayer implementation mistake (e.g., over-estimating funding for gas/storage buffers) rather than a contrived edge case.

## Recommendation
Compute the exact amount required to fund the derived Near action(s) (transfer value + any storage deposit + fee, as applicable) before dispatching the promise, and refund the difference between `attached_deposit` and that required amount back to the predecessor immediately (or as part of `rlp_execute_callback`) regardless of whether the underlying promise succeeds or fails, instead of only refunding on the failure branch.

## Proof of Concept
1. A relayer submits a signed Ethereum transaction wrapped via `rlp_execute(target, tx_bytes_b64)` on behalf of a wallet-contract account, attaching deposit `D` NEAR.
2. The encoded Ethereum transaction specifies `value = V < D` (in wei, converted to yoctoNEAR via `MAX_YOCTO_NEAR`), e.g., a `Transfer` or `FunctionCall` action.
3. `inner_rlp_execute` builds the action with deposit derived solely from `V`/`yocto_near` (see `internal.rs:159-165`, `types.rs:238-260`), and creates `CallerDeposit { account_id: relayer, yocto_near: D }` (see `types.rs:180-192`).
4. The downstream promise (e.g., the `Transfer` action funded with `V`) succeeds.
5. `rlp_execute_callback` matches `PromiseResult::Successful` and returns without issuing any refund (`lib.rs:313-315`), leaving `D - V` permanently added to the wallet contract account's balance instead of being returned to the relayer.

### Citations

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

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L88-128)
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

        match result {
            Ok(promise) => {
                self.has_in_flight_tx = true;
                PromiseOrValue::Promise(promise)
            }
            Err(Error::Relayer(_)) if env::signer_account_id() == current_account_id => {
                let promise = create_ban_relayer_promise(current_account_id);
                self.has_in_flight_tx = true;
                PromiseOrValue::Promise(promise)
            }
            Err(e) => PromiseOrValue::Value(e.into()),
        }
    }
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

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/internal.rs (L159-165)
```rust
    validate_tx_value(&tx)?;

    // Call to `low_u128` here is safe because of the validation done in `validate_tx_value`
    let near_action = action
        .try_into_near_action(tx.value.raw().low_u128().saturating_mul(MAX_YOCTO_NEAR.into()))?;

    Ok((near_action, transaction_kind))
```
