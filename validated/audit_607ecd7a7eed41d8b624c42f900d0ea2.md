### Title
`DeleteAccount` Batch Action Bypasses `total_near()` Accounting, Enabling Router Sub-Account Drain — (`engine-types/src/parameters/promise.rs`, `etc/xcc-router/src/lib.rs`)

---

### Summary

When the `all-promise-actions` feature is enabled in the XCC router, an attacker can submit a `CrossContractCallArgs::Eager` wrapping a `PromiseArgs::Recursive` batch containing `PromiseAction::DeleteAccount { beneficiary_id: attacker_near_account }` targeting their own router sub-account. Because `total_near()` does not count `DeleteAccount` as carrying NEAR value, zero wNEAR is deducted from the attacker, yet the router executes the `DeleteAccount` action and transfers its entire NEAR balance (including the engine's 2 NEAR storage staking deposit) to the attacker-controlled beneficiary.

---

### Finding Description

**Step 1 — `total_near()` gap**

`SimpleNearPromise::total_near()` for a `Batch` variant only sums `FunctionCall { attached_yocto }` and `Transfer { amount }`. All other action variants, including `DeleteAccount`, fall through the `_ => None` arm and contribute zero: [1](#0-0) 

**Step 2 — XCC precompile charges based on `total_near()`**

In the XCC precompile, `attached_near = call.total_near()` is the sole basis for wNEAR deduction. If the router already exists (`get_code_version_of_address` returns `Some(_)`), `required_near = attached_near`, so zero wNEAR is charged: [2](#0-1) [3](#0-2) 

**Step 3 — Router `execute` has no action-type validation**

The router's `execute` method only checks that the caller is the parent (Aurora engine). It performs no inspection of the action types inside the batch: [4](#0-3) 

**Step 4 — `add_batch_actions` unconditionally executes `DeleteAccount`**

Under `#[cfg(feature = "all-promise-actions")]`, `add_batch_actions` handles every `PromiseAction` variant including `DeleteAccount`, calling `env::promise_batch_action_delete_account` with the attacker-supplied `beneficiary_id`: [5](#0-4) [6](#0-5) 

**Step 5 — `target_account_id` is fully attacker-controlled**

`PromiseBatchAction.target_account_id` is deserialized directly from attacker input with no whitelist or self-reference check. The attacker sets it to their own router sub-account: [7](#0-6) 

**Step 6 — The 2 NEAR storage deposit is the drained balance**

The router sub-account holds the 2 NEAR storage staking deposit (`STORAGE_AMOUNT = 2_000_000_000_000_000_000_000_000 yoctoNEAR`) paid by the engine at deployment. `REFUND_AMOUNT` in the router confirms this value: [8](#0-7) [9](#0-8) 

---

### Impact Explanation

When `all-promise-actions` is enabled, an attacker with an existing router sub-account can delete that sub-account and redirect its entire NEAR balance (the engine's 2 NEAR storage capital plus any staking yield) to an arbitrary NEAR account they control. The engine's invariant — that the storage staking deposit is non-transferable to arbitrary accounts via user-controlled promise actions — is broken. Impact: **High — Theft of unclaimed yield** (the 2 NEAR storage capital and accumulated staking rewards per router sub-account).

---

### Likelihood Explanation

**Preconditions required:**
1. The `all-promise-actions` feature must be enabled in the deployed XCC router WASM. This feature is **not** in `default = []` in `etc/xcc-router/Cargo.toml`, so it requires an explicit opt-in at build time.
2. The attacker must have a pre-existing router sub-account (trivially satisfied by any prior XCC user).
3. No special privileges, leaked keys, or social engineering are needed beyond submitting a normal EVM transaction.

If `all-promise-actions` is enabled in a production router build, the exploit is trivially reachable by any EVM user who has previously used XCC.

---

### Recommendation

1. **Blocklist destructive action types**: In `add_batch_actions` (or before dispatching to the router), reject `PromiseAction::DeleteAccount` and `PromiseAction::AddFullAccessKey` / `PromiseAction::AddFunctionCallKey` when the target is the router's own account.
2. **Fix `total_near()` accounting**: `DeleteAccount` transfers the entire account balance to the beneficiary — this is not a zero-NEAR operation from the engine's perspective. The accounting should either charge the full router balance or prohibit the action entirely.
3. **Validate `target_account_id`**: Prevent batch actions from targeting the router's own account ID for destructive operations.
4. **Audit all `PromiseAction` variants** for similar accounting gaps (e.g., `Stake` moves NEAR to a validator without appearing in `total_near()`).

---

### Proof of Concept

```rust
// Construct the malicious promise
let malicious_promise = CrossContractCallArgs::Eager(PromiseArgs::Recursive(
    NearPromise::Simple(SimpleNearPromise::Batch(PromiseBatchAction {
        target_account_id: router_sub_account.clone(), // e.g. "{evm_addr}.aurora"
        actions: vec![PromiseAction::DeleteAccount {
            beneficiary_id: attacker_near_account.clone(),
        }],
    })),
));

// Assert accounting gap: total_near() == 0 despite DeleteAccount draining the balance
assert_eq!(
    PromiseArgs::Recursive(NearPromise::Simple(SimpleNearPromise::Batch(
        PromiseBatchAction {
            target_account_id: router_sub_account.clone(),
            actions: vec![PromiseAction::DeleteAccount {
                beneficiary_id: attacker_near_account.clone(),
            }],
        }
    )))
    .total_near(),
    Yocto::new(0) // No wNEAR deducted from attacker
);

// Attacker submits EVM tx to XCC precompile with borsh-encoded malicious_promise.
// Engine calls router.execute(malicious_promise).
// Router calls add_batch_actions -> promise_batch_action_delete_account(router_sub_account, attacker_near_account).
// Router sub-account deleted; 2 NEAR transferred to attacker_near_account.
// assert attacker_near_account balance increased by ~2 NEAR.
```

### Citations

**File:** engine-types/src/parameters/promise.rs (L84-98)
```rust
            Self::Batch(batch) => {
                let total: u128 = batch
                    .actions
                    .iter()
                    .filter_map(|a| match a {
                        PromiseAction::FunctionCall { attached_yocto, .. } => {
                            Some(attached_yocto.as_u128())
                        }
                        PromiseAction::Transfer { amount } => Some(amount.as_u128()),
                        _ => None,
                    })
                    .fold(0, u128::saturating_add);
                Yocto::new(total)
            }
        }
```

**File:** engine-types/src/parameters/promise.rs (L265-270)
```rust
#[must_use]
#[derive(Debug, BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq)]
pub struct PromiseBatchAction {
    pub target_account_id: AccountId,
    pub actions: Vec<PromiseAction>,
}
```

**File:** engine-precompiles/src/xcc.rs (L139-158)
```rust
        let (promise, attached_near) = match args {
            CrossContractCallArgs::Eager(call) => {
                let call_gas = call.total_gas();
                let attached_near = call.total_near();
                let callback_count = call
                    .promise_count()
                    .checked_sub(1)
                    .ok_or_else(|| ExitError::Other(Cow::from(consts::ERR_INVALID_INPUT)))?;
                let router_exec_cost = costs::ROUTER_EXEC_BASE
                    + NearGas::new(callback_count * costs::ROUTER_EXEC_PER_CALLBACK.as_u64());
                let promise = PromiseCreateArgs {
                    target_account_id,
                    method: consts::ROUTER_EXEC_NAME.into(),
                    args: borsh::to_vec(&call)
                        .map_err(|_| ExitError::Other(Cow::from(consts::ERR_SERIALIZE)))?,
                    attached_balance: ZERO_YOCTO,
                    attached_gas: router_exec_cost.saturating_add(call_gas),
                };
                (promise, attached_near)
            }
```

**File:** engine-precompiles/src/xcc.rs (L177-182)
```rust
        let required_near =
            match state::get_code_version_of_address(&self.io, &Address::new(sender)) {
                // If there is no deployed version of the router contract then we need to charge for storage staking
                None => attached_near + state::STORAGE_AMOUNT,
                Some(_) => attached_near,
            };
```

**File:** engine-precompiles/src/xcc.rs (L254-255)
```rust
    /// Amount of NEAR needed to cover storage for a router contract.
    pub const STORAGE_AMOUNT: Yocto = Yocto::new(2_000_000_000_000_000_000_000_000);
```

**File:** etc/xcc-router/src/lib.rs (L39-40)
```rust
/// Must match aurora_engine_precompiles::xcc::state::STORAGE_AMOUNT
const REFUND_AMOUNT: NearToken = NearToken::from_near(2);
```

**File:** etc/xcc-router/src/lib.rs (L128-133)
```rust
    pub fn execute(&self, #[serializer(borsh)] promise: PromiseArgs) {
        self.assert_preconditions();

        let promise_id = Self::promise_create(promise);
        env::promise_return(promise_id);
    }
```

**File:** etc/xcc-router/src/lib.rs (L289-354)
```rust
    #[cfg(feature = "all-promise-actions")]
    fn add_batch_actions(id: PromiseIndex, actions: &[PromiseAction]) {
        for action in actions.iter() {
            match action {
                PromiseAction::CreateAccount => env::promise_batch_action_create_account(id),
                PromiseAction::Transfer { amount } => env::promise_batch_action_transfer(
                    id,
                    NearToken::from_yoctonear(amount.as_u128()),
                ),
                PromiseAction::DeployContract { code } => {
                    env::promise_batch_action_deploy_contract(id, code)
                }
                PromiseAction::FunctionCall {
                    name,
                    args,
                    attached_yocto,
                    gas,
                } => env::promise_batch_action_function_call(
                    id,
                    name,
                    args,
                    NearToken::from_yoctonear(attached_yocto.as_u128()),
                    Gas::from_gas(gas.as_u64()),
                ),
                PromiseAction::Stake { amount, public_key } => env::promise_batch_action_stake(
                    id,
                    NearToken::from_yoctonear(amount.as_u128()),
                    &to_sdk_pk(public_key),
                ),
                PromiseAction::AddFullAccessKey { public_key, nonce } => {
                    env::promise_batch_action_add_key_with_full_access(
                        id,
                        &to_sdk_pk(public_key),
                        *nonce,
                    )
                }
                PromiseAction::AddFunctionCallKey {
                    public_key,
                    nonce,
                    allowance,
                    receiver_id,
                    function_names,
                } => {
                    let receiver_id = receiver_id.as_ref().parse().unwrap();
                    env::promise_batch_action_add_key_allowance_with_function_call(
                        id,
                        &to_sdk_pk(public_key),
                        *nonce,
                        near_sdk::Allowance::limited(NearToken::from_yoctonear(
                            allowance.as_u128(),
                        ))
                        .unwrap(),
                        &receiver_id,
                        function_names,
                    )
                }
                PromiseAction::DeleteKey { public_key } => {
                    env::promise_batch_action_delete_key(id, &to_sdk_pk(public_key))
                }
                PromiseAction::DeleteAccount { beneficiary_id } => {
                    let beneficiary_id = beneficiary_id.as_ref().parse().unwrap();
                    env::promise_batch_action_delete_account(id, &beneficiary_id)
                }
            }
        }
    }
```
