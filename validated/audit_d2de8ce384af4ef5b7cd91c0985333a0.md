Looking at the M-13 vulnerability class — a **mandatory check in all exit paths that can fail due to external/protocol state, blocking fund withdrawal** — I need to find an analog in Starknet Staking where a mandatory operation in `unstake_action` or `exit_delegation_pool_action` can revert, trapping principal.

The key finding is in `src/staking/utils.cairo` and `src/staking/staking.cairo`. [1](#0-0) [2](#0-1) [3](#0-2) 

---

### Title
Mandatory Reward Claiming in `unstake_action` Blocks Staker Principal Withdrawal When Reward Supplier Is Underfunded — (File: `src/staking/staking.cairo`)

### Summary

`unstake_action` unconditionally calls `send_rewards_to_staker`, which calls `claim_from_reward_supplier`. If the reward supplier's actual STRK token balance is less than the staker's `unclaimed_rewards_own` — a window that exists because `unclaimed_rewards` is incremented immediately on reward calculation but L1 minting fills the balance asynchronously — the `checked_transfer` inside `reward_supplier.claim_rewards` panics, reverting `unstake_action` and trapping the staker's principal.

### Finding Description

In `unstake_action` (`src/staking/staking.cairo:483–515`), the function unconditionally calls `send_rewards_to_staker` at line 495 regardless of whether the staker has any unclaimed rewards:

```cairo
// src/staking/staking.cairo:492-495
// Send rewards to staker's reward address.
// It must be part of this function's flow because staker_info is about to be erased.
let token_dispatcher = strk_token_dispatcher();
self.send_rewards_to_staker(:staker_address, ref :staker_info, :token_dispatcher);
```

`send_rewards_to_staker` reads `staker_info.unclaimed_rewards_own` and calls `claim_from_reward_supplier`:

```cairo
// src/staking/staking.cairo:1621-1624
let amount = staker_info.unclaimed_rewards_own;
let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();
claim_from_reward_supplier(:reward_supplier_dispatcher, :amount, :token_dispatcher);
```

`claim_from_reward_supplier` (`src/staking/utils.cairo:50–60`) calls `reward_supplier.claim_rewards(amount)`, which executes a `checked_transfer` of STRK tokens from the reward supplier to the staking contract:

```cairo
// src/reward_supplier/reward_supplier.cairo:213-219
let unclaimed_rewards = self.unclaimed_rewards.read();
assert!(amount <= unclaimed_rewards, "{}", GenericError::AMOUNT_TOO_HIGH);
self.unclaimed_rewards.write(unclaimed_rewards - amount);
let token_dispatcher = self.token_dispatcher.read();
token_dispatcher.checked_transfer(recipient: staking_contract, amount: amount.into());
```

The `unclaimed_rewards` accounting counter is updated **immediately** when rewards are calculated via `update_unclaimed_rewards_from_staking_contract` (`src/reward_supplier/reward_supplier.cairo:189–202`), but the actual STRK tokens only arrive from L1 later via `on_receive`. This creates a persistent window where `unclaimed_rewards (accounting) > actual_token_balance`. During this window, `checked_transfer` panics, causing `unstake_action` to revert.

Critically, the staker cannot work around this by calling `claim_rewards` first to zero out `unclaimed_rewards_own`, because `claim_rewards` (`src/staking/staking.cairo:411–431`) also calls `send_rewards_to_staker` → `claim_from_reward_supplier`, which will fail for the same reason. There is no code path that allows a staker to retrieve their principal while bypassing reward claiming.

Additionally, `claim_from_reward_supplier` contains a second mandatory check:

```cairo
// src/staking/utils.cairo:58-59
assert!(balance_after - balance_before == amount.into(), "{}", Error::UNEXPECTED_BALANCE);
```

If the `checked_transfer` somehow partially succeeds or the balance arithmetic underflows, this check also reverts the transaction.

### Impact Explanation

A staker who has accumulated any non-zero `unclaimed_rewards_own` cannot call `unstake_action` to retrieve their staked principal while the reward supplier's actual STRK balance is below the owed amount. Both `unstake_action` and `claim_rewards` are blocked simultaneously. The staker's principal — which is entirely separate from rewards — is frozen until L1 minting replenishes the reward supplier. If L1 minting is delayed for an extended period (e.g., due to L1 congestion, bridge issues, or governance inaction), this constitutes **temporary freezing of funds** (staker principal + unclaimed rewards).

This maps to the allowed impact: **High — Temporary freezing of funds**.

### Likelihood Explanation

The reward supplier is designed to request L1 minting via `request_funds` when `unclaimed_rewards` exceeds a threshold. However, L1→L2 messaging on Starknet is inherently asynchronous and can take hours to days. During any period of high staking activity or L1 congestion, the reward supplier's actual balance will lag behind its `unclaimed_rewards` accounting. Any staker attempting to exit during this lag window is blocked. This is a normal operational condition, not a rare edge case.

### Recommendation

Decouple reward claiming from principal withdrawal in `unstake_action`. When a staker calls `unstake_action`, transfer the principal unconditionally and leave `unclaimed_rewards_own` intact in storage (or in a separate claimable record). Allow the staker to claim their rewards separately once the reward supplier is replenished. This mirrors the fix suggested in M-13: move the mandatory valuation check inside the conditional so that a full exit always succeeds.

### Proof of Concept

1. Staker accumulates rewards over several epochs: `staker_info.unclaimed_rewards_own = R > 0`.
2. Reward supplier's `unclaimed_rewards` counter = R (accounting is correct), but actual STRK balance = B where B < R (L1 minting request is in-flight).
3. Staker calls `unstake_intent()` — succeeds (no reward claiming here).
4. Exit wait window passes.
5. Staker calls `unstake_action(staker_address)`.
6. `send_rewards_to_staker` → `claim_from_reward_supplier(amount: R)` → `reward_supplier.claim_rewards(R)`.
7. Accounting check passes: `R <= R` ✓.
8. `checked_transfer(recipient: staking_contract, amount: R)` **panics** — reward supplier only holds B < R tokens.
9. `unstake_action` reverts. Staker's principal remains locked in the staking contract.
10. Staker attempts `claim_rewards` to zero out `unclaimed_rewards_own` first — same call path, same revert.
11. Staker has no remaining exit path until L1 minting fulfills the reward supplier balance. [1](#0-0) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** src/staking/utils.cairo (L50-60)
```text
pub(crate) fn claim_from_reward_supplier(
    reward_supplier_dispatcher: IRewardSupplierDispatcher,
    amount: Amount,
    token_dispatcher: IERC20Dispatcher,
) {
    let staking_contract = get_contract_address();
    let balance_before = token_dispatcher.balance_of(account: staking_contract);
    reward_supplier_dispatcher.claim_rewards(:amount);
    let balance_after = token_dispatcher.balance_of(account: staking_contract);
    assert!(balance_after - balance_before == amount.into(), "{}", Error::UNEXPECTED_BALANCE);
}
```

**File:** src/staking/staking.cairo (L483-515)
```text
        fn unstake_action(ref self: ContractState, staker_address: ContractAddress) -> Amount {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let mut staker_info = self.internal_staker_info(:staker_address);
            let unstake_time = staker_info
                .unstake_time
                .expect_with_err(Error::MISSING_UNSTAKE_INTENT);
            assert!(Time::now() >= unstake_time, "{}", GenericError::INTENT_WINDOW_NOT_FINISHED);

            // Send rewards to staker's reward address.
            // It must be part of this function's flow because staker_info is about to be erased.
            let token_dispatcher = strk_token_dispatcher();
            self.send_rewards_to_staker(:staker_address, ref :staker_info, :token_dispatcher);
            // Update staker info to storage (it will be erased later).
            // This is done here to avoid re-entrancy.
            self.write_staker_info(:staker_address, :staker_info);

            let staker_amount = self.get_own_balance(:staker_address).to_strk_native_amount();
            let staker_pool_info = self.staker_pool_info.entry(staker_address);
            self.remove_staker(:staker_address, :staker_info, :staker_pool_info);

            // Return stake to staker.
            token_dispatcher
                .checked_transfer(recipient: staker_address, amount: staker_amount.into());
            // Return delegated stake to pools and zero their balances.
            self
                .transfer_to_pools_when_unstake(
                    :staker_address, staker_pool_info: staker_pool_info.as_non_mut(),
                );
            // Clear staker pools.
            staker_pool_info.pools.clear();
            staker_amount
        }
```

**File:** src/staking/staking.cairo (L1614-1629)
```text
        fn send_rewards_to_staker(
            ref self: ContractState,
            staker_address: ContractAddress,
            ref staker_info: InternalStakerInfoLatest,
            token_dispatcher: IERC20Dispatcher,
        ) {
            let reward_address = staker_info.reward_address;
            let amount = staker_info.unclaimed_rewards_own;
            let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();

            claim_from_reward_supplier(:reward_supplier_dispatcher, :amount, :token_dispatcher);
            token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
            staker_info.unclaimed_rewards_own = Zero::zero();

            self.emit(Events::StakerRewardClaimed { staker_address, reward_address, amount });
        }
```

**File:** src/reward_supplier/reward_supplier.cairo (L189-220)
```text
        fn update_unclaimed_rewards_from_staking_contract(
            ref self: ContractState, rewards: Amount,
        ) {
            assert!(
                get_caller_address() == self.staking_contract.read(),
                "{}",
                GenericError::CALLER_IS_NOT_STAKING_CONTRACT,
            );

            let unclaimed_rewards = self.unclaimed_rewards.read() + rewards;
            self.unclaimed_rewards.write(unclaimed_rewards);
            // Request funds from L1 if needed.
            self.request_funds(:unclaimed_rewards);
        }

        // This function is called by the staking contract, claiming an amount of owed rewards.
        fn claim_rewards(ref self: ContractState, amount: Amount) {
            // Asserts.
            let staking_contract = self.staking_contract.read();
            assert!(
                get_caller_address() == staking_contract,
                "{}",
                GenericError::CALLER_IS_NOT_STAKING_CONTRACT,
            );
            let unclaimed_rewards = self.unclaimed_rewards.read();
            assert!(amount <= unclaimed_rewards, "{}", GenericError::AMOUNT_TOO_HIGH);

            // Update unclaimed_rewards and transfer the requested rewards to the staking contract.
            self.unclaimed_rewards.write(unclaimed_rewards - amount);
            let token_dispatcher = self.token_dispatcher.read();
            token_dispatcher.checked_transfer(recipient: staking_contract, amount: amount.into());
        }
```

**File:** src/reward_supplier/interface.cairo (L43-55)
```text
    /// Transfers the given `amount` (FRI) of rewards to the staking contract.
    ///
    /// #### Preconditions:
    /// - `reward_supplier.unclaimed_rewards >= amount`
    ///
    /// #### Errors:
    /// -
    /// [`CALLER_IS_NOT_STAKING_CONTRACT`](staking::errors::GenericError::CALLER_IS_NOT_STAKING_CONTRACT)
    /// - [`AMOUNT_TOO_HIGH`](staking::errors::GenericError::AMOUNT_TOO_HIGH)
    ///
    /// #### Access control:
    /// Only staking contract.
    fn claim_rewards(ref self: TContractState, amount: Amount);
```
