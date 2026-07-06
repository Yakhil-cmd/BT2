### Title
Push-Pattern Principal Withdrawal in `exit_delegation_pool_action` Permanently Freezes Pool Member Funds if Recipient Address Has Transfer Restrictions — (File: `src/pool/pool.cairo`)

---

### Summary

`exit_delegation_pool_action` uses a push pattern that unconditionally transfers the pool member's principal to the hardcoded `pool_member` address. There is no mechanism to specify an alternative recipient, and the `pool_member` address is immutable (only `reward_address` can be changed). If the `pool_member` address is subject to transfer restrictions in the staked token (e.g., a token with a blacklist added via `add_token`), the transfer will always revert, permanently freezing the pool member's principal inside the pool contract with no recovery path.

---

### Finding Description

In `exit_delegation_pool_action` (`src/pool/pool.cairo:295–333`), after the exit window has elapsed, the function transfers `unpool_amount` directly to `pool_member`:

```cairo
// Transfer delegated amount to the pool member.
let token_dispatcher = self.token_dispatcher.read();
token_dispatcher.checked_transfer(recipient: pool_member, amount: unpool_amount.into());
``` [1](#0-0) 

The `pool_member` address is the identity key for the pool member record and cannot be changed. The only address a pool member can update is their `reward_address` via `change_reward_address`:

```cairo
fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
    ...
    pool_member_info.reward_address = reward_address;
``` [2](#0-1) 

There is no analogous function to redirect the principal withdrawal to a different address. The `switch_delegation_pool` escape hatch also does not help: it requires the pool member to be in exit window and only moves funds to another pool of the **same token**, so a blacklisted address remains blacklisted regardless of which pool holds the funds. [3](#0-2) 

The Staking contract is explicitly designed to support multiple tokens beyond STRK, including BTC and any future token added by governance via `add_token`/`enable_token`. The pool's `token_dispatcher` is set at deployment time to whichever token the pool was opened for: [4](#0-3) 

If any supported token implements transfer restrictions (e.g., a compliance blacklist, a token pause, or a freeze mechanism), and the `pool_member` address falls under that restriction, `checked_transfer` will revert on every call to `exit_delegation_pool_action`. Because the state update (zeroing `unpool_amount` and `unpool_time`) and the transfer are in the same atomic transaction, the state is also reverted, leaving the pool member perpetually stuck in the exit window with no way to complete the withdrawal.

There is no admin rescue, emergency withdrawal, or governance override function in the Pool contract that could recover these funds. [5](#0-4) 

The same structural issue exists in `unstake_action` in the Staking contract, where `send_rewards_to_staker` transfers to `reward_address` (mitigated: changeable) and then the principal is transferred to `staker_address` (not mitigated: immutable): [6](#0-5) 

---

### Impact Explanation

A pool member whose address is subject to transfer restrictions in the staked token permanently loses access to their principal. The funds remain locked in the pool contract indefinitely. No governance, admin, or protocol mechanism can recover them. This constitutes permanent freezing of user funds (principal at-rest), mapping to **High** (permanent freezing of funds / temporary freezing of funds) and potentially **Critical** (direct theft of user funds at-rest, since permanent inaccessibility is economically equivalent to loss).

---

### Likelihood Explanation

The Staking protocol is explicitly multi-token: governance can add arbitrary ERC20 tokens via `add_token`. Any token with a blacklist, freeze, or pause mechanism (common in regulated or compliance-oriented tokens) triggers this path. The pool member's address becoming restricted is an external event (regulatory action, sanctions, token-admin decision), but the internal design choice — push-only withdrawal with no alternative recipient — is the necessary co-cause that converts a temporary restriction into a permanent fund freeze. Likelihood is **Low-Medium**: it requires a token with transfer restrictions to be listed and a pool member's address to be restricted, but both conditions are realistic over the protocol's lifetime.

---

### Recommendation

Implement a pull pattern for principal withdrawals in `exit_delegation_pool_action`. Instead of pushing tokens to `pool_member` immediately, record the claimable amount in a storage mapping keyed by `pool_member`. Add a separate `withdraw_funds(recipient: ContractAddress)` function callable only by the pool member (or their reward address) that allows specifying an arbitrary recipient. This mirrors the fix described in the external report and decouples the accounting step (burning the exit intent) from the token transfer step.

---

### Proof of Concept

1. Governance adds a token `T` (with a blacklist) to the staking protocol via `add_token` / `enable_token`.
2. Staker opens a delegation pool for token `T` via `set_open_for_delegation`.
3. Alice (address `A`) delegates `N` units of `T` to the pool via `enter_delegation_pool` / `add_to_delegation_pool`.
4. Alice calls `exit_delegation_pool_intent(amount: N)`. The exit window starts.
5. Token `T`'s admin blacklists address `A`.
6. After the exit window elapses, anyone calls `exit_delegation_pool_action(pool_member: A)`.
7. Inside the function, `token_dispatcher.checked_transfer(recipient: A, amount: N)` reverts because `A` is blacklisted.
8. The entire transaction reverts; `unpool_amount` and `unpool_time` are restored.
9. Step 6–8 repeats forever. Alice's `N` tokens are permanently frozen in the pool contract.
10. `switch_delegation_pool` cannot help: it only moves to another pool of token `T`, and `A` remains blacklisted in `T`.
11. `change_reward_address` cannot help: it only redirects reward transfers, not principal withdrawals. [5](#0-4) [3](#0-2) [7](#0-6)

### Citations

**File:** src/pool/pool.cairo (L295-333)
```text
        fn exit_delegation_pool_action(
            ref self: ContractState, pool_member: ContractAddress,
        ) -> Amount {
            // Asserts.
            let mut pool_member_info = self.internal_pool_member_info(:pool_member);
            let unpool_time = pool_member_info
                .unpool_time
                .expect_with_err(GenericError::MISSING_UNDELEGATE_INTENT);
            assert!(Time::now() >= unpool_time, "{}", GenericError::INTENT_WINDOW_NOT_FINISHED);

            // Emit event.
            self
                .emit(
                    Events::PoolMemberExitAction {
                        pool_member, unpool_amount: pool_member_info.unpool_amount,
                    },
                );

            // Perform removal action in the staking contract, receiving funds if needed.
            // Note that if the intent was done after the staker was removed (unstake_action),
            // the funds will already be in the pool contract, and the following call will do
            // nothing.
            let staking_pool_dispatcher = self.staking_pool_dispatcher.read();
            staking_pool_dispatcher
                .remove_from_delegation_pool_action(identifier: pool_member.into());

            let unpool_amount = pool_member_info.unpool_amount;
            pool_member_info.unpool_amount = Zero::zero();
            pool_member_info.unpool_time = Option::None;

            // Write the updated pool member info to storage.
            self.write_pool_member_info(:pool_member, :pool_member_info);

            // Transfer delegated amount to the pool member.
            let token_dispatcher = self.token_dispatcher.read();
            token_dispatcher.checked_transfer(recipient: pool_member, amount: unpool_amount.into());

            unpool_amount
        }
```

**File:** src/pool/pool.cairo (L379-428)
```text
        fn switch_delegation_pool(
            ref self: ContractState,
            to_staker: ContractAddress,
            to_pool: ContractAddress,
            amount: Amount,
        ) -> Amount {
            // Asserts.
            assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);
            let pool_member = get_caller_address();
            let mut pool_member_info = self.internal_pool_member_info(:pool_member);
            assert!(
                pool_member_info.unpool_time.is_some(),
                "{}",
                GenericError::MISSING_UNDELEGATE_INTENT,
            );
            assert!(amount <= pool_member_info.unpool_amount, "{}", GenericError::AMOUNT_TOO_HIGH);
            let reward_address = pool_member_info.reward_address;

            // Update pool_member_info and write to storage.
            pool_member_info.unpool_amount -= amount;
            if pool_member_info.unpool_amount.is_zero() {
                // unpool_amount is zero, clear unpool_time.
                pool_member_info.unpool_time = Option::None;
            }
            self.write_pool_member_info(:pool_member, :pool_member_info);

            // Serialize the switch pool data and invoke the staking contract to switch pool.
            let switch_pool_data = SwitchPoolData { pool_member, reward_address };
            let mut serialized_data = array![];
            switch_pool_data.serialize(ref output: serialized_data);
            self
                .staking_pool_dispatcher
                .read()
                .switch_staking_delegation_pool(
                    :to_staker,
                    :to_pool,
                    switched_amount: amount,
                    data: serialized_data.span(),
                    identifier: pool_member.into(),
                );

            // Emit event.
            self
                .emit(
                    Events::SwitchDelegationPool {
                        pool_member, new_delegation_pool: to_pool, amount,
                    },
                );

            pool_member_info.unpool_amount
```

**File:** src/pool/pool.cairo (L505-526)
```text
        fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
            assert!(
                self.token_dispatcher.contract_address.read() != reward_address,
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
            let pool_member = get_caller_address();
            let mut pool_member_info = self.internal_pool_member_info(:pool_member);
            let old_address = pool_member_info.reward_address;

            // Update reward_address and commit to storage.
            pool_member_info.reward_address = reward_address;
            self.write_pool_member_info(:pool_member, :pool_member_info);

            // Emit event.
            self
                .emit(
                    Events::PoolMemberRewardAddressChanged {
                        pool_member, new_address: reward_address, old_address,
                    },
                );
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
