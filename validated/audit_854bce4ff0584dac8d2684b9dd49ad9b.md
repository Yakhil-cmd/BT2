### Title
Missing Zero-Address Validation in `change_reward_address` Enables Temporary Freezing of Staker Principal via DoS on `unstake_action` - (File: src/staking/staking.cairo, src/pool/pool.cairo)

---

### Summary

Both `change_reward_address` functions in `staking.cairo` and `pool.cairo` accept `address(0)` as a valid reward address. Because `unstake_action` unconditionally calls `send_rewards_to_staker`, which calls `checked_transfer(recipient: reward_address, ...)`, setting the reward address to zero causes `unstake_action` to revert on every call. This temporarily freezes the staker's principal inside the staking contract until the reward address is corrected.

---

### Finding Description

`change_reward_address` in `staking.cairo` only validates that the new address is not a registered token address:

```cairo
// src/staking/staking.cairo:517-531
fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
    self.general_prerequisites();
    assert!(
        !self.does_token_exist(token_address: reward_address),
        "{}",
        GenericError::REWARD_ADDRESS_IS_TOKEN,
    );
    ...
    staker_info.reward_address = reward_address;
    self.write_staker_info(:staker_address, :staker_info);
```

There is no `assert!(reward_address.is_non_zero(), ...)` guard. The same omission exists in `pool.cairo`:

```cairo
// src/pool/pool.cairo:505-517
fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
    assert!(
        self.token_dispatcher.contract_address.read() != reward_address,
        "{}",
        GenericError::REWARD_ADDRESS_IS_TOKEN,
    );
    ...
    pool_member_info.reward_address = reward_address;
```

`unstake_action` calls `send_rewards_to_staker` unconditionally before returning the principal:

```cairo
// src/staking/staking.cairo:494-495
let token_dispatcher = strk_token_dispatcher();
self.send_rewards_to_staker(:staker_address, ref :staker_info, :token_dispatcher);
```

`send_rewards_to_staker` calls `checked_transfer` to the stored `reward_address`:

```cairo
// src/staking/staking.cairo:1624-1625
claim_from_reward_supplier(:reward_supplier_dispatcher, :amount, :token_dispatcher);
token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
```

OpenZeppelin Cairo ERC20's `_transfer` rejects the zero address as recipient unconditionally (before any amount check). Therefore, if `reward_address` is `address(0)`, `checked_transfer` reverts, causing the entire `unstake_action` call to revert.

---

### Impact Explanation

A staker who has called `unstake_intent` and is waiting out the exit window can call `change_reward_address(0)` at any point — including during the exit window, since `change_reward_address` has no guard against being in an exit window. After the exit window expires, every call to `unstake_action(staker_address)` reverts. The staker's principal (potentially millions of STRK) is frozen inside the staking contract until the reward address is corrected. This matches **Temporary freezing of funds** (High).

For pool members, `claim_rewards` in `pool.cairo` similarly calls `checked_transfer(recipient: reward_address, ...)` and reverts if `reward_address` is zero, permanently freezing unclaimed yield until the address is corrected. This matches **Permanent freezing of unclaimed yield** (High).

---

### Likelihood Explanation

Any active staker or pool member can call `change_reward_address` at any time with no preconditions beyond being a registered participant. The call requires no special privilege. A staker who is a smart contract (e.g., a multisig or DAO contract) that inadvertently sets reward address to zero — or a staker who deliberately self-griefs — triggers this path. The entry point is fully unprivileged and reachable by any staker or delegator.

---

### Recommendation

Add a non-zero address assertion in both `change_reward_address` implementations:

In `src/staking/staking.cairo` (`change_reward_address`):
```cairo
assert!(reward_address.is_non_zero(), "{}", GenericError::ZERO_ADDRESS);
```

In `src/pool/pool.cairo` (`change_reward_address`):
```cairo
assert!(reward_address.is_non_zero(), "{}", GenericError::ZERO_ADDRESS);
```

The `ZERO_ADDRESS` error string already exists in the protocol's error catalogue (`docs/spec.md` line 2822–2823).

Additionally, apply the same guard at initial `stake()` and `enter_delegation_pool()` call sites where `reward_address` is first recorded.

---

### Proof of Concept

1. Staker calls `stake(reward_address: VALID, ...)` and accrues rewards over several epochs.
2. Staker calls `unstake_intent()`. Exit window begins (default: 1 week).
3. During the exit window, staker calls `change_reward_address(reward_address: 0)`.
   - Passes: `does_token_exist(0)` returns `false` (zero address is not a registered token).
   - `staker_info.reward_address` is now `0`.
4. Exit window expires. Any caller invokes `unstake_action(staker_address)`.
5. `unstake_action` calls `send_rewards_to_staker` → `checked_transfer(recipient: 0, amount: unclaimed_rewards)`.
6. OpenZeppelin ERC20 reverts: `"ERC20: transfer to the zero address"`.
7. `unstake_action` reverts. The staker's principal remains locked in the staking contract.
8. The staker must call `change_reward_address(valid_address)` to unblock `unstake_action`.

**Affected functions and lines:**

- `change_reward_address` (missing zero check): [1](#0-0) 
- `change_reward_address` in pool (missing zero check): [2](#0-1) 
- `send_rewards_to_staker` (unconditional transfer to reward_address): [3](#0-2) 
- `unstake_action` (calls send_rewards_to_staker before returning principal): [4](#0-3) 
- `pool.claim_rewards` (direct transfer to reward_address): [5](#0-4)

### Citations

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

**File:** src/staking/staking.cairo (L517-531)
```text
        fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(
                !self.does_token_exist(token_address: reward_address),
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
            let staker_address = get_caller_address();
            let mut staker_info = self.internal_staker_info(:staker_address);
            let old_address = staker_info.reward_address;

            // Update reward_address and commit to storage.
            staker_info.reward_address = reward_address;
            self.write_staker_info(:staker_address, :staker_info);
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

**File:** src/pool/pool.cairo (L335-377)
```text
        fn claim_rewards(ref self: ContractState, pool_member: ContractAddress) -> Amount {
            // Asserts.
            let mut pool_member_info = self.internal_pool_member_info(:pool_member);
            let caller_address = get_caller_address();
            let reward_address = pool_member_info.reward_address;
            assert!(
                caller_address == pool_member || caller_address == reward_address,
                "{}",
                Error::POOL_CLAIM_REWARDS_FROM_UNAUTHORIZED_ADDRESS,
            );

            let until_checkpoint = self.get_current_checkpoint(:pool_member);

            // Calculate rewards and update entry_to_claim_from.
            let (mut rewards, updated_entry_to_claim_from) = self
                .calculate_rewards(
                    :pool_member,
                    from_checkpoint: pool_member_info.reward_checkpoint,
                    :until_checkpoint,
                    entry_to_claim_from: pool_member_info.entry_to_claim_from,
                );
            rewards += pool_member_info._unclaimed_rewards_from_v0;
            pool_member_info._unclaimed_rewards_from_v0 = Zero::zero();
            pool_member_info.entry_to_claim_from = updated_entry_to_claim_from;
            pool_member_info.reward_checkpoint = until_checkpoint;

            // Write the updated pool member info to storage.
            self.write_pool_member_info(:pool_member, :pool_member_info);

            // Transfer rewards to the pool member.
            let reward_token = IERC20Dispatcher { contract_address: STRK_TOKEN_ADDRESS };
            reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());

            // Emit event.
            self
                .emit(
                    Events::PoolMemberRewardClaimed {
                        pool_member, reward_address, amount: rewards,
                    },
                );

            rewards
        }
```

**File:** src/pool/pool.cairo (L505-517)
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
```
