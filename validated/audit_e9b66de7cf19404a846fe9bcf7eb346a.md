### Title
Missing Zero-Address Validation in `change_reward_address` Allows Permanent Freezing of Unclaimed Yield and Temporary Freezing of Staker Funds - (File: src/staking/staking.cairo, src/pool/pool.cairo)

---

### Summary

Both `Staking.change_reward_address` and `Pool.change_reward_address` accept a zero address as the new `reward_address` without validation. Because `reward_address` is the destination for all reward transfers and is also used in the `unstake_action` flow, setting it to zero causes all reward-claiming and unstaking operations to revert, freezing unclaimed yield and temporarily locking staked principal.

---

### Finding Description

**`Staking.change_reward_address`** (src/staking/staking.cairo, line 517) only validates that `reward_address` is not a registered token address. There is no check that it is non-zero:

```cairo
fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
    self.general_prerequisites();
    assert!(
        !self.does_token_exist(token_address: reward_address),
        "{}",
        GenericError::REWARD_ADDRESS_IS_TOKEN,
    );
    let staker_address = get_caller_address();
    let mut staker_info = self.internal_staker_info(:staker_address);
    staker_info.reward_address = reward_address;   // zero accepted here
    self.write_staker_info(:staker_address, :staker_info);
    ...
}
``` [1](#0-0) 

The same pattern exists in **`Pool.change_reward_address`** (src/pool/pool.cairo, line 505):

```cairo
fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
    assert!(
        self.token_dispatcher.contract_address.read() != reward_address,
        "{}",
        GenericError::REWARD_ADDRESS_IS_TOKEN,
    );
    let pool_member = get_caller_address();
    let mut pool_member_info = self.internal_pool_member_info(:pool_member);
    pool_member_info.reward_address = reward_address;  // zero accepted here
    ...
}
``` [2](#0-1) 

The zero `reward_address` is then used as the recipient in `send_rewards_to_staker`:

```cairo
fn send_rewards_to_staker(...) {
    let reward_address = staker_info.reward_address;
    let amount = staker_info.unclaimed_rewards_own;
    claim_from_reward_supplier(:reward_supplier_dispatcher, :amount, :token_dispatcher);
    token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
    ...
}
``` [3](#0-2) 

And in `Pool.claim_rewards`:

```cairo
reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
``` [4](#0-3) 

The OpenZeppelin ERC20 implementation on Starknet rejects transfers to the zero address, so `checked_transfer(recipient: 0x0, ...)` reverts whenever `amount > 0`.

---

### Impact Explanation

**Staking contract path:**

`unstake_action` unconditionally calls `send_rewards_to_staker` before returning the principal:

```cairo
self.send_rewards_to_staker(:staker_address, ref :staker_info, :token_dispatcher);
...
token_dispatcher.checked_transfer(recipient: staker_address, amount: staker_amount.into());
``` [5](#0-4) 

If `reward_address == 0x0` and `unclaimed_rewards_own > 0`, the `checked_transfer` inside `send_rewards_to_staker` reverts, causing `unstake_action` to revert entirely. The staker's principal remains locked in the contract. This constitutes **temporary freezing of funds** (High).

`claim_rewards` also reverts for the same reason, constituting **permanent freezing of unclaimed yield** until the address is corrected (High). [6](#0-5) 

**Pool contract path:**

`Pool.claim_rewards` transfers directly to `reward_address`. With a zero address, all reward claims revert, freezing unclaimed yield for the pool member. [7](#0-6) 

---

### Likelihood Explanation

Any active staker or pool member can call `change_reward_address(0x0)` directly — no privilege is required. The initial `stake` call also accepts zero `reward_address` without validation, meaning a staker can enter this broken state from the very first transaction. The freeze persists until the user calls `change_reward_address` again with a valid address; however, if the user is unaware of the cause (e.g., a scripting error or front-end bug passes zero), the funds and yield remain inaccessible for an indefinite period. [8](#0-7) 

---

### Recommendation

Add a non-zero address assertion in both `change_reward_address` implementations and in the initial `stake` / `enter_delegation_pool` entry points:

```cairo
// In Staking.change_reward_address and Pool.change_reward_address:
assert!(reward_address.is_non_zero(), "Reward address cannot be zero");
```

Apply the same guard to the `reward_address` parameter of `stake` in `staking.cairo` and `enter_delegation_pool` in `pool.cairo`.

---

### Proof of Concept

1. Staker calls `staking.stake(reward_address: 0x0, operational_address: X, amount: MIN_STAKE)`.
   - Accepted — no zero-address check on `reward_address`.
2. Several epochs pass; rewards accumulate in `staker_info.unclaimed_rewards_own`.
3. Staker calls `staking.unstake_intent()` — succeeds.
4. After the exit window, staker calls `staking.unstake_action(staker_address)`.
   - Internally calls `send_rewards_to_staker`, which calls `checked_transfer(recipient: 0x0, amount: rewards)`.
   - ERC20 reverts on zero-address recipient → entire `unstake_action` reverts.
5. Staker's principal remains locked. `claim_rewards` also reverts for the same reason.
6. The staker must call `change_reward_address(valid_address)` to recover — but if the user does not understand the root cause, the funds remain frozen indefinitely. [9](#0-8) [10](#0-9)

### Citations

**File:** src/staking/staking.cairo (L288-317)
```text
        fn stake(
            ref self: ContractState,
            reward_address: ContractAddress,
            operational_address: ContractAddress,
            amount: Amount,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let staker_address = get_caller_address();
            assert!(self.staker_info.read(staker_address).is_none(), "{}", Error::STAKER_EXISTS);
            assert!(
                self.operational_address_to_staker_address.read(operational_address).is_zero(),
                "{}",
                Error::OPERATIONAL_EXISTS,
            );
            self.assert_staker_address_not_reused(:staker_address);
            assert!(
                !self.does_token_exist(token_address: staker_address), "{}", Error::STAKER_IS_TOKEN,
            );
            assert!(
                !self.does_token_exist(token_address: reward_address),
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
            assert!(
                !self.does_token_exist(token_address: operational_address),
                "{}",
                Error::OPERATIONAL_IS_TOKEN,
            );
            assert!(amount >= self.min_stake.read(), "{}", Error::AMOUNT_LESS_THAN_MIN_STAKE);
```

**File:** src/staking/staking.cairo (L411-431)
```text
        fn claim_rewards(ref self: ContractState, staker_address: ContractAddress) -> Amount {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let mut staker_info = self.internal_staker_info(:staker_address);
            let caller_address = get_caller_address();
            let reward_address = staker_info.reward_address;
            assert!(
                caller_address == staker_address || caller_address == reward_address,
                "{}",
                Error::CLAIM_REWARDS_FROM_UNAUTHORIZED_ADDRESS,
            );

            // Transfer rewards to staker's reward address and write updated staker info to storage.
            // Note: `send_rewards_to_staker` alters `staker_info` thus commit to storage is
            // performed only after that.
            let amount = staker_info.unclaimed_rewards_own;
            let token_dispatcher = strk_token_dispatcher();
            self.send_rewards_to_staker(:staker_address, ref :staker_info, :token_dispatcher);
            self.write_staker_info(:staker_address, :staker_info);
            amount
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
