### Title
Pool Contract Reward Address Validation Only Checks Pool's Own Token, Allowing Permanent Freezing of Unclaimed Yield — (File: `src/pool/pool.cairo`)

---

### Summary

The `Pool` contract's `enter_delegation_pool` and `change_reward_address` functions validate the `reward_address` only against the pool's own token, not against all registered protocol tokens. For BTC pools, this allows a pool member to set their `reward_address` to the STRK token contract address. Since all pool rewards are always paid in STRK, calling `claim_rewards` will transfer STRK tokens into the STRK token contract itself, permanently locking them.

---

### Finding Description

In `staking.cairo`, `change_reward_address` uses `does_token_exist` to guard against any registered token being used as a reward address:

```cairo
// staking.cairo - change_reward_address
assert!(
    !self.does_token_exist(token_address: reward_address),
    "{}",
    GenericError::REWARD_ADDRESS_IS_TOKEN,
);
``` [1](#0-0) 

Where `does_token_exist` covers ALL registered tokens:

```cairo
fn does_token_exist(self: @ContractState, token_address: ContractAddress) -> bool {
    token_address == STRK_TOKEN_ADDRESS || self.btc_tokens.read(token_address).is_some()
}
``` [2](#0-1) 

In contrast, `pool.cairo`'s `change_reward_address` only checks against the pool's own token:

```cairo
// pool.cairo - change_reward_address
assert!(
    self.token_dispatcher.contract_address.read() != reward_address,
    "{}",
    GenericError::REWARD_ADDRESS_IS_TOKEN,
);
``` [3](#0-2) 

And `enter_delegation_pool` has the same partial check:

```cairo
assert!(token_address != pool_member, "{}", Error::POOL_MEMBER_IS_TOKEN);
assert!(token_address != reward_address, "{}", GenericError::REWARD_ADDRESS_IS_TOKEN);
``` [4](#0-3) 

For a BTC pool, `token_dispatcher.contract_address` is the BTC token. The check `reward_address != BTC_TOKEN_ADDRESS` passes freely when `reward_address = STRK_TOKEN_ADDRESS`. The pool member's record is written with `reward_address = STRK_TOKEN_ADDRESS`.

When `claim_rewards` is later called, rewards are unconditionally paid in STRK regardless of pool type:

```cairo
let reward_token = IERC20Dispatcher { contract_address: STRK_TOKEN_ADDRESS };
reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
``` [5](#0-4) 

This transfers STRK tokens into the STRK token contract itself. The STRK ERC20 contract has no mechanism to recover tokens sent to its own address, so those rewards are permanently locked.

---

### Impact Explanation

A BTC pool member who sets `reward_address = STRK_TOKEN_ADDRESS` (or any other registered token address that is not the pool's own token) will have all their accrued STRK rewards permanently locked inside the STRK token contract upon calling `claim_rewards`. This constitutes **permanent freezing of unclaimed yield**, matching the High impact category.

---

### Likelihood Explanation

The entry path is fully unprivileged. Any pool member of a BTC pool can call `enter_delegation_pool(reward_address: STRK_TOKEN_ADDRESS, amount)` or `change_reward_address(STRK_TOKEN_ADDRESS)` directly. No special role, leaked key, or external dependency is required. The STRK token contract address is a well-known constant (`STRK_TOKEN_ADDRESS`) in the codebase, making accidental or deliberate misuse realistic. [6](#0-5) 

---

### Recommendation

Replace the single-token check in `pool.cairo`'s `enter_delegation_pool` and `change_reward_address` with a call to the staking contract to verify the reward address is not any registered token. For example, expose `does_token_exist` via the staking interface and call it from the pool:

```cairo
// pool.cairo - change_reward_address (fixed)
let staking_dispatcher = IStakingDispatcher {
    contract_address: self.staking_pool_dispatcher.contract_address.read(),
};
assert!(
    !staking_dispatcher.does_token_exist(token_address: reward_address),
    "{}",
    GenericError::REWARD_ADDRESS_IS_TOKEN,
);
```

Apply the same fix to `enter_delegation_pool`. This mirrors the protection already present in `staking.cairo`.

---

### Proof of Concept

1. A staker calls `set_open_for_delegation(btc_token_address)` to deploy a BTC pool.
2. A pool member calls `pool.enter_delegation_pool(reward_address: STRK_TOKEN_ADDRESS, amount: X)`.
   - The check `btc_token_address != STRK_TOKEN_ADDRESS` passes — no revert.
   - Pool member record is stored with `reward_address = STRK_TOKEN_ADDRESS`.
3. Epochs pass; rewards accrue for the pool member.
4. Anyone calls `pool.claim_rewards(pool_member)`.
   - `checked_transfer(recipient: STRK_TOKEN_ADDRESS, amount: rewards)` executes successfully.
   - STRK rewards are deposited into the STRK token contract with no recovery path.
5. Pool member's unclaimed yield is permanently frozen. [7](#0-6) [8](#0-7)

### Citations

**File:** src/staking/staking.cairo (L12-12)
```text
    use staking::constants::{K, STARTING_EPOCH, STRK_TOKEN_ADDRESS};
```

**File:** src/staking/staking.cairo (L520-524)
```text
            assert!(
                !self.does_token_exist(token_address: reward_address),
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
```

**File:** src/staking/staking.cairo (L2227-2229)
```text
        fn does_token_exist(self: @ContractState, token_address: ContractAddress) -> bool {
            token_address == STRK_TOKEN_ADDRESS || self.btc_tokens.read(token_address).is_some()
        }
```

**File:** src/pool/pool.cairo (L182-219)
```text
        fn enter_delegation_pool(
            ref self: ContractState, reward_address: ContractAddress, amount: Amount,
        ) {
            // Asserts.
            self.assert_staker_is_active();
            let pool_member = get_caller_address();
            assert!(
                self.pool_member_info.read(pool_member).is_none(), "{}", Error::POOL_MEMBER_EXISTS,
            );
            assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);
            let token_dispatcher = self.token_dispatcher.read();
            let token_address = token_dispatcher.contract_address;
            assert!(token_address != pool_member, "{}", Error::POOL_MEMBER_IS_TOKEN);
            assert!(token_address != reward_address, "{}", GenericError::REWARD_ADDRESS_IS_TOKEN);
            // Transfer funds from the delegator to the staking contract.
            let staker_address = self.staker_address.read();
            transfer_from_delegator(:pool_member, :amount, :token_dispatcher);
            self.transfer_to_staking_contract(:amount, :token_dispatcher, :staker_address);

            self.set_member_balance(:pool_member, :amount);

            // Create the pool member record.
            self
                .pool_member_info
                .write(pool_member, VInternalPoolMemberInfoTrait::new_latest(:reward_address));

            // Emit events.
            self
                .emit(
                    Events::NewPoolMember { pool_member, staker_address, reward_address, amount },
                );
            self
                .emit(
                    Events::PoolMemberBalanceChanged {
                        pool_member, old_delegated_stake: Zero::zero(), new_delegated_stake: amount,
                    },
                );
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

**File:** src/pool/pool.cairo (L506-510)
```text
            assert!(
                self.token_dispatcher.contract_address.read() != reward_address,
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
```
