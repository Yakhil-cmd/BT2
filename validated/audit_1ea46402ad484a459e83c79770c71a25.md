### Title
Missing Zero-Address Validation in `change_reward_address` Enables Permanent Freezing of Unclaimed Yield — (File: src/pool/pool.cairo, src/staking/staking.cairo)

---

### Summary

Both the Pool and Staking contracts allow a staker or pool member to set their `reward_address` to the zero address (`0x0`). Because all reward transfers are unconditionally sent to the stored `reward_address`, any rewards claimed while that field is zero are permanently unrecoverable — either reverting (freezing) or burning to the zero address. No zero-address guard exists in `change_reward_address`, `enter_delegation_pool`, or `stake`.

---

### Finding Description

**Vulnerability class:** Missing parameter validation / reward misrouting (state-transition bug)

In `pool.cairo` the only guard in `change_reward_address` is:

```cairo
assert!(
    self.token_dispatcher.contract_address.read() != reward_address,
    "{}",
    GenericError::REWARD_ADDRESS_IS_TOKEN,
);
``` [1](#0-0) 

In `staking.cairo` the only guard is:

```cairo
assert!(
    !self.does_token_exist(token_address: reward_address),
    "{}",
    GenericError::REWARD_ADDRESS_IS_TOKEN,
);
``` [2](#0-1) 

Neither function checks `reward_address.is_non_zero()`. The same omission exists in the initial-entry paths `enter_delegation_pool` and `stake`. [3](#0-2) [4](#0-3) 

When `claim_rewards` executes, it unconditionally transfers to whatever `reward_address` is stored:

```cairo
reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
``` [5](#0-4) 

If `reward_address` is zero, the transfer either reverts (permanently freezing the yield in the contract) or succeeds and burns the tokens to the zero address — both outcomes are irreversible for those specific reward tokens.

---

### Impact Explanation

**Allowed impact matched:** *Permanent freezing of unclaimed yield* (High).

Any rewards accrued and claimed while `reward_address == 0` are permanently lost. The pool member or staker cannot recover those specific tokens; they can only fix the address going forward. The staking contract holds no rescue mechanism for tokens sent to the zero address.

---

### Likelihood Explanation

The analog to the external report is direct: a malicious or buggy frontend (the "dApp" in the MetaMask Snap report) can submit a `change_reward_address` call with a zero or attacker-controlled address without surfacing the actual destination to the user. Because the smart contract performs no validation beyond "not a token address," the contract itself is the necessary vulnerable step — it is the last line of defense and it fails. Additionally, a user copy-paste error or a UI that pre-fills an empty field can trigger this without any adversarial frontend. The function is callable by any pool member or staker with no privileged role required. [6](#0-5) [7](#0-6) 

---

### Recommendation

Add a non-zero assertion in every function that writes `reward_address` to storage:

```cairo
assert!(reward_address.is_non_zero(), "Reward address cannot be zero");
```

Apply this to `change_reward_address` in both `pool.cairo` and `staking.cairo`, and to the initial-entry functions `enter_delegation_pool` and `stake`.

---

### Proof of Concept

1. Pool member `P` calls `pool.change_reward_address(reward_address: 0)`.  
   — The only check (`token_address != reward_address`) passes because `0 != token_address`.  
   — `pool_member_info.reward_address` is now `0`. [8](#0-7) 

2. Rewards accrue over subsequent epochs via `update_rewards_from_staking_contract`.

3. Anyone (including `P` themselves) calls `pool.claim_rewards(pool_member: P)`.  
   — The authorization check passes because `caller == pool_member`.  
   — `reward_token.checked_transfer(recipient: 0, amount: rewards)` executes. [9](#0-8) 

4. The STRK ERC-20 either reverts (rewards permanently frozen in the pool contract) or transfers to the zero address (rewards permanently burned). Either way, `P`'s accrued yield is unrecoverable.

### Citations

**File:** src/pool/pool.cairo (L182-195)
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
```

**File:** src/pool/pool.cairo (L335-366)
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

**File:** src/staking/staking.cairo (L301-317)
```text
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

**File:** src/staking/staking.cairo (L517-540)
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

            // Emit event.
            self
                .emit(
                    Events::StakerRewardAddressChanged {
                        staker_address, new_address: reward_address, old_address,
                    },
                );
        }
```
