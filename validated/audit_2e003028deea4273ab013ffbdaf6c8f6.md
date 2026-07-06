### Title
Missing Zero Address Check for `reward_address` Allows Permanent Freezing of Unclaimed Yield - (`src/staking/staking.cairo`, `src/pool/pool.cairo`)

---

### Summary

Both the staking contract and the pool contract accept a `reward_address` parameter in their registration and update functions without validating that it is non-zero. A staker or pool member can set their `reward_address` to the zero address, causing all accumulated rewards to be permanently unclaimable (either burned or reverting on every claim attempt).

---

### Finding Description

Four entry points accept `reward_address` without a zero-address check:

**1. `staking.cairo` — `stake()`**
The `reward_address` parameter is only validated against the token-address registry. No zero check exists. [1](#0-0) 

**2. `staking.cairo` — `change_reward_address()`**
The setter for an existing staker's reward address performs only a token-address check, not a zero check. [2](#0-1) 

**3. `pool.cairo` — `enter_delegation_pool()`**
The `reward_address` parameter is only checked against the pool's token address. [3](#0-2) 

**4. `pool.cairo` — `change_reward_address()`**
The pool-member reward address setter performs only a token-address check. [4](#0-3) 

In all four cases, the zero address (`0x0`) passes every existing assertion because it is not a registered token address.

---

### Impact Explanation

When `claim_rewards` is called on the pool contract, accumulated rewards are transferred directly to the stored `reward_address`:

```
reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
``` [5](#0-4) 

If `reward_address` is the zero address, the transfer either:
- **Burns the tokens** (if the STRK ERC20 allows transfers to address 0), or
- **Reverts on every call** (if the ERC20 rejects zero-address recipients), permanently freezing the unclaimed yield with no recovery path.

The same applies to the staking contract's own `claim_rewards` path, which transfers to the staker's stored `reward_address`. Once set to zero, the address cannot be changed back by anyone other than the staker — but if the staker made the mistake, they can call `change_reward_address` again to fix it. However, any rewards already accrued and sent to address 0 during the window are permanently lost.

**Impact class:** High — Permanent freezing of unclaimed yield / theft of unclaimed yield (tokens sent to address 0 are irrecoverable).

---

### Likelihood Explanation

The entry path is fully unprivileged: any staker or pool member can call `stake()`, `enter_delegation_pool()`, or `change_reward_address()`. The most realistic scenario is an accidental misconfiguration (passing a zero address by mistake), which is exactly the scenario the original report describes. The `change_reward_address` variant is particularly dangerous because it can silently redirect all future rewards for an already-active staker with accumulated balance.

---

### Recommendation

Add a non-zero assertion for `reward_address` in all four entry points. The codebase already defines a `ZERO_ADDRESS` error string: [6](#0-5) 

Apply the pattern already used for caller validation: [7](#0-6) 

Concretely, add before each `reward_address` write:
```cairo
assert!(reward_address.is_non_zero(), "{}", Error::ZERO_ADDRESS);
```

This should be applied in:
- `staking.cairo` → `stake()` [8](#0-7) 
- `staking.cairo` → `change_reward_address()` [2](#0-1) 
- `pool.cairo` → `enter_delegation_pool()` [3](#0-2) 
- `pool.cairo` → `change_reward_address()` [4](#0-3) 

---

### Proof of Concept

**Staker path:**
1. Staker calls `staking.stake(reward_address: 0x0, operational_address: <valid>, amount: <min_stake>)`.
2. All assertions pass — `0x0` is not a registered token address.
3. Staker accumulates rewards over epochs.
4. Staker (or anyone) calls `claim_rewards(staker_address)`.
5. The contract attempts `checked_transfer(recipient: 0x0, amount: rewards)` → tokens are burned or the call reverts permanently.

**Pool member path:**
1. Pool member calls `pool.enter_delegation_pool(reward_address: 0x0, amount: <valid>)`.
2. All assertions pass — `0x0 != token_address`.
3. Pool member accumulates rewards.
4. `claim_rewards(pool_member)` transfers to `0x0` → yield permanently lost. [9](#0-8)

### Citations

**File:** src/staking/staking.cairo (L307-317)
```text
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

**File:** src/pool/pool.cairo (L192-195)
```text
            let token_dispatcher = self.token_dispatcher.read();
            let token_address = token_dispatcher.contract_address;
            assert!(token_address != pool_member, "{}", Error::POOL_MEMBER_IS_TOKEN);
            assert!(token_address != reward_address, "{}", GenericError::REWARD_ADDRESS_IS_TOKEN);
```

**File:** src/pool/pool.cairo (L335-376)
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
```

**File:** src/pool/pool.cairo (L505-510)
```text
        fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
            assert!(
                self.token_dispatcher.contract_address.read() != reward_address,
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
```

**File:** docs/spec.md (L2822-2823)
```markdown
### ZERO_ADDRESS
"Zero address"
```

**File:** src/staking/utils.cairo (L62-64)
```text
pub(crate) fn assert_caller_is_not_zero() {
    assert!(get_caller_address().is_non_zero(), "{}", Error::CALLER_IS_ZERO_ADDRESS);
}
```
