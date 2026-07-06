### Title
Missing Zero Address Check in `change_reward_address` Allows Permanent Burning of Unclaimed Yield - (File: src/staking/staking.cairo, src/pool/pool.cairo)

### Summary
Both `staking::change_reward_address` and `pool::change_reward_address` accept a zero address as the new `reward_address` without validation. Any staker or pool member can set their reward address to `0x0`, causing all subsequent reward transfers to be sent to the zero address — permanently burning unclaimed yield.

### Finding Description
`change_reward_address` in `src/staking/staking.cairo` performs only one validation on the incoming address: it must not be a registered token address. There is no check that `reward_address.is_non_zero()`. [1](#0-0) 

The identical gap exists in the pool contract: [2](#0-1) 

Once `reward_address` is written as zero, every downstream reward-transfer path uses it directly without re-validating:

- `send_rewards_to_staker` (called by `claim_rewards` and `unstake_action`) reads `staker_info.reward_address` and calls `checked_transfer(recipient: reward_address, ...)`: [3](#0-2) 

- `pool::claim_rewards` reads `pool_member_info.reward_address` and calls `checked_transfer(recipient: reward_address, ...)`: [4](#0-3) 

If the underlying ERC20 permits transfers to the zero address, the tokens are silently burned. If it reverts, `claim_rewards` and `unstake_action` become uncallable until the address is corrected — temporarily freezing all accrued yield and the principal exit flow.

The same missing check exists at initial entry points (`stake` and `enter_delegation_pool`), meaning a user can register with a zero reward address from the start: [5](#0-4) [6](#0-5) 

### Impact Explanation
**High — Permanent freezing / burning of unclaimed yield.**

If the ERC20 token allows transfers to address zero, every reward token sent via `claim_rewards` or `unstake_action` while `reward_address == 0` is irreversibly destroyed. If the ERC20 reverts on zero-address transfers, `unstake_action` (which calls `send_rewards_to_staker` atomically before returning principal) becomes permanently reverting, freezing both yield and the staker's principal in the exit window until the address is corrected.

### Likelihood Explanation
**Low-to-Medium.** Any registered staker or pool member can trigger this with a single call. It is most likely to occur through a user error (e.g., passing an uninitialized variable), but a malicious actor could also deliberately set their own reward address to zero to grief the protocol's accounting or to permanently burn yield they no longer want tracked.

### Recommendation
Add an explicit non-zero check in both `change_reward_address` implementations and in `stake` / `enter_delegation_pool`:

```cairo
assert!(reward_address.is_non_zero(), "{}", GenericError::ZERO_ADDRESS);
```

This mirrors the pattern already used elsewhere in the codebase (e.g., `add_token` asserts `ZERO_ADDRESS`): [7](#0-6) 

### Proof of Concept

1. A staker is registered and has accrued rewards.
2. The staker calls `staking.change_reward_address(reward_address: 0x0)`. No assertion fires — only the token-address check is present, and `0x0` is not a token.
3. The staker (or anyone) calls `staking.claim_rewards(staker_address)`.
4. `send_rewards_to_staker` executes `token_dispatcher.checked_transfer(recipient: 0x0, amount: rewards)`.
   - If the ERC20 allows zero-address transfers → rewards are burned permanently.
   - If the ERC20 reverts → `claim_rewards` and `unstake_action` both revert, freezing yield and blocking principal withdrawal until `change_reward_address` is called again with a valid address.

The same sequence applies to a pool member via `pool.change_reward_address(0x0)` followed by `pool.claim_rewards`.

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

**File:** src/staking/staking.cairo (L1620-1626)
```text
            let reward_address = staker_info.reward_address;
            let amount = staker_info.unclaimed_rewards_own;
            let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();

            claim_from_reward_supplier(:reward_supplier_dispatcher, :amount, :token_dispatcher);
            token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
            staker_info.unclaimed_rewards_own = Zero::zero();
```

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

**File:** src/pool/pool.cairo (L339-366)
```text
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
