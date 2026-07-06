### Title
Missing Zero-Address Validation for `reward_address` Allows Permanent Loss of Unclaimed Yield - (File: src/staking/staking.cairo, src/pool/pool.cairo)

### Summary
Neither `stake()` nor `change_reward_address()` in `staking.cairo`, nor `enter_delegation_pool()` nor `change_reward_address()` in `pool.cairo`, validate that the supplied `reward_address` is non-zero. Because all reward transfers are sent unconditionally to the stored `reward_address`, setting it to the zero address permanently destroys all future unclaimed yield for the affected staker or pool member.

### Finding Description
`stake()` in `staking.cairo` accepts `reward_address` and stores it without a zero-address check:

```
assert!(!self.does_token_exist(token_address: reward_address), ...) // only token check
// NO: assert!(reward_address.is_non_zero(), ...)
```

`change_reward_address()` in `staking.cairo` has the same gap — it only guards against the token address, not the zero address:

```cairo
fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
    self.general_prerequisites();
    assert!(!self.does_token_exist(token_address: reward_address), ..., REWARD_ADDRESS_IS_TOKEN);
    // reward_address == 0 is accepted here
    staker_info.reward_address = reward_address;
    self.write_staker_info(:staker_address, :staker_info);
}
```

`change_reward_address()` in `pool.cairo` has the identical gap:

```cairo
fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
    assert!(self.token_dispatcher.contract_address.read() != reward_address, ..., REWARD_ADDRESS_IS_TOKEN);
    // reward_address == 0 is accepted here
    pool_member_info.reward_address = reward_address;
    self.write_pool_member_info(:pool_member, :pool_member_info);
}
```

When `claim_rewards()` is subsequently called in either contract, the transfer is sent unconditionally to the stored `reward_address`:

- `staking.cairo` `claim_rewards()`: calls `send_rewards_to_staker()` which transfers to `staker_info.reward_address`
- `pool.cairo` `claim_rewards()`: `reward_token.checked_transfer(recipient: reward_address, amount: rewards.into())`

On Starknet, a transfer to address `0` does not revert — it silently succeeds and the tokens are unrecoverable.

### Impact Explanation
Any staker or pool member who sets `reward_address = 0` (whether by mistake or due to a front-end bug) will have all accumulated and future unclaimed STRK yield permanently sent to the zero address. The principal stake is returned to `staker_address` on `unstake_action()`, but all rewards are irreversibly destroyed. This matches the allowed impact: **permanent freezing of unclaimed yield**.

### Likelihood Explanation
The entry path is fully unprivileged — any active staker calls `change_reward_address(0)` directly on the staking contract, and any pool member calls `change_reward_address(0)` directly on their pool contract. No special role or external dependency is required. Accidental zero-address submission is a well-known user error in DeFi (e.g., copy-paste failure, uninitialized variable in a script), making this a realistic scenario.

### Recommendation
Add an explicit non-zero check in all four locations:

1. `stake()` in `staking.cairo` — before storing `reward_address`
2. `change_reward_address()` in `staking.cairo`
3. `enter_delegation_pool()` in `pool.cairo` — before storing `reward_address`
4. `change_reward_address()` in `pool.cairo`

```cairo
assert!(reward_address.is_non_zero(), "{}", GenericError::ZERO_ADDRESS);
```

The `GenericError::ZERO_ADDRESS` variant already exists in `src/errors.cairo`.

### Proof of Concept

1. Staker calls `stake(reward_address: 0, operational_address: X, amount: MIN_STAKE)`.
   - All token-address checks pass (zero is not a token address).
   - `reward_address = 0` is written to storage.
2. Protocol accrues rewards over several epochs.
3. Anyone calls `claim_rewards(staker_address)`.
   - `staking.cairo` line 416: `let reward_address = staker_info.reward_address;` → `0`
   - `staking.cairo` line 428: `send_rewards_to_staker(...)` transfers accumulated STRK to address `0`.
   - Tokens are permanently lost; no recovery path exists.

The same path applies via `change_reward_address(0)` on an already-staked account, and via `enter_delegation_pool` / `change_reward_address` in `pool.cairo`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** src/errors.cairo (L39-39)
```text
            GenericError::ZERO_ADDRESS => "Address is zero",
```
