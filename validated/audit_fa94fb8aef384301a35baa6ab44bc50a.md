### Title
Missing Zero-Address Validation in `change_reward_address` Allows Permanent Freezing of Unclaimed Yield — (`src/staking/staking.cairo`, `src/pool/pool.cairo`)

---

### Summary

Both `change_reward_address` implementations in the staking and pool contracts accept `ContractAddress::zero()` as a valid new reward address without reverting. Once set, all future reward transfers are directed to the zero address, permanently destroying unclaimed yield. If the underlying ERC20 `transfer` to zero reverts (as is standard in OpenZeppelin-style implementations), the staker's `unstake_action` also becomes permanently blocked because it unconditionally calls `send_rewards_to_staker` before returning stake.

---

### Finding Description

`Staking::change_reward_address` (staking.cairo line 517) performs exactly one validation before writing the new address to storage:

```cairo
assert!(
    !self.does_token_exist(token_address: reward_address),
    "{}",
    GenericError::REWARD_ADDRESS_IS_TOKEN,
);
```

There is no `assert!(reward_address.is_non_zero(), ...)` guard. The function then unconditionally overwrites `staker_info.reward_address` with the caller-supplied value and commits it to storage.

The identical pattern exists in `Pool::change_reward_address` (pool.cairo line 505):

```cairo
assert!(
    self.token_dispatcher.contract_address.read() != reward_address,
    "{}",
    GenericError::REWARD_ADDRESS_IS_TOKEN,
);
```

Again, no zero-address check.

The reward address is consumed in two critical paths:

1. **`Staking::claim_rewards`** (staking.cairo line 411) → calls `send_rewards_to_staker` (line 1614) → `token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into())` (line 1625). If `reward_address` is zero and `amount > 0`, this transfer either silently burns the tokens or reverts.

2. **`Staking::unstake_action`** (staking.cairo line 483) → calls `send_rewards_to_staker` (line 495) **before** returning the principal stake. If the transfer to zero reverts, the entire `unstake_action` reverts, permanently trapping the staker's principal.

3. **`Pool::claim_rewards`** (pool.cairo line 335) → `reward_token.checked_transfer(recipient: reward_address, amount: rewards.into())` (line 366). Same outcome for pool members.

The same missing check is present in the initial `stake` call (staking.cairo line 288), so a staker can register with `reward_address = 0` from the outset.

---

### Impact Explanation

- **Permanent freezing of unclaimed yield**: All accrued STRK rewards are sent to `address(0)` and are irrecoverable.
- **Potential permanent freezing of staked principal**: If the ERC20 implementation reverts on `transfer(address(0), non_zero_amount)` (standard OZ behavior), `unstake_action` will always revert for that staker because `send_rewards_to_staker` is called unconditionally before the principal is returned. The staker's entire stake is permanently locked in the contract.

Both outcomes fall within the allowed impact scope: *Permanent freezing of unclaimed yield* (High) and *Temporary/permanent freezing of funds* (High).

---

### Likelihood Explanation

Any staker or pool member — entirely unprivileged — can trigger this on their own account by calling `change_reward_address(0)`. No special role, leaked key, or external dependency is required. The call succeeds silently. The damage is irreversible once committed to storage. Accidental misconfiguration (e.g., passing an uninitialized variable) is a realistic path.

---

### Recommendation

Add a zero-address guard at the top of both `change_reward_address` implementations, and also in `stake` / `enter_delegation_pool`:

```cairo
assert!(reward_address.is_non_zero(), "{}", GenericError::ZERO_ADDRESS);
```

The error constant `GenericError::ZERO_ADDRESS` ("Zero address") already exists in the codebase (`docs/spec.md` line 2822–2823), confirming the protocol authors intended this class of check to exist.

---

### Proof of Concept

**Staking contract path:**

1. Staker calls `stake(reward_address: VALID, ...)` — succeeds normally.
2. Staker calls `change_reward_address(reward_address: ContractAddress::zero())` — passes the single `REWARD_ADDRESS_IS_TOKEN` check; zero address is not a registered token. Storage is updated.
3. Epochs pass; `unclaimed_rewards_own` accumulates.
4. Anyone calls `unstake_action(staker_address)` after the exit window. Execution reaches `send_rewards_to_staker` → `checked_transfer(recipient: 0, amount: rewards)`. If the STRK ERC20 reverts on transfer-to-zero (standard behavior), `unstake_action` reverts. The staker's principal is permanently locked.
5. Even if the transfer does not revert, all rewards are burned at `address(0)`.

**Pool contract path:**

1. Pool member calls `enter_delegation_pool(...)` — succeeds.
2. Pool member calls `change_reward_address(ContractAddress::zero())` — passes the single token-address check.
3. Pool member calls `claim_rewards(pool_member)` — `checked_transfer(recipient: 0, amount: rewards)` either burns rewards or reverts, permanently freezing unclaimed yield. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** src/staking/staking.cairo (L483-495)
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

**File:** src/staking/staking.cairo (L1614-1626)
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
