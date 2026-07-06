### Title
Missing Zero-Address Validation on `reward_address` Causes Permanent Freezing of Unclaimed Yield - (File: src/staking/staking.cairo, src/pool/pool.cairo)

---

### Summary

The `stake()`, `change_reward_address()` (staking contract), `enter_delegation_pool()`, and `change_reward_address()` (pool contract) functions accept a user-supplied `reward_address` without validating it is non-zero. If a staker or pool member sets `reward_address` to the zero address — whether by mistake or due to a frontend bug — all accumulated STRK rewards are irreversibly transferred to address `0x0` and permanently frozen.

---

### Finding Description

The `general_prerequisites()` guard only checks that the **caller** is non-zero:

```cairo
fn general_prerequisites(ref self: ContractState) {
    self.assert_is_unpaused();
    assert_caller_is_not_zero();   // checks caller, NOT reward_address
}
```

The only validation applied to `reward_address` across all entry points is that it is not a registered token address (`REWARD_ADDRESS_IS_TOKEN`). There is no `assert!(reward_address.is_non_zero(), ...)` guard.

Affected entry points:

- `stake()` in `src/staking/staking.cairo` — accepts `reward_address` at registration time.
- `change_reward_address()` in `src/staking/staking.cairo` — allows updating to any non-token address, including zero.
- `enter_delegation_pool()` in `src/pool/pool.cairo` — accepts `reward_address` at pool-member registration.
- `change_reward_address()` in `src/pool/pool.cairo` — allows updating to any non-token address, including zero.

When rewards are later disbursed, `send_rewards_to_staker()` unconditionally transfers to whatever `reward_address` is stored:

```cairo
fn send_rewards_to_staker(...) {
    let reward_address = staker_info.reward_address;
    let amount = staker_info.unclaimed_rewards_own;
    claim_from_reward_supplier(...);
    token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
    staker_info.unclaimed_rewards_own = Zero::zero();
    ...
}
```

Critically, `unstake_action()` calls `send_rewards_to_staker()` automatically before deleting the staker record, giving the user no opportunity to correct a zero `reward_address` at that point. The same applies to pool rewards in `claim_rewards()` in `pool.cairo`:

```cairo
reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
```

---

### Impact Explanation

If `reward_address` is zero at the time rewards are disbursed (via `claim_rewards`, `unstake_action`, or `update_rewards_from_attestation_contract`), all accumulated STRK yield is transferred to address `0x0` and is permanently unrecoverable. This constitutes **permanent freezing of unclaimed yield**, which is in the allowed High-severity impact category.

---

### Likelihood Explanation

This is analogous to the external report's classification: it occurs only when a user supplies an invalid routing parameter — either through a frontend bug that passes a zero address, a user error during direct contract interaction, or a malicious/broken UI. The `change_reward_address()` path is particularly dangerous because a staker may have already accumulated significant rewards before the bad address is set, and `unstake_action()` will flush those rewards to zero without any further prompt.

---

### Recommendation

Add a non-zero assertion on `reward_address` in all four entry points:

```cairo
assert!(reward_address.is_non_zero(), "{}", GenericError::ZERO_ADDRESS);
```

This mirrors the existing pattern used for other address parameters (e.g., `token_address` in `add_token()`).

---

### Proof of Concept

1. Staker calls `stake(reward_address: 0, operational_address: X, amount: MIN_STAKE)`.
   - No zero-address check exists; the call succeeds. [1](#0-0) 

2. Staker accumulates rewards over several epochs via attestation.

3. Staker calls `unstake_intent()`, waits for the exit window, then calls `unstake_action()`.
   - `unstake_action()` internally calls `send_rewards_to_staker()`. [2](#0-1) 

4. `send_rewards_to_staker()` reads `reward_address = 0` from storage and executes `checked_transfer(recipient: 0, amount: rewards)`. [3](#0-2) 

5. All accumulated STRK rewards are sent to address `0x0` and are permanently frozen. The staker record is then deleted, making recovery impossible.

The same path applies to pool members via `enter_delegation_pool(reward_address: 0, ...)` followed by `claim_rewards()` in `pool.cairo`: [4](#0-3) [5](#0-4)

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

**File:** src/pool/pool.cairo (L364-366)
```text
            // Transfer rewards to the pool member.
            let reward_token = IERC20Dispatcher { contract_address: STRK_TOKEN_ADDRESS };
            reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
```
