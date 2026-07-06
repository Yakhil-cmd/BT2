### Title
Missing Zero Address Validation for `reward_address` Allows Permanent Loss of Unclaimed Yield - (File: `src/staking/staking.cairo`, `src/pool/pool.cairo`)

### Summary
Both `stake()` in `staking.cairo` and `enter_delegation_pool()` in `pool.cairo` accept a `reward_address` parameter with no zero-address check. Additionally, `change_reward_address()` in both contracts also lacks this check. If `reward_address` is set to the zero address, all accumulated staking or delegation rewards are irreversibly transferred to address(0) upon the next `claim_rewards()` call, permanently destroying the yield.

### Finding Description
In `staking.cairo`, `stake()` validates that `reward_address` is not a registered token address but performs no zero-address check: [1](#0-0) 

Similarly, `change_reward_address()` in `staking.cairo` only guards against the token-address case: [2](#0-1) 

In `pool.cairo`, `enter_delegation_pool()` mirrors the same gap: [3](#0-2) 

And `change_reward_address()` in `pool.cairo` is identical in its omission: [4](#0-3) 

When `claim_rewards()` is subsequently called, `send_rewards_to_staker()` unconditionally transfers to whatever `reward_address` is stored: [5](#0-4) 

The pool's `claim_rewards()` does the same: [6](#0-5) 

There is no recovery path once the transfer to address(0) executes — `unclaimed_rewards_own` is zeroed out immediately after the transfer.

### Impact Explanation
**High — Permanent freezing of unclaimed yield.**

Any STRK rewards accumulated by a staker or pool member whose `reward_address` is the zero address are sent to address(0) and are unrecoverable. The token balance at address(0) is permanently inaccessible on Starknet. The staker's `unclaimed_rewards_own` (or pool member's accumulated rewards) is set to zero after the transfer, so there is no second chance to redirect the funds.

### Likelihood Explanation
**Low-to-Medium.** A user must supply or update to `reward_address = 0` — either by mistake (e.g., a front-end bug, a scripting error, or an uninitialized variable) or through a direct contract call. Because `change_reward_address()` is also unguarded, a user who later "clears" their reward address by passing zero will silently arm the loss. The protocol provides no warning or revert to prevent this. Given that reward addresses are set by unprivileged callers (any staker or delegator), the entry path is fully permissionless.

### Recommendation
Add a non-zero assertion for `reward_address` in all four locations:

- `stake()` in `src/staking/staking.cairo`
- `change_reward_address()` in `src/staking/staking.cairo`
- `enter_delegation_pool()` in `src/pool/pool.cairo`
- `change_reward_address()` in `src/pool/pool.cairo`

```cairo
assert!(reward_address.is_non_zero(), "Reward address cannot be zero");
```

This mirrors the existing `AMOUNT_IS_ZERO` guard pattern already used throughout the codebase.

### Proof of Concept

**Staker path:**

1. Staker calls `staking.stake(reward_address: 0, operational_address: op, amount: min_stake)`.
   - Passes all existing checks (not a token address, not already in use, amount ≥ min). [7](#0-6) 
2. Staker accrues rewards over epochs via attestation.
3. Anyone calls `staking.claim_rewards(staker_address)`.
   - `send_rewards_to_staker` reads `reward_address = 0` and executes `checked_transfer(recipient: 0, amount: rewards)`. [8](#0-7) 
4. Rewards are transferred to address(0) and `unclaimed_rewards_own` is zeroed. Funds are permanently lost.

**Pool member path:**

1. Pool member calls `pool.enter_delegation_pool(reward_address: 0, amount: x)`.
   - Passes all existing checks (not a token address, amount > 0). [9](#0-8) 
2. Pool member accrues rewards.
3. Anyone calls `pool.claim_rewards(pool_member)`.
   - Reads `reward_address = 0` and executes `checked_transfer(recipient: 0, amount: rewards)`. [6](#0-5) 
4. Rewards are permanently destroyed.

### Citations

**File:** src/staking/staking.cairo (L294-317)
```text
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

**File:** src/staking/staking.cairo (L517-524)
```text
        fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(
                !self.does_token_exist(token_address: reward_address),
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
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

**File:** src/pool/pool.cairo (L191-195)
```text
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

**File:** src/pool/pool.cairo (L505-510)
```text
        fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
            assert!(
                self.token_dispatcher.contract_address.read() != reward_address,
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
```
