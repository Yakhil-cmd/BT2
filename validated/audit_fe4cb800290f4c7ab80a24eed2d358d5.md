### Title
Missing Zero Address Validation for `reward_address` Causes Permanent Loss of Unclaimed Yield - (File: `src/staking/staking.cairo`, `src/pool/pool.cairo`)

---

### Summary
Neither `Staking.change_reward_address`, `Staking.stake`, `Pool.change_reward_address`, nor `Pool.enter_delegation_pool` validate that the supplied `reward_address` is non-zero. A staker or pool member who sets (or initialises) their `reward_address` to `0x0` will have all future reward transfers sent to the zero address, permanently destroying their unclaimed yield.

---

### Finding Description

The protocol explicitly guards against a `reward_address` that equals a registered token address (`REWARD_ADDRESS_IS_TOKEN`), and it defines a `ZERO_ADDRESS` error and a helper `assert_caller_is_not_zero()`. However, none of the four entry points that accept a `reward_address` parameter check `reward_address.is_non_zero()`:

**`Staking.stake`** — no zero check on `reward_address`: [1](#0-0) 

**`Staking.change_reward_address`** — only checks `REWARD_ADDRESS_IS_TOKEN`, not zero: [2](#0-1) 

**`Pool.enter_delegation_pool`** — no zero check on `reward_address`: [3](#0-2) 

**`Pool.change_reward_address`** — only checks `REWARD_ADDRESS_IS_TOKEN`, not zero: [4](#0-3) 

Once `reward_address` is stored as zero, every downstream reward-transfer path sends tokens to `0x0`:

**`send_rewards_to_staker`** (called by `claim_rewards` and `unstake_action`): [5](#0-4) 

**`Pool.claim_rewards`**: [6](#0-5) 

The `ZERO_ADDRESS` error and `assert_caller_is_not_zero` utility already exist in the codebase, confirming the protocol is aware of the zero-address concern but has not applied it to `reward_address` inputs: [7](#0-6) [8](#0-7) 

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

When `reward_address` is zero, every call to `claim_rewards` (staking or pool) and `unstake_action` transfers accumulated STRK rewards to `0x0`. Those tokens are irrecoverable. The principal stake itself is returned to `staker_address` (not `reward_address`), so only the yield is destroyed, not the principal.

---

### Likelihood Explanation

**Medium.** The entry points are callable by any unprivileged staker or pool member. A user who accidentally passes `0x0` (e.g., an uninitialised variable in a calling script or front-end), or who is socially-engineered into doing so, will silently lose all future rewards. The protocol provides no warning and no recovery path once the address is stored. The `change_reward_address` path makes this reachable even for existing stakers who already have accumulated rewards.

---

### Recommendation

Add a non-zero assertion for `reward_address` in all four entry points, mirroring the existing `assert_caller_is_not_zero` pattern:

```cairo
assert!(reward_address.is_non_zero(), "{}", GenericError::ZERO_ADDRESS);
```

Apply this check in:
- `Staking.stake` — before writing `staker_info`
- `Staking.change_reward_address` — alongside the existing `REWARD_ADDRESS_IS_TOKEN` check
- `Pool.enter_delegation_pool` — before writing `pool_member_info`
- `Pool.change_reward_address` — alongside the existing `REWARD_ADDRESS_IS_TOKEN` check

---

### Proof of Concept

1. A staker calls `Staking.stake(reward_address: 0x0, operational_address: <valid>, amount: <min_stake>)`.
   - All existing checks pass: zero is not a token address, not an existing staker, etc.
   - `staker_info.reward_address` is stored as `0x0`.

2. After an attestation epoch, the staker calls `Staking.claim_rewards(staker_address)`.
   - `send_rewards_to_staker` executes: `token_dispatcher.checked_transfer(recipient: 0x0, amount: rewards)`.
   - Rewards are transferred to the zero address and permanently lost.

3. Alternatively, an existing staker with a valid `reward_address` calls `Staking.change_reward_address(reward_address: 0x0)`.
   - The only check (`REWARD_ADDRESS_IS_TOKEN`) passes because `0x0` is not a registered token.
   - All subsequent `claim_rewards` and `unstake_action` calls route yield to `0x0`.

The same two-step scenario applies identically to `Pool.enter_delegation_pool` and `Pool.change_reward_address`.

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

**File:** src/pool/pool.cairo (L182-206)
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
```

**File:** src/pool/pool.cairo (L365-366)
```text
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

**File:** src/errors.cairo (L39-39)
```text
            GenericError::ZERO_ADDRESS => "Address is zero",
```

**File:** src/staking/utils.cairo (L62-64)
```text
pub(crate) fn assert_caller_is_not_zero() {
    assert!(get_caller_address().is_non_zero(), "{}", Error::CALLER_IS_ZERO_ADDRESS);
}
```
