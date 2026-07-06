### Title
Missing Zero-Address Validation on `reward_address` Allows Permanent Freezing of Unclaimed Yield - (File: src/staking/staking.cairo, src/pool/pool.cairo)

### Summary
Both `change_reward_address` in `staking.cairo` and `change_reward_address` / `enter_delegation_pool` in `pool.cairo` accept a `reward_address` parameter without validating it is non-zero. A staker or pool member who passes `0x0` as their reward address will have all future claimed rewards permanently transferred to the zero address, irreversibly destroying their unclaimed yield.

### Finding Description
The `change_reward_address` function in `staking.cairo` performs only one validation on the incoming address — that it is not a registered token address — but does not assert it is non-zero:

```cairo
fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
    self.general_prerequisites();
    assert!(
        !self.does_token_exist(token_address: reward_address),
        "{}",
        GenericError::REWARD_ADDRESS_IS_TOKEN,
    );
    // No zero-address check
    staker_info.reward_address = reward_address;
    ...
}
``` [1](#0-0) 

The same pattern exists in `pool.cairo`'s `change_reward_address`:

```cairo
fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
    assert!(
        self.token_dispatcher.contract_address.read() != reward_address,
        "{}",
        GenericError::REWARD_ADDRESS_IS_TOKEN,
    );
    // No zero-address check
    pool_member_info.reward_address = reward_address;
    ...
}
``` [2](#0-1) 

And in `enter_delegation_pool` in `pool.cairo`, the `reward_address` is stored without a zero-address check: [3](#0-2) 

Similarly, the `stake` function in `staking.cairo` checks `REWARD_ADDRESS_IS_TOKEN` but not whether `reward_address` is zero: [4](#0-3) 

### Impact Explanation
When `claim_rewards` is called, the protocol transfers accumulated rewards to the stored `reward_address`. If that address is `0x0`, the ERC-20 transfer succeeds (Starknet does not revert on transfers to address zero) but the tokens are permanently unrecoverable — no private key controls address `0x0`. This constitutes **permanent freezing of unclaimed yield**, which is a listed High-severity impact.

### Likelihood Explanation
Any staker or pool member can trigger this by calling `change_reward_address(0x0)` or by entering the pool / staking with `reward_address = 0x0`. Programmatic callers (scripts, bots, integrations) that pass a default-initialized address are the most realistic path. The action is irreversible once rewards begin accumulating to the zero address.

### Recommendation
Add an explicit non-zero assertion on `reward_address` in all four entry points:

- `stake` in `staking.cairo`
- `change_reward_address` in `staking.cairo`
- `enter_delegation_pool` in `pool.cairo`
- `change_reward_address` in `pool.cairo`

```cairo
assert!(!reward_address.is_zero(), "{}", GenericError::ZERO_ADDRESS);
```

This mirrors the existing `ZERO_ADDRESS` guard already used elsewhere in the codebase (e.g., `add_token` rejects a zero token address). [5](#0-4) 

### Proof of Concept
1. Staker calls `stake(reward_address: 0x0, operational_address: <valid>, amount: <min_stake>)` — accepted without revert.
2. Staker earns attestation rewards over several epochs.
3. Staker (or anyone) calls `claim_rewards(staker_address)` — rewards are transferred to `0x0` and permanently lost.

Alternatively, an existing staker calls `change_reward_address(0x0)` — all subsequent reward claims are burned. [6](#0-5) [7](#0-6)

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
