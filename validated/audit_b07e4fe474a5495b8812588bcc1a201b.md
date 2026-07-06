### Title
Missing Zero-Address Validation in `change_reward_address` Allows Permanent Freezing of Unclaimed Yield — (`src/staking/staking.cairo`, `src/pool/pool.cairo`)

---

### Summary

Both `change_reward_address` functions in the Staking and Pool contracts accept `reward_address = 0x0` without any zero-address guard. Once stored, every subsequent call to `claim_rewards` (and `unstake_action` in the staking contract) attempts to transfer tokens to the zero address. Depending on the ERC-20 implementation, this either permanently burns the unclaimed yield or causes every reward-claim and unstake call to revert, temporarily freezing the staker's or pool member's funds until they notice and correct the address.

---

### Finding Description

**Staking contract — `change_reward_address`** [1](#0-0) 

The only guard present is:

```cairo
assert!(
    !self.does_token_exist(token_address: reward_address),
    "{}",
    GenericError::REWARD_ADDRESS_IS_TOKEN,
);
```

There is no `assert!(reward_address.is_non_zero(), ...)` check. A staker can therefore write `0x0` into `staker_info.reward_address`.

**Pool contract — `change_reward_address`** [2](#0-1) 

The only guard is:

```cairo
assert!(
    self.token_dispatcher.contract_address.read() != reward_address,
    "{}",
    GenericError::REWARD_ADDRESS_IS_TOKEN,
);
```

Again, no zero-address check. A pool member can write `0x0` into `pool_member_info.reward_address`.

The same gap exists at initial entry points:

- `stake` in `staking.cairo` (line 307–311) — only checks `REWARD_ADDRESS_IS_TOKEN`.
- `enter_delegation_pool` in `pool.cairo` (line 195) — only checks `token_address != reward_address`. [3](#0-2) [4](#0-3) 

**Downstream transfer sites that consume the stored address without re-validation:**

*Staking contract — `send_rewards_to_staker` (called by both `claim_rewards` and `unstake_action`):* [5](#0-4) 

*Pool contract — `claim_rewards`:* [6](#0-5) 

Neither site checks whether `reward_address` is zero before calling `checked_transfer`.

---

### Impact Explanation

**Scenario A — ERC-20 reverts on zero-address transfer (standard OpenZeppelin behaviour on Starknet):**

- `claim_rewards` reverts for the affected staker / pool member → unclaimed yield is temporarily frozen.
- `unstake_action` also calls `send_rewards_to_staker` before returning the principal; if that reverts, the staker cannot retrieve their staked STRK until they first call `change_reward_address` with a valid address. [7](#0-6) 

This constitutes **temporary freezing of funds** (staked principal + accrued rewards inaccessible until corrected).

**Scenario B — ERC-20 silently accepts zero-address transfer:**

Rewards are transferred to `0x0` and permanently burned. This constitutes **permanent freezing / theft of unclaimed yield**.

Both scenarios fall within the allowed High-impact scope.

---

### Likelihood Explanation

The entry path is reachable by any unprivileged staker or pool member with no special role required. A user who accidentally passes `0x0` (e.g., a front-end bug, a scripting error, or a misunderstanding of the API) will silently store the invalid address. The contract provides no warning. The error is only discovered when a subsequent `claim_rewards` or `unstake_action` call fails or silently burns tokens. Likelihood is **Low-Medium** (accidental misuse is plausible; deliberate self-harm is also possible as a griefing vector against oneself, but the primary concern is accidental loss).

---

### Recommendation

Add a non-zero guard in every function that writes to `reward_address`:

```cairo
// In staking.cairo change_reward_address and stake:
assert!(reward_address.is_non_zero(), "{}", Error::REWARD_ADDRESS_IS_ZERO);

// In pool.cairo change_reward_address and enter_delegation_pool:
assert!(reward_address.is_non_zero(), "{}", Error::REWARD_ADDRESS_IS_ZERO);
```

Apply the same guard to the `SwitchPoolData.reward_address` field consumed in `enter_delegation_pool_from_staking_contract`. [8](#0-7) 

---

### Proof of Concept

1. Alice is a registered staker. She calls:
   ```
   staking.change_reward_address(reward_address: 0x0)
   ```
   The call succeeds — only the token-address check fires, not a zero check. [9](#0-8) 

2. Alice's `staker_info.reward_address` is now `0x0`. [10](#0-9) 

3. Alice (or anyone) calls `staking.claim_rewards(alice)`. Inside `send_rewards_to_staker`:
   ```cairo
   token_dispatcher.checked_transfer(recipient: 0x0, amount: amount.into());
   ```
   Either reverts (DoS on claim + unstake) or silently burns the rewards. [11](#0-10) 

4. Alice calls `staking.unstake_action(alice)` — same revert path, blocking principal withdrawal. [7](#0-6) 

5. The identical path exists for pool members via `pool.change_reward_address(0x0)` followed by `pool.claim_rewards(pool_member)`. [12](#0-11) [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L307-311)
```text
            assert!(
                !self.does_token_exist(token_address: reward_address),
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
```

**File:** src/staking/staking.cairo (L492-498)
```text
            // Send rewards to staker's reward address.
            // It must be part of this function's flow because staker_info is about to be erased.
            let token_dispatcher = strk_token_dispatcher();
            self.send_rewards_to_staker(:staker_address, ref :staker_info, :token_dispatcher);
            // Update staker info to storage (it will be erased later).
            // This is done here to avoid re-entrancy.
            self.write_staker_info(:staker_address, :staker_info);
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

**File:** src/staking/staking.cairo (L1621-1628)
```text
            let amount = staker_info.unclaimed_rewards_own;
            let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();

            claim_from_reward_supplier(:reward_supplier_dispatcher, :amount, :token_dispatcher);
            token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
            staker_info.unclaimed_rewards_own = Zero::zero();

            self.emit(Events::StakerRewardClaimed { staker_address, reward_address, amount });
```

**File:** src/pool/pool.cairo (L193-195)
```text
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

**File:** src/pool/pool.cairo (L459-468)
```text
                Option::None => {
                    // Pool member does not exist. Create a new record.
                    let reward_address = switch_pool_data.reward_address;

                    // Update the pool member's balance checkpoint.
                    self.set_member_balance(:pool_member, :amount);

                    let pool_member_info = VInternalPoolMemberInfoTrait::new_latest(
                        :reward_address,
                    );
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
