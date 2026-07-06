### Title
Missing Zero-Address Validation on `reward_address` Enables Permanent Freezing of Unclaimed Yield — (File: `src/pool/pool.cairo`, `src/staking/staking.cairo`)

---

### Summary

Both `change_reward_address()` in the pool and staking contracts, and `stake()` in the staking contract, accept `Zero::zero()` as a valid `reward_address` without any zero-address guard. When `claim_rewards` is subsequently called, accumulated STRK rewards are transferred to `address(0)` and are permanently unrecoverable.

---

### Finding Description

**Vulnerability class:** Token-freeze bug / reward misrouting via missing zero-address validation — direct analog to the `recoverSigner()` returning `address(0)` root cause in the reference report.

**Root cause — three entry points, all missing a zero check:**

**1. `staking.cairo::stake()`** [1](#0-0) 

The only guard on `reward_address` is `!does_token_exist(reward_address)`. There is no `assert!(reward_address.is_non_zero(), ...)`. A staker may register with `reward_address = 0` from the very first call.

**2. `staking.cairo::change_reward_address()`** [2](#0-1) 

Same single guard (`REWARD_ADDRESS_IS_TOKEN`), no zero check. An existing staker can overwrite a valid reward address with `Zero::zero()` at any time.

**3. `pool.cairo::change_reward_address()`** [3](#0-2) 

Identical pattern: only the token-address guard is present. A pool member can set their reward address to zero.

**Consequence — `pool.cairo::claim_rewards()`** [4](#0-3) 

```cairo
reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
```

`reward_address` is read directly from storage and used as the transfer recipient with no zero guard. If it is `Zero::zero()`, the transfer either:
- **reverts** (if the STRK ERC-20 implementation rejects zero recipients) → rewards are permanently unclaimable (frozen), or
- **succeeds** (if the ERC-20 allows it) → rewards are burned to address(0).

Both outcomes constitute permanent freezing of unclaimed yield.

The authorization check in `claim_rewards` compounds the issue: [5](#0-4) 

```cairo
assert!(
    caller_address == pool_member || caller_address == reward_address,
    "{}",
    Error::POOL_CLAIM_REWARDS_FROM_UNAUTHORIZED_ADDRESS,
);
```

When `reward_address` is zero, `caller_address == reward_address` evaluates to `caller_address == 0`. On Starknet the zero address cannot be a transaction sender, so this branch is dead — only `pool_member` can trigger the claim, and the rewards still route to address(0).

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

Any staker or pool member who sets (or initially registers with) `reward_address = Zero::zero()` will have all earned STRK rewards permanently destroyed or frozen on every `claim_rewards` call. The tokens cannot be redirected after the fact because `change_reward_address` itself accepts zero, allowing the state to persist indefinitely. There is no recovery path.

---

### Likelihood Explanation

**Medium.** The path is reachable by any unprivileged staker or pool member with a single direct call to `change_reward_address(Zero::zero())` or by passing zero at `stake()` time. No special role, leaked key, or external dependency is required. Accidental misuse (e.g., passing an uninitialized variable) is a realistic scenario, and a malicious actor could also use this to irreversibly destroy a victim's yield if they control the victim's staker key (e.g., after a key compromise).

---

### Recommendation

Add an explicit non-zero assertion in all three entry points:

```cairo
assert!(reward_address.is_non_zero(), "{}", GenericError::ZERO_ADDRESS);
```

This mirrors the existing `ZERO_ADDRESS` guard already used elsewhere in the codebase (e.g., `add_token` — confirmed in tests at `src/staking/tests/test.cairo` line 5094). [6](#0-5) [7](#0-6) 

---

### Proof of Concept

```
1. Pool member calls pool.change_reward_address(reward_address: Zero::zero())
   → No assertion fires; pool_member_info.reward_address is written as 0.

2. Rewards accrue over epochs (attestation, update_rewards_from_staking_contract).

3. Pool member (or anyone who is pool_member) calls pool.claim_rewards(pool_member).
   → Authorization check passes (caller == pool_member).
   → rewards calculated > 0.
   → checked_transfer(recipient: 0x0, amount: rewards) executes.
   → Rewards are permanently lost / frozen.
   → Pool member's unclaimed_rewards reset to zero; no recovery possible.
```

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

**File:** src/pool/pool.cairo (L340-344)
```text
            assert!(
                caller_address == pool_member || caller_address == reward_address,
                "{}",
                Error::POOL_CLAIM_REWARDS_FROM_UNAUTHORIZED_ADDRESS,
            );
```

**File:** src/pool/pool.cairo (L364-366)
```text
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
