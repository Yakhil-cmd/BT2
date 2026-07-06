### Title
Missing Zero-Address Validation in `change_reward_address` Causes `unstake_action` to Permanently Revert — (`src/staking/staking.cairo`, `src/pool/pool.cairo`)

---

### Summary

Both `Staking::change_reward_address` and `Pool::change_reward_address` accept `ContractAddress::zero()` as a valid reward address. When a staker with accrued unclaimed rewards sets their reward address to zero and later calls `unstake_action`, the function unconditionally attempts to transfer rewards to address(0) via the ERC20 token. Because OpenZeppelin's ERC20 on Starknet reverts on transfers to address(0), the entire `unstake_action` call reverts, blocking the staker from recovering their staked principal.

---

### Finding Description

**Root cause — `Staking::change_reward_address` (staking.cairo:517–540)**

The only validation performed is that the new address is not a registered token address:

```cairo
assert!(
    !self.does_token_exist(token_address: reward_address),
    "{}",
    GenericError::REWARD_ADDRESS_IS_TOKEN,
);
```

There is no check that `reward_address.is_non_zero()`. A staker can therefore call `change_reward_address(reward_address: 0)` and the call succeeds, writing `ContractAddress::zero()` into `staker_info.reward_address`.

**Root cause — `Pool::change_reward_address` (pool.cairo:505–526)**

Identical gap: only the token-address check is present, no zero-address guard.

**Trigger path — `Staking::unstake_action` (staking.cairo:483–515)**

`unstake_action` unconditionally calls `send_rewards_to_staker` before returning the principal:

```cairo
self.send_rewards_to_staker(:staker_address, ref :staker_info, :token_dispatcher);
```

`send_rewards_to_staker` (staking.cairo:1614–1629) reads the stored `reward_address` and calls:

```cairo
token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
```

When `reward_address == 0` and `amount > 0` (i.e., the staker has any unclaimed rewards), the ERC20 `transfer` to address(0) reverts. Because this call is inside `unstake_action`, the entire transaction reverts, and the staker's principal remains locked in the staking contract.

**Secondary trigger — `Pool::claim_rewards` (pool.cairo:335–377)**

`claim_rewards` similarly calls:

```cairo
reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
```

If a pool member entered with or changed to `reward_address = 0`, any call to `claim_rewards` (including calls made during `exit_delegation_pool_action` if rewards are claimed there) will revert.

---

### Impact Explanation

A staker who has set `reward_address` to zero and has any non-zero `unclaimed_rewards_own` cannot complete `unstake_action`. The staker's principal is frozen in the staking contract for as long as the zero reward address persists. The staker can recover by calling `change_reward_address` again with a valid address (there is no restriction on doing so during the exit window), making this a **temporary freeze of funds**. However, a user who does not understand the cause will have their principal indefinitely locked with no on-chain error message pointing to the reward address as the problem — the revert surfaces from deep inside the ERC20 transfer.

Impact: **Temporary freezing of staked funds** — matches the allowed High impact category.

---

### Likelihood Explanation

- `change_reward_address` is a public, permissionless function callable by any staker or pool member.
- There is no UI-level or contract-level guard preventing a zero address from being submitted.
- A user migrating reward addresses, testing, or making a scripting error could easily pass `0` as the argument.
- The failure only manifests later, at `unstake_action` time, making it non-obvious to diagnose.

Likelihood: **Medium** — requires a user to set reward address to zero (accidental or deliberate), but the missing guard makes it a realistic user-error scenario.

---

### Recommendation

Add a non-zero assertion in both `change_reward_address` implementations, and also in `enter_delegation_pool` and `stake` where `reward_address` is first recorded:

```cairo
// In Staking::change_reward_address and Pool::change_reward_address
assert!(reward_address.is_non_zero(), "{}", Error::REWARD_ADDRESS_IS_ZERO);
```

Apply the same guard to `enter_delegation_pool` (pool.cairo:182) and the `stake` entry point in staking.cairo.

---

### Proof of Concept

1. Staker stakes the minimum amount and earns rewards via attestation.
2. Staker calls `staking.change_reward_address(reward_address: 0)` — succeeds, no revert.
3. Staker calls `staking.unstake_intent()` — succeeds.
4. After the exit wait window, staker calls `staking.unstake_action(staker_address)`.
5. Inside `unstake_action`, `send_rewards_to_staker` is called, which calls `checked_transfer(recipient: 0, amount: unclaimed_rewards)`.
6. The ERC20 contract reverts with "ERC20: transfer to the zero address" (or equivalent).
7. `unstake_action` reverts; the staker's principal remains locked.
8. The staker must discover the root cause, call `change_reward_address` with a valid address, and retry `unstake_action`.

Relevant code locations: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** src/staking/staking.cairo (L492-495)
```text
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

**File:** src/staking/staking.cairo (L1620-1626)
```text
            let reward_address = staker_info.reward_address;
            let amount = staker_info.unclaimed_rewards_own;
            let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();

            claim_from_reward_supplier(:reward_supplier_dispatcher, :amount, :token_dispatcher);
            token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
            staker_info.unclaimed_rewards_own = Zero::zero();
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
