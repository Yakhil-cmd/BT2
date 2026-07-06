### Title
Missing Zero-Address Validation on `reward_address` Allows Permanent Loss of Unclaimed Yield - (File: src/staking/staking.cairo, src/pool/pool.cairo)

---

### Summary
Neither `staking.cairo::change_reward_address` nor `pool.cairo::change_reward_address` (nor the initial `stake()` / `enter_delegation_pool()` entry points) validate that the supplied `reward_address` is non-zero. A staker or pool member can set their reward address to `0`, after which any call to `claim_rewards` or `unstake_action` permanently transfers accumulated STRK rewards to the zero address, destroying them.

---

### Finding Description

**Staking contract – `change_reward_address`**

`src/staking/staking.cairo` lines 517–540 only assert that `reward_address` is not a registered token address:

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
    self.write_staker_info(:staker_address, :staker_info);
    ...
}
``` [1](#0-0) 

The same omission exists in the initial `stake()` call, which also only checks `REWARD_ADDRESS_IS_TOKEN`: [2](#0-1) 

**Pool contract – `change_reward_address`**

`src/pool/pool.cairo` lines 505–526 mirror the same pattern — only the token-address guard is present, no zero check:

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
``` [3](#0-2) 

**Reward transfer sinks**

`send_rewards_to_staker` (staking.cairo line 1625) and `claim_rewards` (pool.cairo line 366) both unconditionally transfer to whatever `reward_address` is stored:

```cairo
token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
``` [4](#0-3) [5](#0-4) 

`unstake_action` also calls `send_rewards_to_staker` before erasing the staker record, so accumulated rewards are irrecoverably sent to zero during exit: [6](#0-5) 

---

### Impact Explanation

Any STRK rewards accumulated in `unclaimed_rewards_own` (staker) or via the pool reward trace (pool member) are transferred to address `0x0` and permanently destroyed. Because `unstake_action` is callable by **any** address once the exit window has elapsed, a third party can trigger the reward loss for a staker whose `reward_address` is already zero, making the destruction irreversible without any further action from the victim. This constitutes **permanent freezing of unclaimed yield** — a High-severity impact under the allowed scope.

---

### Likelihood Explanation

The zero address is a valid `ContractAddress` value in Cairo/Starknet and passes all existing guards. A user can reach this state via:
1. Calling `stake(reward_address: 0.try_into().unwrap(), ...)` directly (no zero guard at entry).
2. Calling `change_reward_address(0)` after staking, intentionally or by scripting/UI error.
3. A pool member calling `pool.change_reward_address(0)`.

All three paths are reachable by an unprivileged caller with no special role. The likelihood is **medium**: it requires a user action, but the protocol provides no protection against it, and the consequence (permanent loss of yield) is irreversible.

---

### Recommendation

Add an explicit non-zero check in every function that writes to `reward_address`:

1. `staking.cairo::stake()` — assert `reward_address.is_non_zero()`.
2. `staking.cairo::change_reward_address()` — assert `reward_address.is_non_zero()`.
3. `pool.cairo::enter_delegation_pool()` — assert `reward_address.is_non_zero()`.
4. `pool.cairo::change_reward_address()` — assert `reward_address.is_non_zero()`.

A dedicated error constant (e.g., `REWARD_ADDRESS_IS_ZERO`) should be added to the shared errors module for consistency.

---

### Proof of Concept

```
1. Staker calls staking.stake(reward_address: 0, operational_address: X, amount: MIN_STAKE).
   → Staker record is created with reward_address = 0x0.

2. Protocol advances epochs; attestation triggers update_rewards.
   → staker_info.unclaimed_rewards_own accumulates non-zero STRK.

3. Anyone calls staking.unstake_intent() (as the staker), waits exit_wait_window.

4. Anyone calls staking.unstake_action(staker_address).
   → send_rewards_to_staker fires:
       claim_from_reward_supplier(amount)          // pulls STRK into staking contract
       token.checked_transfer(recipient: 0x0, amount)  // STRK sent to zero address → lost
   → staker_info erased; rewards unrecoverable.

Same flow applies to a pool member who calls pool.change_reward_address(0)
followed by pool.claim_rewards(pool_member) or pool.exit_delegation_pool_action(pool_member).
```

### Citations

**File:** src/staking/staking.cairo (L307-311)
```text
            assert!(
                !self.does_token_exist(token_address: reward_address),
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
```

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

**File:** src/staking/staking.cairo (L1625-1625)
```text
            token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
```

**File:** src/pool/pool.cairo (L366-366)
```text
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
