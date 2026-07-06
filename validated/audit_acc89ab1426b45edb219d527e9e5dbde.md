### Title
Missing Zero Address Validation in `change_reward_address` Allows Permanent Freezing of Unclaimed Yield - (File: `src/staking/staking.cairo`, `src/pool/pool.cairo`)

---

### Summary

Both `Staking.change_reward_address` and `Pool.change_reward_address` (and their initial-setup counterparts `stake` / `enter_delegation_pool`) validate that the supplied `reward_address` is not a registered token address, but perform **no check against the zero address**. A staker or pool member can therefore set their `reward_address` to `0x0`, causing all future reward transfers to be sent to the zero address and permanently frozen.

---

### Finding Description

The `change_reward_address` function in `staking.cairo` performs exactly one address-validity check:

```cairo
// src/staking/staking.cairo  lines 520-524
assert!(
    !self.does_token_exist(token_address: reward_address),
    "{}",
    GenericError::REWARD_ADDRESS_IS_TOKEN,
);
``` [1](#0-0) 

The zero address (`0x0`) is not a registered token, so this assertion passes silently. The function then writes the zero address directly into persistent storage as the staker's `reward_address`.

The same pattern exists in `pool.cairo`:

```cairo
// src/pool/pool.cairo  lines 506-510
assert!(
    self.token_dispatcher.contract_address.read() != reward_address,
    "{}",
    GenericError::REWARD_ADDRESS_IS_TOKEN,
);
``` [2](#0-1) 

The same gap is present at entry points: `stake()` in `staking.cairo` and `enter_delegation_pool()` in `pool.cairo` apply the identical single-check pattern and accept `reward_address = 0` without complaint. [3](#0-2) [4](#0-3) 

When rewards are later distributed, the staking contract calls `send_rewards_to_staker` (invoked inside `unstake_action`) which transfers STRK to `staker_info.reward_address`: [5](#0-4) 

The pool contract's `claim_rewards` similarly transfers to the stored `reward_address`:

```cairo
// src/pool/pool.cairo  line 366
reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
``` [6](#0-5) 

If `reward_address` is `0x0`, the STRK transfer succeeds (the ERC-20 does not revert on a zero-address recipient in Cairo) and the tokens are permanently unrecoverable.

---

### Impact Explanation

Any staker or pool member who has set `reward_address = 0x0` will have **all accrued and future yield permanently sent to the zero address**. The tokens cannot be recovered: there is no admin override, no re-routing mechanism, and no way to reclaim funds from address `0x0` on Starknet. This matches the allowed High-severity impact: **Permanent freezing of unclaimed yield**.

---

### Likelihood Explanation

The entry path requires only a single self-initiated transaction from an unprivileged staker or pool member — no special role, no governance action, no bridge interaction. The risk is realistic in two scenarios:

1. **User error**: A staker passes `0x0` as `reward_address` during `stake()` or later calls `change_reward_address(0)` by mistake (e.g., a front-end bug, a scripting error, or a misunderstanding of the field's purpose).
2. **Griefing / self-harm**: A staker deliberately burns their own yield, which is irreversible and permanently removes those tokens from circulation.

The protocol's own spec lists `REWARD_ADDRESS_IS_TOKEN` as a guarded error for `change_reward_address`, demonstrating intent to validate the address — the zero-address case is simply an overlooked gap in that validation. [7](#0-6) 

---

### Recommendation

Add an explicit zero-address guard in every function that accepts or stores a `reward_address`:

```cairo
assert!(reward_address.is_non_zero(), "Reward address cannot be zero");
```

This guard should be applied in:
- `Staking::stake` (`src/staking/staking.cairo`)
- `Staking::change_reward_address` (`src/staking/staking.cairo`)
- `Pool::enter_delegation_pool` (`src/pool/pool.cairo`)
- `Pool::change_reward_address` (`src/pool/pool.cairo`)

---

### Proof of Concept

**Staker path:**

1. Staker calls `staking.change_reward_address(reward_address: 0x0)`.
2. The only check — `!does_token_exist(0x0)` — passes because `0x0` is not a registered token.
3. `staker_info.reward_address` is written as `0x0` to storage.
4. On the next attestation cycle, `update_rewards_from_attestation_contract` accumulates rewards for the staker.
5. When `unstake_action` is called (or `claim_rewards` if exposed), `send_rewards_to_staker` executes `checked_transfer(recipient: 0x0, amount: rewards)`.
6. STRK tokens are transferred to address `0x0` and are permanently frozen.

**Pool member path:**

1. Pool member calls `pool.change_reward_address(reward_address: 0x0)`.
2. The check `token_dispatcher.contract_address != 0x0` passes.
3. `pool_member_info.reward_address` is stored as `0x0`.
4. On `claim_rewards`, `reward_token.checked_transfer(recipient: 0x0, amount: rewards)` executes.
5. All accrued STRK yield is permanently frozen at address `0x0`.

### Citations

**File:** src/staking/staking.cairo (L307-311)
```text
            assert!(
                !self.does_token_exist(token_address: reward_address),
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
```

**File:** src/staking/staking.cairo (L492-506)
```text
            // Send rewards to staker's reward address.
            // It must be part of this function's flow because staker_info is about to be erased.
            let token_dispatcher = strk_token_dispatcher();
            self.send_rewards_to_staker(:staker_address, ref :staker_info, :token_dispatcher);
            // Update staker info to storage (it will be erased later).
            // This is done here to avoid re-entrancy.
            self.write_staker_info(:staker_address, :staker_info);

            let staker_amount = self.get_own_balance(:staker_address).to_strk_native_amount();
            let staker_pool_info = self.staker_pool_info.entry(staker_address);
            self.remove_staker(:staker_address, :staker_info, :staker_pool_info);

            // Return stake to staker.
            token_dispatcher
                .checked_transfer(recipient: staker_address, amount: staker_amount.into());
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

**File:** docs/spec.md (L878-882)
```markdown
#### errors <!-- omit from toc -->
1. [CONTRACT\_IS\_PAUSED](#contract_is_paused)
2. [REWARD\_ADDRESS\_IS\_TOKEN](#reward_address_is_token)
3. [STAKER\_NOT\_EXISTS](#staker_not_exists)
#### pre-condition <!-- omit from toc -->
```
