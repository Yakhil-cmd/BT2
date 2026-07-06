### Title
Missing Zero Address Validation in `change_reward_address` Allows Permanent Freezing of Unclaimed Yield - (File: `src/staking/staking.cairo`, `src/pool/pool.cairo`)

---

### Summary

Both `change_reward_address` in the Staking contract and in the Pool contract accept any `ContractAddress` as the new reward destination. Neither function checks that the supplied address is non-zero. If a staker or pool member sets their reward address to `0`, all subsequently claimed (or auto-claimed on unstake) yield is transferred to the zero address and is permanently unrecoverable.

---

### Finding Description

**Staking contract — `change_reward_address`** (`src/staking/staking.cairo`, line 517):

```cairo
fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
    self.general_prerequisites();
    assert!(
        !self.does_token_exist(token_address: reward_address),
        "{}",
        GenericError::REWARD_ADDRESS_IS_TOKEN,
    );
    let staker_address = get_caller_address();
    let mut staker_info = self.internal_staker_info(:staker_address);
    let old_address = staker_info.reward_address;
    staker_info.reward_address = reward_address;   // ← zero accepted here
    self.write_staker_info(:staker_address, :staker_info);
    ...
}
```

The only guard is `REWARD_ADDRESS_IS_TOKEN`; there is no `assert!(reward_address.is_non_zero(), ...)`. [1](#0-0) 

**Pool contract — `change_reward_address`** (`src/pool/pool.cairo`, line 505):

```cairo
fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
    assert!(
        self.token_dispatcher.contract_address.read() != reward_address,
        "{}",
        GenericError::REWARD_ADDRESS_IS_TOKEN,
    );
    let pool_member = get_caller_address();
    let mut pool_member_info = self.internal_pool_member_info(:pool_member);
    pool_member_info.reward_address = reward_address;   // ← zero accepted here
    self.write_pool_member_info(:pool_member, :pool_member_info);
    ...
}
```

Same pattern: only the token-address guard, no zero-address guard. [2](#0-1) 

**Reward dispatch paths that consume `reward_address`:**

- `claim_rewards` in `staking.cairo` reads `staker_info.reward_address` and calls `send_rewards_to_staker`, which transfers STRK to that address. [3](#0-2) 
- `unstake_action` in `staking.cairo` also calls `send_rewards_to_staker` before erasing the staker record, so any accrued yield is dispatched to whatever `reward_address` is stored at that moment. [4](#0-3) 
- The pool's `claim_rewards` similarly dispatches to `pool_member_info.reward_address`. [5](#0-4) 

If `reward_address` is `0` at any of these dispatch points, the STRK transfer goes to the zero address and is permanently unrecoverable.

The same gap exists in the initial `stake` call, which also only checks `REWARD_ADDRESS_IS_TOKEN` and not zero: [6](#0-5) 

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

Any accrued STRK rewards that are dispatched while `reward_address == 0` are sent to the zero address on Starknet and cannot be recovered. This applies to:
- A staker's own unclaimed rewards (claimed via `claim_rewards` or auto-claimed during `unstake_action`).
- A pool member's unclaimed rewards (claimed via the pool's `claim_rewards`).

Because `unstake_action` forcibly dispatches rewards before deleting the staker record, a staker who has set `reward_address = 0` and then unstakes will lose all accumulated yield in a single, irreversible transaction.

---

### Likelihood Explanation

**Low-Medium.** The entry path is reachable by any unprivileged staker or pool member with no special permissions. Realistic trigger scenarios include:

1. A front-end or scripting bug that passes an uninitialized/default address (`0`) to `change_reward_address`.
2. A staker migrating wallets who clears the reward address before setting the new one.
3. A malicious actor who has obtained temporary signing access to the staker key (e.g., a compromised hot wallet used only for operational tasks) calling `change_reward_address(0)` to grief the staker's yield before the staker notices.

---

### Recommendation

Add a non-zero guard at the top of both `change_reward_address` implementations, and also in `stake` / `enter_delegation_pool`:

```cairo
assert!(reward_address.is_non_zero(), "{}", GenericError::ZERO_ADDRESS);
```

This mirrors the pattern already used elsewhere in the codebase (e.g., `add_token` asserts `token_address.is_non_zero()`). [7](#0-6) 

---

### Proof of Concept

1. Staker `A` stakes with a valid `reward_address`.
2. Several epochs pass; `A` accrues significant unclaimed STRK rewards.
3. `A` (or a script acting on `A`'s behalf) calls `staking.change_reward_address(reward_address: 0)`. The call succeeds — only the `REWARD_ADDRESS_IS_TOKEN` check runs, and `0` is not a token address.
4. `A` calls `staking.claim_rewards(staker_address: A)`. `send_rewards_to_staker` executes `token.transfer(recipient: 0, amount: accrued_rewards)`. The STRK is sent to the zero address and is permanently lost.
5. Alternatively, if `A` calls `unstake_intent` and then `unstake_action`, the same `send_rewards_to_staker` path fires automatically, with the same result.

The identical sequence applies to a pool member calling `pool.change_reward_address(0)` followed by `pool.claim_rewards`.

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

**File:** src/staking/staking.cairo (L415-431)
```text
            let caller_address = get_caller_address();
            let reward_address = staker_info.reward_address;
            assert!(
                caller_address == staker_address || caller_address == reward_address,
                "{}",
                Error::CLAIM_REWARDS_FROM_UNAUTHORIZED_ADDRESS,
            );

            // Transfer rewards to staker's reward address and write updated staker info to storage.
            // Note: `send_rewards_to_staker` alters `staker_info` thus commit to storage is
            // performed only after that.
            let amount = staker_info.unclaimed_rewards_own;
            let token_dispatcher = strk_token_dispatcher();
            self.send_rewards_to_staker(:staker_address, ref :staker_info, :token_dispatcher);
            self.write_staker_info(:staker_address, :staker_info);
            amount
        }
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

**File:** src/staking/staking.cairo (L1346-1346)
```text
            assert!(token_address.is_non_zero(), "{}", GenericError::ZERO_ADDRESS);
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
