### Title
Blacklisted `reward_address` Blocks `unstake_action`, Temporarily Freezing Staker Principal — (`src/staking/staking.cairo`)

---

### Summary

`unstake_action` unconditionally calls `send_rewards_to_staker` — which performs a live STRK token transfer to `reward_address` — before returning the staker's principal. If `reward_address` is blacklisted by the STRK token at the time of the call, the transfer reverts and the entire `unstake_action` fails, leaving the staker's principal locked in the contract until they change their reward address.

---

### Finding Description

`unstake_action` is the two-step exit function for stakers. After the exit window elapses, anyone can call it for a given `staker_address`. Its execution order is:

1. Call `send_rewards_to_staker` → pulls STRK from the reward supplier and calls `checked_transfer(recipient: reward_address, amount: amount.into())`.
2. Erase staker state (`remove_staker`).
3. Return principal: `checked_transfer(recipient: staker_address, amount: staker_amount.into())`. [1](#0-0) 

`send_rewards_to_staker` performs the reward transfer unconditionally — there is no zero-amount guard that would skip the transfer when `unclaimed_rewards_own > 0`: [2](#0-1) 

If the STRK token enforces a transfer blacklist (as USDC and many regulated ERC-20s do) and `reward_address` is on that list, `checked_transfer` reverts. Because the reward transfer is sequenced **before** the principal return and before state erasure, the entire transaction reverts. The staker's principal remains locked in the staking contract.

The staker does have a recovery path — `change_reward_address` — but it requires them to notice the failure, identify the cause, and submit a separate transaction before retrying `unstake_action`. [3](#0-2) 

The same structural issue exists in `claim_rewards` (staking contract), which also calls `send_rewards_to_staker` inline: [4](#0-3) 

And in `Pool::claim_rewards`, which transfers STRK rewards directly to `reward_address` in a single atomic call: [5](#0-4) 

Pool members can also change their `reward_address`: [6](#0-5) 

A harder variant with no recovery path exists in `exit_delegation_pool_action`, which transfers the pool token (which may be wrapped BTC — a token with known blacklist controls) directly to `pool_member` with no alternative recipient: [7](#0-6) 

There is no `change_pool_member_address` function; the pool member address is immutable. If `pool_member` is blacklisted by the pool token, their principal is permanently unrecoverable.

---

### Impact Explanation

For the staking contract path: the staker's principal STRK is temporarily frozen — they cannot complete `unstake_action` until they change `reward_address` to a non-blacklisted address. This matches **Temporary freezing of funds (High)**.

For the pool contract path: the pool member's principal (BTC or STRK) is permanently frozen with no recovery mechanism, since the pool member address is immutable. This matches **Permanent freezing of unclaimed yield / Temporary freezing of funds (High)**.

---

### Likelihood Explanation

STRK is a regulated token deployed by StarkWare; wrapped BTC tokens on Starknet are typically governed ERC-20s with admin transfer controls. Blacklisting of an address can occur due to regulatory action, OFAC compliance, or the address being flagged for illicit activity — all realistic, non-hypothetical events. The affected functions (`unstake_action`, `exit_delegation_pool_action`) are on the critical withdrawal path exercised by every exiting staker and delegator.

---

### Recommendation

Decouple the reward transfer from the principal-return operation. Store unclaimed rewards in a claimable mapping rather than pushing them inline during exit. Allow the staker/pool member to claim rewards separately, so a failed reward transfer does not block principal withdrawal:

```cairo
// Instead of:
self.send_rewards_to_staker(...); // may revert
token_dispatcher.checked_transfer(recipient: staker_address, ...);

// Prefer:
// 1. Record rewards as claimable (no transfer).
// 2. Transfer principal unconditionally.
// 3. Let staker call claim_rewards() separately.
```

This mirrors the recommendation in the original report: store token amounts in variables and let parties claim independently.

---

### Proof of Concept

1. Staker stakes STRK and accumulates rewards over several epochs.
2. Staker calls `unstake_intent` — succeeds, sets `unstake_time`.
3. Exit window elapses.
4. Staker's `reward_address` is added to the STRK token blacklist (e.g., regulatory action).
5. Anyone calls `unstake_action(staker_address)`.
6. `send_rewards_to_staker` calls `checked_transfer(recipient: reward_address, amount: rewards)` → reverts because `reward_address` is blacklisted.
7. Entire `unstake_action` reverts. Staker's principal remains locked.
8. Staker must call `change_reward_address(new_address)` and retry — principal is inaccessible until this is done.

For the permanent-freeze variant (pool): replace step 4 with "pool member's own address is blacklisted by the BTC pool token" and step 6 with `exit_delegation_pool_action` → `checked_transfer(recipient: pool_member, ...)` reverts. No recovery path exists since pool member address is immutable.

### Citations

**File:** src/staking/staking.cairo (L426-430)
```text
            let amount = staker_info.unclaimed_rewards_own;
            let token_dispatcher = strk_token_dispatcher();
            self.send_rewards_to_staker(:staker_address, ref :staker_info, :token_dispatcher);
            self.write_staker_info(:staker_address, :staker_info);
            amount
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

**File:** src/staking/staking.cairo (L1619-1626)
```text
        ) {
            let reward_address = staker_info.reward_address;
            let amount = staker_info.unclaimed_rewards_own;
            let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();

            claim_from_reward_supplier(:reward_supplier_dispatcher, :amount, :token_dispatcher);
            token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
            staker_info.unclaimed_rewards_own = Zero::zero();
```

**File:** src/pool/pool.cairo (L328-330)
```text
            // Transfer delegated amount to the pool member.
            let token_dispatcher = self.token_dispatcher.read();
            token_dispatcher.checked_transfer(recipient: pool_member, amount: unpool_amount.into());
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
