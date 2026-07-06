### Title
Permanent Freezing of Delegator Principal Due to Fixed Recipient in `exit_delegation_pool_action` — (File: `src/pool/pool.cairo`)

---

### Summary

The `exit_delegation_pool_action` function in `pool.cairo` always transfers the delegator's principal to the hardcoded `pool_member` address with no mechanism to specify an alternative recipient. If the `pool_member` address is blacklisted in the staking token (e.g., a BTC-wrapped token such as WBTC, which has blacklisting), the delegator's principal is permanently frozen in the pool contract. The same structural flaw exists in `unstake_action` in `staking.cairo`, where the STRK principal is always returned to the fixed `staker_address`.

---

### Finding Description

**Root cause — `exit_delegation_pool_action` in `src/pool/pool.cairo`:** [1](#0-0) 

The transfer is hardcoded to `pool_member`:

```cairo
// Transfer delegated amount to the pool member.
let token_dispatcher = self.token_dispatcher.read();
token_dispatcher.checked_transfer(recipient: pool_member, amount: unpool_amount.into());
```

The `pool_member` address is the key used to identify the delegator's record in storage. There is no `change_pool_member_address` function — only `change_reward_address` exists, which only affects reward routing, not principal withdrawal. [2](#0-1) 

If the `pool_member` address is blacklisted in the staking token, `checked_transfer` panics (it asserts the return value of `transfer`), causing the entire `exit_delegation_pool_action` call to revert. The delegator has no recourse: they cannot change their `pool_member` address, and they cannot redirect the principal to a different address.

**Same structural flaw — `unstake_action` in `src/staking/staking.cairo`:** [3](#0-2) 

The STRK principal is always returned to `staker_address` (fixed). Additionally, `send_rewards_to_staker` is called first and transfers STRK rewards to `reward_address` atomically within the same transaction: [4](#0-3) 

While a staker can change `reward_address` via `change_reward_address`, they cannot change `staker_address`. If `staker_address` is blacklisted in STRK, the principal transfer at line 506 reverts, permanently freezing the staker's principal.

**The `checked_transfer` wrapper panics on failure:** [5](#0-4) 

The `CheckedIERC20DispatcherTrait` asserts the return value of `transfer`. Any token-level revert (blacklist, pause, etc.) propagates as a panic, rolling back the entire withdrawal transaction.

---

### Impact Explanation

A delegator whose `pool_member` address is blacklisted in the staking token (BTC or STRK) cannot execute `exit_delegation_pool_action`. Their principal (`unpool_amount`) remains permanently locked in the pool contract with no recovery path. This matches the **Permanent freezing of funds** impact category.

---

### Likelihood Explanation

The protocol explicitly supports BTC tokens — any ERC20 with 5–18 decimals: [6](#0-5) 

BTC-wrapped tokens (e.g., WBTC) commonly implement address blacklisting. The protocol performs no validation that the configured BTC token lacks blacklisting. A delegator whose address is sanctioned or blacklisted by the token issuer after entering the pool would be permanently unable to withdraw their principal. This is a realistic scenario for any compliant token issuer.

---

### Recommendation

Allow the caller to specify an alternative recipient address for the principal withdrawal in `exit_delegation_pool_action`:

```cairo
- fn exit_delegation_pool_action(ref self: ContractState, pool_member: ContractAddress) -> Amount {
+ fn exit_delegation_pool_action(ref self: ContractState, pool_member: ContractAddress, recipient: ContractAddress) -> Amount {
    ...
-   token_dispatcher.checked_transfer(recipient: pool_member, amount: unpool_amount.into());
+   token_dispatcher.checked_transfer(recipient: recipient, amount: unpool_amount.into());
```

Access control should still enforce that only `pool_member` (or their `reward_address`) can call the function, but the destination of the principal should be caller-specified. Apply the same fix to `unstake_action` in `staking.cairo` for the `staker_address` principal transfer.

---

### Proof of Concept

1. Delegator calls `exit_delegation_pool_intent` to begin the exit window.
2. The BTC token issuer blacklists the delegator's `pool_member` address (e.g., due to sanctions).
3. After the exit window expires, the delegator calls `exit_delegation_pool_action`.
4. Inside the function, `token_dispatcher.checked_transfer(recipient: pool_member, ...)` is called.
5. The BTC token's `transfer` reverts because `pool_member` is blacklisted.
6. `checked_transfer` panics, rolling back the entire transaction.
7. The delegator's `unpool_amount` remains in the pool contract indefinitely.
8. The delegator has no mechanism to redirect the principal to a non-blacklisted address — `change_reward_address` only affects STRK reward routing, not BTC principal withdrawal.

### Citations

**File:** src/pool/pool.cairo (L328-331)
```text
            // Transfer delegated amount to the pool member.
            let token_dispatcher = self.token_dispatcher.read();
            token_dispatcher.checked_transfer(recipient: pool_member, amount: unpool_amount.into());

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

**File:** src/staking/staking.cairo (L504-506)
```text
            // Return stake to staker.
            token_dispatcher
                .checked_transfer(recipient: staker_address, amount: staker_amount.into());
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

**File:** src/pool/utils.cairo (L13-13)
```text
use starkware_utils::erc20::erc20_utils::CheckedIERC20DispatcherTrait;
```

**File:** src/pool/utils.cairo (L125-138)
```text
pub(crate) fn get_token_rewards_config(token_address: ContractAddress) -> TokenRewardsConfig {
    if token_address == STRK_TOKEN_ADDRESS {
        STRK_CONFIG
    } else {
        // BTC token.
        let token_dispatcher = IERC20MetadataDispatcher { contract_address: token_address };
        let decimals = token_dispatcher.decimals();
        assert!(decimals >= 5 && decimals <= 18, "{}", GenericError::INVALID_TOKEN_DECIMALS);
        TokenRewardsConfig {
            decimals,
            min_for_rewards: 10_u128.pow(decimals.into() - 5),
            base_value: 10_u128.pow(decimals.into() + 5),
        }
    }
```
