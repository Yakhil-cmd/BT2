### Title
Missing `reward_address != token_address` Validation in `enter_delegation_pool_from_staking_contract` Allows Permanent Freezing of Unclaimed STRK Yield - (File: src/pool/pool.cairo)

---

### Summary

`enter_delegation_pool_from_staking_contract` in `pool.cairo` is missing the `reward_address != token_address` guard that exists in every other pool entry path. When a delegator in a STRK pool holds `reward_address = <BTC_token_address>` and switches to a BTC pool, the destination pool silently registers them with that invalid reward address. All subsequent STRK reward claims are transferred to the BTC token contract, where they are permanently unrecoverable.

---

### Finding Description

The pool contract enforces `reward_address != token_address` in two places:

- `enter_delegation_pool` — [1](#0-0) 
- `change_reward_address` — [2](#0-1) 

However, the third entry path — `enter_delegation_pool_from_staking_contract` — contains **no such check**: [3](#0-2) 

This function is the destination-side callback invoked by `switch_staking_delegation_pool` in the staking contract when a pool member migrates between pools: [4](#0-3) 

The `reward_address` embedded in `SwitchPoolData` is taken verbatim from the member's existing record in the source pool: [5](#0-4) 

Because the source pool's token is STRK and the destination pool's token is BTC, the check `STRK != BTC_token_address` passes in the source pool at entry time. The destination pool's `enter_delegation_pool_from_staking_contract` never validates the reward address against its own token, so the member is registered with `reward_address = BTC_token_address` in the BTC pool.

When `claim_rewards` is later called, rewards are always paid in STRK and sent to `reward_address`: [6](#0-5) 

STRK tokens are transferred to the BTC token contract, which has no recovery mechanism. The yield is permanently frozen.

---

### Impact Explanation

Every STRK reward accrued by the affected pool member in the BTC pool is irrecoverably transferred to the BTC token contract address. The principal (BTC delegation) is unaffected and can still be withdrawn, but all unclaimed STRK yield is permanently frozen. This satisfies the **High: Permanent freezing of unclaimed yield** impact criterion.

---

### Likelihood Explanation

The system explicitly supports multi-token pools (STRK and BTC). A delegator in a STRK pool may legitimately set `reward_address` to any non-STRK address — including the BTC token contract address — because the STRK pool only checks `STRK != reward_address`. If that delegator later switches to a BTC pool (a supported operation), the missing guard in `enter_delegation_pool_from_staking_contract` silently accepts the invalid state. The trigger requires no privileged access: any unprivileged delegator can reach this path via `exit_delegation_pool_intent` followed by `switch_delegation_pool`.

---

### Recommendation

Add the same guard present in `enter_delegation_pool` and `change_reward_address` to the `Option::None` branch (new member creation) of `enter_delegation_pool_from_staking_contract`:

```cairo
// In the Option::None branch of enter_delegation_pool_from_staking_contract:
let reward_address = switch_pool_data.reward_address;
let token_address = self.token_dispatcher.read().contract_address;
assert!(token_address != reward_address, "{}", GenericError::REWARD_ADDRESS_IS_TOKEN);
```

The `Option::Some` branch (existing member update) is safe because the reward address was already validated when the member first joined the destination pool; only the new-member path is vulnerable.

---

### Proof of Concept

1. Deploy the full system with STRK and BTC tokens active.
2. Staker A opens a STRK delegation pool (Pool A); Staker B opens a BTC delegation pool (Pool B).
3. Alice calls `Pool_A.enter_delegation_pool(reward_address: BTC_token_address, amount: X)`.
   - Passes: `STRK_token_address != BTC_token_address`. [7](#0-6) 
4. Alice calls `Pool_A.exit_delegation_pool_intent(amount: X)`.
5. Alice calls `Pool_A.switch_delegation_pool(to_staker: B, to_pool: Pool_B, amount: X)`.
   - Staking contract validates `to_pool != from_pool` and token compatibility, then calls `Pool_B.enter_delegation_pool_from_staking_contract`. [8](#0-7) 
   - Pool B registers Alice with `reward_address = BTC_token_address` — **no token check performed**. [9](#0-8) 
6. Rewards accrue to Alice in Pool B.
7. Anyone calls `Pool_B.claim_rewards(pool_member: Alice)`.
   - STRK rewards are transferred to `BTC_token_address`. [6](#0-5) 
   - Funds are permanently frozen inside the BTC token contract.

### Citations

**File:** src/pool/pool.cairo (L192-195)
```text
            let token_dispatcher = self.token_dispatcher.read();
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

**File:** src/pool/pool.cairo (L405-408)
```text
            // Serialize the switch pool data and invoke the staking contract to switch pool.
            let switch_pool_data = SwitchPoolData { pool_member, reward_address };
            let mut serialized_data = array![];
            switch_pool_data.serialize(ref output: serialized_data);
```

**File:** src/pool/pool.cairo (L431-494)
```text
        fn enter_delegation_pool_from_staking_contract(
            ref self: ContractState, amount: Amount, data: Span<felt252>,
        ) {
            // Asserts.
            assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);
            self.assert_caller_is_staking_contract();

            // Deserialize the switch pool data.
            let mut serialized = data;
            let switch_pool_data: SwitchPoolData = Serde::deserialize(ref :serialized)
                .expect_with_err(Error::SWITCH_POOL_DATA_DESERIALIZATION_FAILED);
            let pool_member = switch_pool_data.pool_member;

            // Create or update the pool member info, depending on whether the pool member exists,
            // and then commit to storage.
            let pool_member_info = match self.get_internal_pool_member_info(:pool_member) {
                Option::Some(pool_member_info) => {
                    // Pool member already exists. Need to update pool_member_info to account for
                    // the accrued rewards and then update the delegated amount.
                    assert!(
                        pool_member_info.reward_address == switch_pool_data.reward_address,
                        "{}",
                        Error::REWARD_ADDRESS_MISMATCH,
                    );
                    // Update the pool member's balance checkpoint.
                    self.increase_member_balance(:pool_member, :amount);
                    VInternalPoolMemberInfoTrait::wrap_latest(value: pool_member_info)
                },
                Option::None => {
                    // Pool member does not exist. Create a new record.
                    let reward_address = switch_pool_data.reward_address;

                    // Update the pool member's balance checkpoint.
                    self.set_member_balance(:pool_member, :amount);

                    let pool_member_info = VInternalPoolMemberInfoTrait::new_latest(
                        :reward_address,
                    );

                    let staker_address = self.staker_address.read();
                    self
                        .emit(
                            Events::NewPoolMember {
                                pool_member, staker_address, reward_address, amount,
                            },
                        );
                    pool_member_info
                },
            };
            // Create the pool member record.
            self.pool_member_info.write(pool_member, pool_member_info);

            let new_delegated_stake = self.get_last_member_balance(:pool_member);

            // Emit event.
            self
                .emit(
                    Events::PoolMemberBalanceChanged {
                        pool_member,
                        old_delegated_stake: new_delegated_stake - amount,
                        new_delegated_stake,
                    },
                );
        }
```

**File:** src/pool/pool.cairo (L506-510)
```text
            assert!(
                self.token_dispatcher.contract_address.read() != reward_address,
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
```

**File:** src/staking/staking.cairo (L1176-1221)
```text
            assert!(to_pool != from_pool, "{}", Error::SELF_SWITCH_NOT_ALLOWED);
            let decimals = self.get_token_decimals(:token_address);
            let normalized_switched_amount = NormalizedAmountTrait::from_native_amount(
                amount: switched_amount, :decimals,
            );
            assert!(
                normalized_switched_amount <= old_intent_amount,
                "{}",
                GenericError::AMOUNT_TOO_HIGH,
            );

            let to_staker_info = self.internal_staker_info(staker_address: to_staker);

            // More asserts.
            assert!(to_staker_info.unstake_time.is_none(), "{}", Error::UNSTAKE_IN_PROGRESS);
            let to_token_address = self
                .staker_pool_info
                .entry(to_staker)
                .get_pool_token(pool_contract: to_pool)
                .expect_with_err(Error::DELEGATION_POOL_MISMATCH);
            assert!(token_address == to_token_address, "{}", Error::TOKEN_MISMATCH);

            // Update `to_staker`'s delegated stake amount, and add to total stake.
            let old_delegated_stake = self
                .get_delegated_balance(staker_address: to_staker, pool_contract: to_pool);
            let new_delegated_stake = old_delegated_stake + normalized_switched_amount;
            self
                .insert_staker_delegated_balance(
                    staker_address: to_staker,
                    pool_contract: to_pool,
                    delegated_balance: new_delegated_stake,
                );
            self.add_to_total_stake(:token_address, amount: normalized_switched_amount);

            // Update the undelegate intent. If the amount is zero, clear the intent.
            undelegate_intent_value.amount -= normalized_switched_amount;
            if undelegate_intent_value.amount.is_zero() {
                self.clear_undelegate_intent(:undelegate_intent_key);
            } else {
                self.pool_exit_intents.write(undelegate_intent_key, undelegate_intent_value);
            }

            // Notify `to_pool` about the new delegation.
            let to_pool_dispatcher = IPoolDispatcher { contract_address: to_pool };
            to_pool_dispatcher
                .enter_delegation_pool_from_staking_contract(amount: switched_amount, :data);
```
