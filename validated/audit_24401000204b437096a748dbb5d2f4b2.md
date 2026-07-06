### Title
Staker Can Enter Their Own Delegation Pool as a Pool Member — (`File: src/pool/pool.cairo`)

### Summary
The `enter_delegation_pool` function in `pool.cairo` does not check that the caller (`pool_member`) is not the staker who owns the pool. A staker can call `enter_delegation_pool` on their own pool contract, register as a pool member, and earn pool-member rewards on top of their staker rewards. Because the protocol's reward formula is concave (square-root inflation), the staker's self-delegation dilutes the rewards-per-token earned by every other pool member, constituting theft of unclaimed yield.

---

### Finding Description

`Pool.enter_delegation_pool` identifies the caller as `pool_member` and reads the pool's owner as `staker_address`, but never asserts `pool_member != staker_address`:

```
// src/pool/pool.cairo  lines 182-219
fn enter_delegation_pool(
    ref self: ContractState, reward_address: ContractAddress, amount: Amount,
) {
    self.assert_staker_is_active();
    let pool_member = get_caller_address();          // ← caller
    assert!(self.pool_member_info.read(pool_member).is_none(), ...);
    assert!(amount.is_non_zero(), ...);
    let token_dispatcher = self.token_dispatcher.read();
    let token_address = token_dispatcher.contract_address;
    assert!(token_address != pool_member, ...);      // only token check
    assert!(token_address != reward_address, ...);   // only token check
    let staker_address = self.staker_address.read(); // ← owner, never compared to pool_member
    transfer_from_delegator(:pool_member, :amount, :token_dispatcher);
    self.transfer_to_staking_contract(:amount, :token_dispatcher, :staker_address);
    ...
}
``` [1](#0-0) 

The pool's `staker_address` is written at construction time and never changes: [2](#0-1) 

The error enum for the pool contains no `STAKER_IS_POOL_MEMBER` variant, confirming the check was never implemented: [3](#0-2) 

The same gap exists in `add_to_delegation_pool`, which allows the staker to top up their self-delegated position after the initial entry: [4](#0-3) 

---

### Impact Explanation

Staking rewards follow a concave square-root inflation formula $M = C \cdot \sqrt{S}$. When the staker self-delegates an amount $D_s$ into their own pool:

1. The pool's total delegated balance grows from $D$ to $D + D_s$.
2. The staking contract sends the pool a reward proportional to $\sqrt{S + D_s} - \sqrt{S}$, which is strictly less than $D_s \cdot \frac{d\sqrt{S}}{dS}$ (diminishing returns).
3. Pool rewards are then split proportionally among members. Every existing member's reward-per-token shrinks because the denominator $D + D_s$ grows faster than the numerator (the pool's reward increment).
4. The staker simultaneously collects staker-side rewards on their own stake **and** pool-member rewards on $D_s$, double-dipping from the same inflation budget.

The net effect is that honest delegators receive less unclaimed yield than they would if the staker had not self-delegated. This satisfies the **High: Theft of unclaimed yield** impact criterion.

---

### Likelihood Explanation

- The entry point `enter_delegation_pool` is public and permissionless; no privileged role is required.
- The staker already holds the staker address and controls the pool contract address (obtained via `set_open_for_delegation`).
- The staker has a direct financial incentive: earning pool-member rewards on top of staker rewards.
- No off-chain coordination or oracle manipulation is needed; a single on-chain transaction suffices. [5](#0-4) 

---

### Recommendation

Add a guard at the top of `enter_delegation_pool` (and symmetrically in `add_to_delegation_pool`) that rejects the staker as a pool member:

```cairo
let staker_address = self.staker_address.read();
assert!(pool_member != staker_address, "{}", Error::STAKER_CANNOT_BE_POOL_MEMBER);
```

A corresponding error variant `STAKER_CANNOT_BE_POOL_MEMBER` should be added to `src/pool/errors.cairo`. [3](#0-2) 

---

### Proof of Concept

1. **Staker stakes** and calls `set_open_for_delegation` to deploy a pool. Pool's `staker_address` is set to `STAKER`.
2. **Honest delegators** call `enter_delegation_pool` on the pool, depositing a combined amount $D$.
3. **Staker calls `enter_delegation_pool`** on the same pool contract with `pool_member = STAKER` and a large amount $D_s$. No check prevents this.
   - `pool_member_info.read(STAKER)` returns `None` (first entry) → passes.
   - `token_address != STAKER` → passes (staker is not the token contract).
   - `staker_address` is read but never compared to `pool_member` → passes.
4. Tokens are transferred from `STAKER` to the staking contract as delegated stake. The pool's total balance is now $D + D_s$.
5. After the next attestation epoch, the staking contract calls `update_rewards_from_staking_contract` on the pool. The reward is computed on the enlarged balance $D + D_s$.
6. **Staker calls `claim_rewards(pool_member: STAKER)`** and receives $\frac{D_s}{D + D_s}$ of the pool's reward allocation.
7. Honest delegators each receive a proportionally smaller reward than they would have without the staker's self-delegation, because the pool's reward-per-unit-of-stake decreased due to the concave inflation formula. [6](#0-5) [7](#0-6)

### Citations

**File:** src/pool/pool.cairo (L99-100)
```text
        /// Address of the staker that the pool is associated with.
        staker_address: ContractAddress,
```

**File:** src/pool/pool.cairo (L182-219)
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

            // Emit events.
            self
                .emit(
                    Events::NewPoolMember { pool_member, staker_address, reward_address, amount },
                );
            self
                .emit(
                    Events::PoolMemberBalanceChanged {
                        pool_member, old_delegated_stake: Zero::zero(), new_delegated_stake: amount,
                    },
                );
        }
```

**File:** src/pool/pool.cairo (L221-254)
```text
        fn add_to_delegation_pool(
            ref self: ContractState, pool_member: ContractAddress, amount: Amount,
        ) -> Amount {
            // Asserts.
            self.assert_staker_is_active();
            let pool_member_info = self.internal_pool_member_info(:pool_member);
            let caller_address = get_caller_address();
            assert!(
                caller_address == pool_member || caller_address == pool_member_info.reward_address,
                "{}",
                Error::CALLER_CANNOT_ADD_TO_POOL,
            );
            assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);

            // Transfer funds from the delegator to the staking contract.
            let token_dispatcher = self.token_dispatcher.read();
            let staker_address = self.staker_address.read();
            transfer_from_delegator(pool_member: caller_address, :amount, :token_dispatcher);
            self.transfer_to_staking_contract(:amount, :token_dispatcher, :staker_address);

            // Update the pool member's balance checkpoint.
            let old_delegated_stake = self.increase_member_balance(:pool_member, :amount);
            let new_delegated_stake = old_delegated_stake + amount;

            // Emit events.
            self
                .emit(
                    Events::PoolMemberBalanceChanged {
                        pool_member, old_delegated_stake, new_delegated_stake,
                    },
                );

            new_delegated_stake
        }
```

**File:** src/pool/pool.cairo (L335-377)
```text
        fn claim_rewards(ref self: ContractState, pool_member: ContractAddress) -> Amount {
            // Asserts.
            let mut pool_member_info = self.internal_pool_member_info(:pool_member);
            let caller_address = get_caller_address();
            let reward_address = pool_member_info.reward_address;
            assert!(
                caller_address == pool_member || caller_address == reward_address,
                "{}",
                Error::POOL_CLAIM_REWARDS_FROM_UNAUTHORIZED_ADDRESS,
            );

            let until_checkpoint = self.get_current_checkpoint(:pool_member);

            // Calculate rewards and update entry_to_claim_from.
            let (mut rewards, updated_entry_to_claim_from) = self
                .calculate_rewards(
                    :pool_member,
                    from_checkpoint: pool_member_info.reward_checkpoint,
                    :until_checkpoint,
                    entry_to_claim_from: pool_member_info.entry_to_claim_from,
                );
            rewards += pool_member_info._unclaimed_rewards_from_v0;
            pool_member_info._unclaimed_rewards_from_v0 = Zero::zero();
            pool_member_info.entry_to_claim_from = updated_entry_to_claim_from;
            pool_member_info.reward_checkpoint = until_checkpoint;

            // Write the updated pool member info to storage.
            self.write_pool_member_info(:pool_member, :pool_member_info);

            // Transfer rewards to the pool member.
            let reward_token = IERC20Dispatcher { contract_address: STRK_TOKEN_ADDRESS };
            reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());

            // Emit event.
            self
                .emit(
                    Events::PoolMemberRewardClaimed {
                        pool_member, reward_address, amount: rewards,
                    },
                );

            rewards
        }
```

**File:** src/pool/pool.cairo (L569-587)
```text
        fn update_rewards_from_staking_contract(
            ref self: ContractState, rewards: Amount, pool_balance: Amount,
        ) {
            self.assert_caller_is_staking_contract();

            // `rewards_info` is initialized in the constructor or in the upgrade proccess,
            // so unwrapping should be safe.
            let (_, last) = self.cumulative_rewards_trace.last().unwrap();
            self
                .cumulative_rewards_trace
                .insert(
                    key: self.get_current_epoch(),
                    value: last
                        + self
                            .compute_rewards_per_unit(
                                staking_rewards: rewards, total_stake: pool_balance,
                            ),
                );
        }
```

**File:** src/pool/errors.cairo (L4-15)
```text
pub enum Error {
    POOL_MEMBER_DOES_NOT_EXIST,
    STAKER_INACTIVE,
    POOL_MEMBER_EXISTS,
    UNDELEGATE_IN_PROGRESS,
    SWITCH_POOL_DATA_DESERIALIZATION_FAILED,
    STAKER_ALREADY_REMOVED,
    CALLER_CANNOT_ADD_TO_POOL,
    REWARD_ADDRESS_MISMATCH,
    POOL_CLAIM_REWARDS_FROM_UNAUTHORIZED_ADDRESS,
    POOL_MEMBER_IS_TOKEN,
}
```

**File:** src/staking/staking.cairo (L542-571)
```text
        fn set_open_for_delegation(
            ref self: ContractState, token_address: ContractAddress,
        ) -> ContractAddress {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let staker_address = get_caller_address();
            let staker_info = self.internal_staker_info(:staker_address);
            let staker_pool_info = self.staker_pool_info.entry(staker_address);
            assert!(staker_info.unstake_time.is_none(), "{}", Error::UNSTAKE_IN_PROGRESS);
            assert!(self.does_token_exist(:token_address), "{}", Error::TOKEN_NOT_EXISTS);
            assert!(
                !staker_pool_info.has_pool_for_token(:token_address),
                "{}",
                Error::STAKER_ALREADY_HAS_POOL,
            );
            let commission = staker_pool_info.commission();

            // Deploy delegation pool contract.
            let pool_contract = self
                .deploy_delegation_pool_from_staking_contract(
                    :staker_address,
                    staking_contract: get_contract_address(),
                    :token_address,
                    :commission,
                );
            // Update pool to storage.
            staker_pool_info.pools.write(pool_contract, token_address);
            // Initialize the delegated balance trace.
            self.initialize_staker_delegated_balance_trace(:staker_address, :pool_contract);
            pool_contract
```
