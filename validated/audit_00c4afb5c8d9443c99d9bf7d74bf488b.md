### Title
Missing Delegator-Provided Maximum Commission Validation Enables Front-Running Yield Theft — (File: src/pool/pool.cairo)

---

### Summary

`enter_delegation_pool` and `switch_delegation_pool` accept no `max_commission` parameter from the delegator. A staker who holds an active commission commitment can atomically raise their commission to `max_commission` (up to 100 %) in the same block as a delegator's delegation transaction, silently redirecting all future yield to the staker.

---

### Finding Description

`enter_delegation_pool` and `switch_delegation_pool` in `src/pool/pool.cairo` accept only `reward_address`/`amount` and `to_staker`/`to_pool`/`amount` respectively — no `max_commission` guard is accepted from the caller. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

The staking contract's `set_commission` function enforces that, **without** an active commission commitment, a staker may only lower their commission. However, once a staker has set a commission commitment via `set_commission_commitment`, they are free to raise their commission to any value up to `max_commission` (which can be set as high as 10 000, i.e. 100 %). [5](#0-4) [6](#0-5) 

The attack path is:

1. Staker calls `set_commission_commitment(max_commission: 10000, expiration_epoch: far_future)` — a normal, unprivileged protocol action available to any staker.
2. Staker currently advertises a low commission (e.g. 200 = 2 %).
3. Delegator observes the 2 % commission and submits `enter_delegation_pool(reward_address, amount)` or `switch_delegation_pool(to_staker, to_pool, amount)`.
4. Staker front-runs the delegator's transaction with `set_commission(10000)`, which is valid because the commitment allows it.
5. Delegator's transaction executes and they are enrolled in the pool — now subject to 100 % commission.

Because commission is not read or validated inside `enter_delegation_pool` or `switch_delegation_pool`, the delegator has no on-chain mechanism to reject the changed terms. [7](#0-6) 

---

### Impact Explanation

All future staking yield earned by the delegator's funds is redirected to the staker via the 100 % commission. This constitutes **theft of unclaimed yield** (High impact). The delegator's principal is not at risk, but every reward epoch produces zero net yield for the delegator until they notice and exit.

---

### Likelihood Explanation

**Medium.** The staker must have previously called `set_commission_commitment` with a high `max_commission`. This is a public, permissionless action that any staker can take at any time. A malicious staker can set the commitment well in advance and wait for a large delegator to appear. Starknet's public mempool makes transaction ordering observable, enabling reliable front-running.

---

### Recommendation

Add a `max_commission: Commission` parameter to both `enter_delegation_pool` and `switch_delegation_pool`. Inside each function, read the pool's current commission from the staking contract and assert:

```
requester_max_commission >= pool_current_commission
```

If the staker has raised their commission above the delegator's stated maximum, the transaction reverts, protecting the delegator from the bait-and-switch. [8](#0-7) [9](#0-8) 

---

### Proof of Concept

```
// 1. Staker sets a commitment allowing commission up to 100%.
staking.set_commission_commitment(max_commission: 10000, expiration_epoch: current_epoch + 100);

// 2. Staker currently has commission = 200 (2%).
//    Delegator reads commission = 200 and submits:
pool.enter_delegation_pool(reward_address: delegator_reward, amount: 1_000_000);

// 3. Staker front-runs with:
staking.set_commission(commission: 10000);   // valid under commitment

// 4. Delegator's tx lands — no commission check inside enter_delegation_pool.
//    Pool member is created; all future rewards flow to staker at 100% commission.
//    Delegator receives 0 yield every epoch.
``` [10](#0-9) [11](#0-10)

### Citations

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

**File:** src/pool/pool.cairo (L379-394)
```text
        fn switch_delegation_pool(
            ref self: ContractState,
            to_staker: ContractAddress,
            to_pool: ContractAddress,
            amount: Amount,
        ) -> Amount {
            // Asserts.
            assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);
            let pool_member = get_caller_address();
            let mut pool_member_info = self.internal_pool_member_info(:pool_member);
            assert!(
                pool_member_info.unpool_time.is_some(),
                "{}",
                GenericError::MISSING_UNDELEGATE_INTENT,
            );
            assert!(amount <= pool_member_info.unpool_amount, "{}", GenericError::AMOUNT_TOO_HIGH);
```

**File:** src/pool/interface.cairo (L6-32)
```text
pub trait IPool<TContractState> {
    /// Add a new pool member to the delegation pool with `amount` starting funds.
    ///
    /// #### Preconditions:
    /// - The staker is active and not in exit window.
    /// - The caller address does not exist as a pool member in the pool.
    /// - `amount > 0`.
    /// - Caller address has sufficient funds.
    /// - Caller address has sufficient approval for transfer to pool contract.
    ///
    /// #### Emits:
    /// - [`NewPoolMember`](Events::NewPoolMember)
    /// - [`PoolMemberBalanceChanged`](Events::PoolMemberBalanceChanged)
    ///
    /// #### Errors:
    /// - [`STAKER_INACTIVE`](staking::pool::errors::Error::STAKER_INACTIVE)
    /// - [`POOL_MEMBER_EXISTS`](staking::pool::errors::Error::POOL_MEMBER_EXISTS)
    /// - [`AMOUNT_IS_ZERO`](staking::errors::GenericError::AMOUNT_IS_ZERO)
    /// - [`POOL_MEMBER_IS_TOKEN`](staking::pool::errors::Error::POOL_MEMBER_IS_TOKEN)
    /// - [`REWARD_ADDRESS_IS_TOKEN`](staking::errors::GenericError::REWARD_ADDRESS_IS_TOKEN)
    ///
    /// #### Internal calls:
    /// - [`staking::staking::interface::IStakingPool::add_stake_from_pool`]
    /// - [`staking::staking::interface::IStaking::get_current_epoch`]
    fn enter_delegation_pool(
        ref self: TContractState, reward_address: ContractAddress, amount: Amount,
    );
```

**File:** src/pool/interface.cairo (L120-160)
```text
    /// -
    /// [`POOL_CLAIM_REWARDS_FROM_UNAUTHORIZED_ADDRESS`](staking::pool::errors::Error::POOL_CLAIM_REWARDS_FROM_UNAUTHORIZED_ADDRESS)
    ///
    /// #### Access control:
    /// Only the pool member address or reward address of the given `pool_member`.
    ///
    /// #### Internal calls:
    /// - [`staking::staking::interface::IStaking::get_current_epoch`]
    fn claim_rewards(ref self: TContractState, pool_member: ContractAddress) -> Amount;
    /// Moves `amount` funds of a pool member to `to_staker`'s pool `to_pool`.
    /// Returns the amount left in exit window for the pool member in this pool.
    ///
    /// #### Preconditions:
    /// - `amount > 0`.
    /// - The caller address exists as a pool member in the pool.
    /// - The caller pool member is in exit window.
    /// - The caller pool member's `unpool_amount` is greater than or equal to `amount`.
    /// - `to_staker` exists in the staking contract and is not in exit window.
    /// - `to_pool` is the delegation pool contract for `to_staker`.
    /// - `to_pool` is not the current pool.
    ///
    /// #### Emits:
    /// - [`SwitchDelegationPool`](Events::SwitchDelegationPool)
    ///
    /// #### Errors:
    /// - [`AMOUNT_IS_ZERO`](staking::errors::GenericError::AMOUNT_IS_ZERO)
    /// - [`POOL_MEMBER_DOES_NOT_EXIST`](staking::pool::errors::Error::POOL_MEMBER_DOES_NOT_EXIST)
    /// - [`MISSING_UNDELEGATE_INTENT`](staking::errors::GenericError::MISSING_UNDELEGATE_INTENT)
    /// - [`AMOUNT_TOO_HIGH`](staking::errors::GenericError::AMOUNT_TOO_HIGH)
    ///
    /// #### Access control:
    /// Only the pool member address.
    ///
    /// #### Internal calls:
    /// - [`staking::staking::interface::IStakingPool::switch_staking_delegation_pool`]
    fn switch_delegation_pool(
        ref self: TContractState,
        to_staker: ContractAddress,
        to_pool: ContractAddress,
        amount: Amount,
    ) -> Amount;
```

**File:** docs/spec.md (L929-953)
```markdown
#### description <!-- omit from toc -->
Initialize or update the commission.
Note: `commission` should be between 0 and 10000. for example 1000 is 10%.
#### emits <!-- omit from toc -->
1. [Commission Changed](#commission-changed) - If commission is already initialized.
2. [Commission Initialized](#commission-initialized) - If commission is not initialized.
#### errors <!-- omit from toc -->
1. [CONTRACT\_IS\_PAUSED](#contract_is_paused)
2. [STAKER\_NOT\_EXISTS](#staker_not_exists)
3. [UNSTAKE\_IN\_PROGRESS](#unstake_in_progress)
4. [INVALID\_COMMISSION](#invalid_commission)
5. [INVALID\_COMMISSION\_WITH\_COMMITMENT](#invalid_commission_with_commitment)
6. [COMMISSION\_COMMITMENT\_EXPIRED](#commission_commitment_expired)
7. [COMMISSION\_OUT\_OF\_RANGE](#commission_out_of_range)
#### pre-condition <!-- omit from toc -->
1. Staking contract is unpaused.
2. Staker exist in the contract.
3. If there is no active commission commitment, `commission` must be lower than the current
commission.
4. `commission` is not above the maximum commission for staking.
#### access control <!-- omit from toc -->
Only staker address.
#### logic <!-- omit from toc -->
1. If commission is not initialized, initialize the commission.
2. If commission is already initialized, update the commission.
```

**File:** docs/spec.md (L961-990)
```markdown
#### description <!-- omit from toc -->
Set a commitment that expire in `expiration_epoch`, The commitment allows the staker to update his
commission to any commission that is lower than `max_commission`.
Note: `max_commission` should be between 0 and 10000. for example 1000 is 10%.
#### emits <!-- omit from toc -->
1. [Commission Commitment Set](#commission-commitment-set)
#### errors <!-- omit from toc -->
1. [CONTRACT\_IS\_PAUSED](#contract_is_paused)
2. [STAKER\_NOT\_EXISTS](#staker_not_exists)
3. [UNSTAKE\_IN\_PROGRESS](#unstake_in_progress)
4. [MISSING\_POOL\_CONTRACT](#missing_pool_contract)
5. [COMMISSION\_COMMITMENT\_EXISTS](#commission_commitment_exists)
6. [MAX\_COMMISSION\_TOO\_LOW](#max_commission_too_low)
7. [EXPIRATION\_EPOCH\_TOO\_EARLY](#expiration_epoch_too_early)
8. [EXPIRATION\_EPOCH\_TOO\_FAR](#expiration_epoch_too_far)
9. [COMMISSION\_OUT\_OF\_RANGE](#commission_out_of_range)
#### pre-condition <!-- omit from toc -->
1. Staking contract is unpaused.
2. Staker exist in the contract.
3. Caller (staker) is not in exit window.
4. Delegation pool exist for the staker.
5. Commission commitment already exists.
6. `max_commission` should be greater than or equal to the current commission.
7. `expiration_epoch` should be greater than the current epoch.
8. `expiration_epoch` should be no further than 1 year from the current epoch.
9. `commission` is not above the maximum commission for staking.
#### access control <!-- omit from toc -->
Only staker address.
#### logic <!-- omit from toc -->
1. Set commission commitment.
```
