### Title
Missing Zero-Address Validation for `reward_address` Enables Permanent Loss of Unclaimed Yield — (`src/pool/pool.cairo`, `src/staking/staking.cairo`)

---

### Summary

Neither the Pool nor the Staking contract validates that a supplied `reward_address` is non-zero. Any pool member or staker can set their reward address to `0x0` — either at entry time or via `change_reward_address` — causing all future reward transfers to be sent to the zero address and permanently destroyed.

---

### Finding Description

**Pool contract — `enter_delegation_pool`** (`src/pool/pool.cairo`, lines 182–219):

```cairo
fn enter_delegation_pool(
    ref self: ContractState, reward_address: ContractAddress, amount: Amount,
) {
    ...
    assert!(token_address != reward_address, "{}", GenericError::REWARD_ADDRESS_IS_TOKEN);
    // ← No assert!(reward_address.is_non_zero(), ...)
    ...
    self.pool_member_info.write(pool_member,
        VInternalPoolMemberInfoTrait::new_latest(:reward_address));
}
```

**Pool contract — `change_reward_address`** (`src/pool/pool.cairo`, lines 505–526):

```cairo
fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
    assert!(
        self.token_dispatcher.contract_address.read() != reward_address, ...
    );
    // ← No assert!(reward_address.is_non_zero(), ...)
    pool_member_info.reward_address = reward_address;
    self.write_pool_member_info(:pool_member, :pool_member_info);
}
```

**Staking contract — `stake`** (`src/staking/staking.cairo`, lines 288–366):

```cairo
fn stake(ref self: ContractState, reward_address: ContractAddress, ...) {
    ...
    assert!(!self.does_token_exist(token_address: reward_address), ...);
    // ← No assert!(reward_address.is_non_zero(), ...)
    ...
}
```

**Staking contract — `change_reward_address`** (`src/staking/staking.cairo`, lines 517–540):

```cairo
fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
    self.general_prerequisites();
    assert!(!self.does_token_exist(token_address: reward_address), ...);
    // ← No assert!(reward_address.is_non_zero(), ...)
    staker_info.reward_address = reward_address;
    ...
}
```

When rewards are later claimed, the transfer destination is read directly from storage with no zero-address guard:

**Pool `claim_rewards`** (`src/pool/pool.cairo`, lines 335–377):
```cairo
let reward_address = pool_member_info.reward_address;
...
reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
```

**Staking `send_rewards_to_staker`** (`src/staking/staking.cairo`, lines 1614–1629):
```cairo
let reward_address = staker_info.reward_address;
...
token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) 

---

### Impact Explanation

A pool member or staker who sets `reward_address = 0x0` will have every subsequent reward transfer sent to the zero address. STRK rewards transferred to `0x0` on Starknet are unrecoverable. The affected party permanently loses all accrued and future unclaimed yield with no mechanism for recovery.

**Matched allowed impact**: *High — Permanent freezing of unclaimed yield or unclaimed royalties.*

---

### Likelihood Explanation

The call path is fully unprivileged:

1. Any pool member calls `Pool::change_reward_address(0x0)` — no role check, no zero-address guard.
2. Any pool member calls `Pool::claim_rewards(pool_member)` — rewards are transferred to `0x0`.

The same path exists for stakers via `Staking::change_reward_address` and `Staking::stake`. While the action must be taken by the account holder themselves (making mass exploitation unlikely), the absence of a guard means a single mistaken call permanently destroys the caller's yield. Given that reward addresses are user-supplied strings in wallet UIs and scripts, accidental zero-address submission is a realistic scenario.

---

### Recommendation

Add a non-zero guard at every point where `reward_address` is accepted from an external caller:

```cairo
// In Pool::enter_delegation_pool, Pool::change_reward_address,
// Staking::stake, Staking::change_reward_address:
assert!(reward_address.is_non_zero(), "{}", GenericError::ZERO_ADDRESS);
```

This mirrors the existing pattern already used for `token_address` in `add_token`:

```cairo
assert!(token_address.is_non_zero(), "{}", GenericError::ZERO_ADDRESS);
``` [7](#0-6) 

---

### Proof of Concept

1. Pool member `Alice` calls `Pool::enter_delegation_pool(reward_address: 0x0, amount: X)`.
   - Passes: `token_address != 0x0` ✓, `amount.is_non_zero()` ✓.
   - `pool_member_info.reward_address` is stored as `0x0`.
2. Staking contract accrues rewards for Alice's staker over several epochs.
3. Alice (or anyone) calls `Pool::claim_rewards(alice_address)`.
   - `reward_address = pool_member_info.reward_address` → `0x0`.
   - `reward_token.checked_transfer(recipient: 0x0, amount: rewards)` executes.
   - STRK rewards are sent to the zero address and permanently lost.

The same sequence applies via `change_reward_address` for an existing pool member or staker.

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

**File:** src/pool/pool.cairo (L335-367)
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

```

**File:** src/pool/pool.cairo (L505-518)
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

**File:** src/staking/staking.cairo (L288-320)
```text
        fn stake(
            ref self: ContractState,
            reward_address: ContractAddress,
            operational_address: ContractAddress,
            amount: Amount,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let staker_address = get_caller_address();
            assert!(self.staker_info.read(staker_address).is_none(), "{}", Error::STAKER_EXISTS);
            assert!(
                self.operational_address_to_staker_address.read(operational_address).is_zero(),
                "{}",
                Error::OPERATIONAL_EXISTS,
            );
            self.assert_staker_address_not_reused(:staker_address);
            assert!(
                !self.does_token_exist(token_address: staker_address), "{}", Error::STAKER_IS_TOKEN,
            );
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
            let normalized_amount = NormalizedAmountTrait::from_strk_native_amount(:amount);

            // Transfer funds from staker. Sufficient approvals is a pre-condition.
```

**File:** src/staking/staking.cairo (L517-540)
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

            // Emit event.
            self
                .emit(
                    Events::StakerRewardAddressChanged {
                        staker_address, new_address: reward_address, old_address,
                    },
                );
        }
```

**File:** src/staking/staking.cairo (L1344-1347)
```text
        fn add_token(ref self: ContractState, token_address: ContractAddress) {
            self.roles.only_token_admin();
            assert!(token_address.is_non_zero(), "{}", GenericError::ZERO_ADDRESS);
            assert!(self.staker_info.read(token_address).is_none(), "{}", Error::TOKEN_IS_STAKER);
```

**File:** src/staking/staking.cairo (L1614-1629)
```text
        fn send_rewards_to_staker(
            ref self: ContractState,
            staker_address: ContractAddress,
            ref staker_info: InternalStakerInfoLatest,
            token_dispatcher: IERC20Dispatcher,
        ) {
            let reward_address = staker_info.reward_address;
            let amount = staker_info.unclaimed_rewards_own;
            let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();

            claim_from_reward_supplier(:reward_supplier_dispatcher, :amount, :token_dispatcher);
            token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
            staker_info.unclaimed_rewards_own = Zero::zero();

            self.emit(Events::StakerRewardClaimed { staker_address, reward_address, amount });
        }
```
