### Title
Missing Zero Address Validation for `reward_address` Enables Permanent Freezing of Unclaimed Yield - (File: `src/pool/pool.cairo`)

---

### Summary

`Pool::enter_delegation_pool` accepts an arbitrary `reward_address` including the zero address (`ContractAddress::zero()`). Because the pool contract provides no function to update a pool member's `reward_address` after entry, and because `claim_rewards` unconditionally calls `checked_transfer(recipient: reward_address, ...)`, any pool member who registers with `reward_address = 0` will have their accrued STRK rewards permanently frozen — the transfer to the zero address reverts in the OpenZeppelin ERC20 implementation used by the STRK token.

---

### Finding Description

`enter_delegation_pool` in `src/pool/pool.cairo` validates `reward_address` only against the pool's token address:

```cairo
assert!(token_address != reward_address, "{}", GenericError::REWARD_ADDRESS_IS_TOKEN);
``` [1](#0-0) 

There is no check that `reward_address` is non-zero. The zero address (`ContractAddress::zero()`) is not a token address, so the assertion passes and the pool member record is written with `reward_address = 0`:

```cairo
self.pool_member_info.write(pool_member, VInternalPoolMemberInfoTrait::new_latest(:reward_address));
``` [2](#0-1) 

Later, `claim_rewards` unconditionally calls `checked_transfer` to that stored `reward_address`:

```cairo
let reward_token = IERC20Dispatcher { contract_address: STRK_TOKEN_ADDRESS };
reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
``` [3](#0-2) 

The OpenZeppelin Cairo ERC20 `_transfer` asserts `recipient != 0` regardless of amount, so this call always reverts when `reward_address` is zero.

There is no `change_reward_address` function in the pool contract — the pool interface exposes only `enter_delegation_pool`, `add_to_delegation_pool`, `exit_delegation_pool_intent`, `exit_delegation_pool_action`, `claim_rewards`, and `switch_delegation_pool`. [4](#0-3) 

The same missing validation exists in `Staking::stake` and `Staking::change_reward_address` for stakers: [5](#0-4) [6](#0-5) 

However, stakers have a recovery path via `change_reward_address`, so the staker-side impact is temporary. The pool member case has no recovery path.

---

### Impact Explanation

A pool member who registers with `reward_address = 0` (accidentally or by mistake) will find that every subsequent call to `claim_rewards` reverts. Because the pool contract has no mechanism to update `reward_address`, the accrued STRK rewards are permanently unclaimable — they remain locked in the pool contract forever. The delegated principal is still recoverable via `exit_delegation_pool_action` (which transfers to `pool_member`, not `reward_address`), but all earned yield is permanently frozen.

**Impact: High — Permanent freezing of unclaimed yield.**

---

### Likelihood Explanation

Any unprivileged pool member can trigger this by passing `reward_address = 0` to `enter_delegation_pool`. This can happen by accident (e.g., a front-end bug, a script that passes a default/uninitialized address) or by a user who misunderstands the field. No privileged access is required. The entry point is fully public.

---

### Recommendation

Add a non-zero check for `reward_address` in `enter_delegation_pool` (pool contract) and in `stake` / `change_reward_address` (staking contract):

```cairo
assert!(reward_address.is_non_zero(), "{}", Error::REWARD_ADDRESS_IS_ZERO);
```

Apply this check alongside the existing `REWARD_ADDRESS_IS_TOKEN` guard in all three entry points. [7](#0-6) [8](#0-7) [9](#0-8) 

---

### Proof of Concept

1. Deploy the system normally.
2. A pool member calls `enter_delegation_pool(reward_address: ContractAddress::zero(), amount: MIN_STAKE)`.
   - The call succeeds: `token_address != 0` passes, no other zero-address check exists.
3. The staker attests and rewards accrue to the pool member.
4. The pool member (or anyone) calls `claim_rewards(pool_member)`.
   - `calculate_rewards` returns `rewards > 0`.
   - `reward_token.checked_transfer(recipient: 0, amount: rewards)` is called.
   - The OZ ERC20 `_transfer` asserts `recipient != 0` → **transaction reverts**.
5. No function exists to update `reward_address` on the pool member record.
6. All future calls to `claim_rewards` revert permanently. Accrued yield is frozen.

### Citations

**File:** src/pool/pool.cairo (L182-195)
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
```

**File:** src/pool/pool.cairo (L204-206)
```text
            self
                .pool_member_info
                .write(pool_member, VInternalPoolMemberInfoTrait::new_latest(:reward_address));
```

**File:** src/pool/pool.cairo (L365-366)
```text
            let reward_token = IERC20Dispatcher { contract_address: STRK_TOKEN_ADDRESS };
            reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
```

**File:** src/pool/interface.cairo (L1-60)
```text
use staking::types::{Amount, Commission, InternalPoolMemberInfoLatest};
use starknet::ContractAddress;
use starkware_utils::time::time::Timestamp;

#[starknet::interface]
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
    /// Increase the funds for `pool_member` by `amount`. Returns the updated total amount of the
    /// pool member.
    ///
    /// #### Preconditions:
    /// - The staker is active and not in exit window.
    /// - `pool_member` exists as a member in the pool.
    /// - `amount > 0`.
    /// - `pool_member` has sufficient funds.
    /// - `pool_member` has sufficient approval for transfer to pool contract.
    ///
    /// #### Emits:
    /// - [`PoolMemberBalanceChanged`](Events::PoolMemberBalanceChanged)
    ///
    /// #### Errors:
    /// - [`STAKER_INACTIVE`](staking::pool::errors::Error::STAKER_INACTIVE)
    /// - [`POOL_MEMBER_DOES_NOT_EXIST`](staking::pool::errors::Error::POOL_MEMBER_DOES_NOT_EXIST)
    /// - [`CALLER_CANNOT_ADD_TO_POOL`](staking::pool::errors::Error::CALLER_CANNOT_ADD_TO_POOL)
    /// - [`AMOUNT_IS_ZERO`](staking::errors::GenericError::AMOUNT_IS_ZERO)
    ///
    /// #### Access control:
    /// Only the pool member address or reward address of the given `pool_member`.
    ///
    /// #### Internal calls:
    /// - [`staking::staking::interface::IStakingPool::add_stake_from_pool`]
    /// - [`staking::staking::interface::IStaking::get_current_epoch`]
    fn add_to_delegation_pool(
        ref self: TContractState, pool_member: ContractAddress, amount: Amount,
    ) -> Amount;
```

**File:** src/staking/staking.cairo (L288-311)
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
```

**File:** src/staking/staking.cairo (L517-524)
```text
        fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(
                !self.does_token_exist(token_address: reward_address),
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
```
