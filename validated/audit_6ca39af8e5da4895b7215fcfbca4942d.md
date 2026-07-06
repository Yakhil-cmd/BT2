### Title
Missing Zero-Address Validation for `reward_address` Permanently Burns Unclaimed Yield - (File: `src/staking/staking.cairo`, `src/pool/pool.cairo`)

### Summary
Neither the `Staking` contract nor the `Pool` contract validates that a supplied `reward_address` is non-zero. An unprivileged staker or pool member who passes `0` as their `reward_address` — at registration or via `change_reward_address` — will have all accrued STRK rewards permanently transferred to the zero address, constituting an irreversible loss of unclaimed yield.

### Finding Description
The `GenericError::ZERO_ADDRESS` variant exists in the shared error catalogue, and `assert_caller_is_not_zero()` is already used to guard the caller. However, the analogous guard is never applied to the `reward_address` parameter in any of the four public entry points that accept or mutate it:

**`Staking::stake()`** — `src/staking/staking.cairo` lines 307–311 only asserts the address is not a registered token; no non-zero check:

```cairo
assert!(
    !self.does_token_exist(token_address: reward_address),
    "{}",
    GenericError::REWARD_ADDRESS_IS_TOKEN,
);
``` [1](#0-0) 

**`Staking::change_reward_address()`** — same single guard, no zero check: [2](#0-1) 

**`Pool::enter_delegation_pool()`** — only checks the address is not the pool token: [3](#0-2) 

**`Pool::change_reward_address()`** — same single guard: [4](#0-3) 

When rewards are eventually claimed, `send_rewards_to_staker` unconditionally transfers to whatever address is stored:

```cairo
token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
``` [5](#0-4) 

Likewise in the pool's `claim_rewards`:

```cairo
reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
``` [6](#0-5) 

STRK transferred to address `0` on Starknet is unrecoverable.

### Impact Explanation
**High — Permanent freezing of unclaimed yield.**

Any staker or pool member who supplies `reward_address = 0` (at registration or via `change_reward_address`) will have every future reward payment, including all previously accrued but unclaimed rewards, sent to the zero address and permanently lost. There is no on-chain recovery path.

### Likelihood Explanation
**Medium.** The zero address is the default/uninitialized value in many languages and tooling environments. A user integrating via a script, SDK, or front-end that fails to populate the field will silently register `0`. The `change_reward_address` path is particularly dangerous because it can be called at any time by an already-active staker, redirecting a large accumulated balance to the burn address in a single transaction. No privileged role is required; any unprivileged staker or delegator can trigger this.

### Recommendation
Add an explicit non-zero assertion for `reward_address` in all four entry points, mirroring the existing `assert_caller_is_not_zero` pattern:

```cairo
assert!(reward_address.is_non_zero(), "{}", GenericError::ZERO_ADDRESS);
```

Apply this check in:
- `Staking::stake()` — before line 307 in `src/staking/staking.cairo`
- `Staking::change_reward_address()` — before line 520 in `src/staking/staking.cairo`
- `Pool::enter_delegation_pool()` — before line 192 in `src/pool/pool.cairo`
- `Pool::change_reward_address()` — before line 506 in `src/pool/pool.cairo`

### Proof of Concept

1. Deploy the system normally.
2. Call `Staking::stake(reward_address: 0, operational_address: <valid>, amount: <min_stake>)`. The call succeeds — no revert.
3. Advance epochs so rewards accrue.
4. Call `Staking::claim_rewards(staker_address: <staker>)` as the staker. The assert `caller == staker_address || caller == reward_address` passes (first branch). `send_rewards_to_staker` executes `checked_transfer(recipient: 0, amount: rewards)`. Rewards are burned.
5. Alternatively: stake normally, accumulate rewards, then call `Staking::change_reward_address(reward_address: 0)`. Subsequent `claim_rewards` burns all accrued yield.
6. The same two paths apply to `Pool::enter_delegation_pool` and `Pool::change_reward_address` for pool members. [7](#0-6) [8](#0-7) [9](#0-8) [10](#0-9)

### Citations

**File:** src/staking/staking.cairo (L288-317)
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

**File:** src/staking/staking.cairo (L1614-1628)
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
```

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

**File:** src/pool/pool.cairo (L365-366)
```text
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
