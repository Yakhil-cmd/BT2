### Title
Missing Zero Address Check for `reward_address` Allows Permanent Burning of Staker and Pool Member Rewards - (File: `src/staking/staking.cairo`, `src/pool/pool.cairo`)

---

### Summary
Both `stake()` and `change_reward_address()` in the Staking contract, and `change_reward_address()` in the Pool contract, accept a `reward_address` parameter without validating it against the zero address. If a staker or pool member sets their `reward_address` to `0`, all subsequent reward claims will transfer STRK tokens to address zero, permanently destroying the unclaimed yield.

---

### Finding Description
In `src/staking/staking.cairo`, the `stake()` function validates that `reward_address` is not a token contract address, but performs no zero address check:

```cairo
// staking.cairo::stake() lines 307-311
assert!(
    !self.does_token_exist(token_address: reward_address),
    "{}",
    GenericError::REWARD_ADDRESS_IS_TOKEN,
);
``` [1](#0-0) 

The same omission exists in `change_reward_address()` in the Staking contract:

```cairo
// staking.cairo::change_reward_address() lines 520-524
assert!(
    !self.does_token_exist(token_address: reward_address),
    "{}",
    GenericError::REWARD_ADDRESS_IS_TOKEN,
);
``` [2](#0-1) 

And in `change_reward_address()` in the Pool contract:

```cairo
// pool.cairo::change_reward_address() lines 506-510
assert!(
    self.token_dispatcher.contract_address.read() != reward_address,
    "{}",
    GenericError::REWARD_ADDRESS_IS_TOKEN,
);
``` [3](#0-2) 

When rewards are claimed, `send_rewards_to_staker()` unconditionally transfers to the stored `reward_address`:

```cairo
// staking.cairo lines 1625
token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
``` [4](#0-3) 

Similarly, `claim_rewards()` in the pool transfers directly to the stored `reward_address`:

```cairo
// pool.cairo line 366
reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
``` [5](#0-4) 

---

### Impact Explanation
If a staker or pool member sets `reward_address` to `ContractAddress::zero()` — either at registration via `stake()` / `enter_delegation_pool()`, or later via `change_reward_address()` — all STRK reward tokens transferred during `claim_rewards` or `unstake_action` will be sent to address zero. These tokens are permanently unrecoverable, constituting **permanent freezing of unclaimed yield**. [6](#0-5) 

---

### Likelihood Explanation
Any registered staker or pool member can call `change_reward_address(0)` at any time without restriction. The call succeeds silently, emitting a `StakerRewardAddressChanged` / `PoolMemberRewardAddressChanged` event with `new_address: 0`. The next reward claim then burns all accumulated yield. This is reachable by any unprivileged user with no preconditions beyond being a registered staker or pool member. [7](#0-6) [8](#0-7) 

---

### Recommendation
Add a zero address guard in all three entry points:

```cairo
// In staking.cairo::stake(), staking.cairo::change_reward_address(),
// and pool.cairo::change_reward_address()
assert!(reward_address.is_non_zero(), "Reward address is zero");
```

The existing `assert_caller_is_not_zero()` utility in `src/staking/utils.cairo` demonstrates the pattern already used for caller validation and can serve as a model. [9](#0-8) 

---

### Proof of Concept

1. Deploy the system normally.
2. Staker calls `stake(reward_address: 0, operational_address: <valid>, amount: <min_stake>)` — succeeds with no revert.
3. Advance epochs so rewards accrue.
4. Anyone calls `claim_rewards(staker_address)` — `send_rewards_to_staker` executes `checked_transfer(recipient: 0, amount: rewards)`.
5. STRK tokens are sent to address zero and are permanently lost.

Alternatively, an existing staker calls `change_reward_address(reward_address: 0)` — succeeds — then the next reward claim burns all accumulated unclaimed yield. [10](#0-9) [11](#0-10)

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

**File:** src/staking/utils.cairo (L62-64)
```text
pub(crate) fn assert_caller_is_not_zero() {
    assert!(get_caller_address().is_non_zero(), "{}", Error::CALLER_IS_ZERO_ADDRESS);
}
```
