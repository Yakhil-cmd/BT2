### Title
Missing Zero-Address Validation on `reward_address` Allows Temporary Freeze of Unclaimed Yield and Principal - (File: `src/staking/staking.cairo`, `src/pool/pool.cairo`)

---

### Summary
`change_reward_address` in both the Staking and Pool contracts, as well as `stake()`, validate that `reward_address` is not a token contract address but do **not** validate that it is non-zero. A staker or pool member who accidentally sets their reward address to `0` will find that all subsequent reward-transfer calls revert (OZ ERC20 rejects zero-address recipients), temporarily freezing their unclaimed yield and — in the staking contract — blocking `unstake_action` from completing, which temporarily freezes their principal as well.

---

### Finding Description

`staking.cairo::change_reward_address` performs exactly one validation on the incoming address:

```cairo
// src/staking/staking.cairo:517-524
fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
    self.general_prerequisites();
    assert!(
        !self.does_token_exist(token_address: reward_address),
        "{}",
        GenericError::REWARD_ADDRESS_IS_TOKEN,
    );
    ...
    staker_info.reward_address = reward_address;   // zero is accepted
``` [1](#0-0) 

The same pattern exists in `pool.cairo::change_reward_address`:

```cairo
// src/pool/pool.cairo:505-516
fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
    assert!(
        self.token_dispatcher.contract_address.read() != reward_address,
        "{}",
        GenericError::REWARD_ADDRESS_IS_TOKEN,
    );
    ...
    pool_member_info.reward_address = reward_address;   // zero is accepted
``` [2](#0-1) 

And in `stake()` at initial registration:

```cairo
// src/staking/staking.cairo:307-311
assert!(
    !self.does_token_exist(token_address: reward_address),
    "{}",
    GenericError::REWARD_ADDRESS_IS_TOKEN,
);
``` [3](#0-2) 

The protocol already defines and uses a `ZERO_ADDRESS` error and an `assert_caller_is_not_zero()` helper, confirming awareness of the pattern — but neither is applied to `reward_address`. [4](#0-3) [5](#0-4) 

---

### Impact Explanation

When rewards are disbursed, both contracts call `checked_transfer` with the stored `reward_address` as the recipient:

```cairo
// src/staking/staking.cairo:1625
token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
``` [6](#0-5) 

```cairo
// src/pool/pool.cairo:366
reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
``` [7](#0-6) 

OpenZeppelin's Cairo ERC20 `_transfer` asserts `recipient.is_non_zero()`, so any transfer to address `0` reverts. Consequences:

1. **Permanent freeze of unclaimed yield** (until the address is corrected): `claim_rewards` always reverts.
2. **Temporary freeze of principal**: `unstake_action` calls `send_rewards_to_staker` *before* returning the principal, so the entire exit transaction reverts — the staker cannot withdraw their staked tokens until they first call `change_reward_address` with a valid address. [8](#0-7) 

The staker/pool member can recover by calling `change_reward_address` again with a valid address, so the freeze is temporary. However, during the freeze window the principal is inaccessible, matching the **"Temporary freezing of funds"** impact category.

---

### Likelihood Explanation

Any staker or pool member can trigger this unilaterally by passing `0` as `reward_address` — either at `stake()` time or via a subsequent `change_reward_address` call. No privileged role is required. Accidental zero-address input is a realistic user error (e.g., a scripting bug, a UI that submits an uninitialized field). The entry path is fully unprivileged and reachable on mainnet.

---

### Recommendation

Add a non-zero check on `reward_address` in `stake()`, `staking.cairo::change_reward_address`, and `pool.cairo::change_reward_address`:

```cairo
assert!(reward_address.is_non_zero(), "{}", GenericError::ZERO_ADDRESS);
```

This mirrors the existing `assert_caller_is_not_zero()` pattern already present in the codebase. [5](#0-4) 

---

### Proof of Concept

1. Staker calls `stake(reward_address: 0, operational_address: X, amount: MIN_STAKE)` — succeeds, zero reward address is stored.
2. Rewards accumulate over epochs via `update_rewards`.
3. Staker calls `unstake_intent()` — succeeds, exit window starts.
4. After the exit window, staker calls `unstake_action(staker_address)`.
5. `unstake_action` internally calls `send_rewards_to_staker`, which calls `checked_transfer(recipient: 0, ...)` → OZ ERC20 reverts with `TRANSFER_TO_ZERO`.
6. The entire `unstake_action` transaction reverts; the staker's principal remains locked in the contract.
7. The staker must call `change_reward_address(valid_address)` first, then retry `unstake_action`.

The same sequence applies to a pool member who calls `pool.change_reward_address(0)` — `claim_rewards` reverts until corrected. [9](#0-8) [10](#0-9) [11](#0-10)

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

**File:** src/staking/staking.cairo (L483-515)
```text
        fn unstake_action(ref self: ContractState, staker_address: ContractAddress) -> Amount {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let mut staker_info = self.internal_staker_info(:staker_address);
            let unstake_time = staker_info
                .unstake_time
                .expect_with_err(Error::MISSING_UNSTAKE_INTENT);
            assert!(Time::now() >= unstake_time, "{}", GenericError::INTENT_WINDOW_NOT_FINISHED);

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
            // Return delegated stake to pools and zero their balances.
            self
                .transfer_to_pools_when_unstake(
                    :staker_address, staker_pool_info: staker_pool_info.as_non_mut(),
                );
            // Clear staker pools.
            staker_pool_info.pools.clear();
            staker_amount
        }
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

**File:** src/staking/staking.cairo (L1620-1626)
```text
            let reward_address = staker_info.reward_address;
            let amount = staker_info.unclaimed_rewards_own;
            let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();

            claim_from_reward_supplier(:reward_supplier_dispatcher, :amount, :token_dispatcher);
            token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
            staker_info.unclaimed_rewards_own = Zero::zero();
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

**File:** src/pool/pool.cairo (L505-517)
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

**File:** src/errors.cairo (L20-20)
```text
    ZERO_ADDRESS,
```

**File:** src/staking/utils.cairo (L62-64)
```text
pub(crate) fn assert_caller_is_not_zero() {
    assert!(get_caller_address().is_non_zero(), "{}", Error::CALLER_IS_ZERO_ADDRESS);
}
```
