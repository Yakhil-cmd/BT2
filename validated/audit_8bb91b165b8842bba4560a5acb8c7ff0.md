### Title
Updating reward supplier without draining accumulated `unclaimed_rewards` freezes staker reward claims and unstaking — (`src/staking/staking.cairo`)

---

### Summary

`set_reward_supplier` in the staking contract allows the token admin to swap the reward supplier address with no validation and no state migration. Because the new reward supplier is freshly deployed with `unclaimed_rewards = STRK_IN_FRIS` (1 STRK), while the staking contract still holds each staker's accumulated `unclaimed_rewards_own`, every subsequent `claim_rewards` or `unstake_action` call that tries to pull more than 1 STRK from the new reward supplier will revert. Stakers' accumulated yield is frozen and unstaking is blocked until the admin manually corrects the situation.

---

### Finding Description

**Root cause — `set_reward_supplier` performs no validation:**

```cairo
fn set_reward_supplier(ref self: ContractState, reward_supplier: ContractAddress) {
    self.roles.only_token_admin();
    let old_reward_supplier = self.reward_supplier_dispatcher.contract_address.read();
    self.reward_supplier_dispatcher.contract_address.write(reward_supplier);
    self.emit(ConfigEvents::RewardSupplierChanged { ... });
}
``` [1](#0-0) 

The function simply overwrites the dispatcher address. It does not:
- Verify that the old reward supplier's `unclaimed_rewards` is zero.
- Transfer or mirror the old `unclaimed_rewards` balance to the new contract.
- Reset any staker-side accounting.

**State mismatch after the swap:**

The reward supplier is initialized with exactly 1 STRK in `unclaimed_rewards`:

```cairo
self.unclaimed_rewards.write(STRK_IN_FRIS);
``` [2](#0-1) 

Meanwhile, every staker's `unclaimed_rewards_own` in the staking contract is untouched. When a staker calls `claim_rewards`, the staking contract calls `send_rewards_to_staker`, which calls `claim_from_reward_supplier`:

```cairo
fn send_rewards_to_staker(...) {
    let amount = staker_info.unclaimed_rewards_own;
    let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();
    claim_from_reward_supplier(:reward_supplier_dispatcher, :amount, :token_dispatcher);
    ...
}
``` [3](#0-2) 

`claim_from_reward_supplier` calls `reward_supplier_dispatcher.claim_rewards(amount)`:

```cairo
pub(crate) fn claim_from_reward_supplier(...) {
    reward_supplier_dispatcher.claim_rewards(:amount);
    ...
}
``` [4](#0-3) 

The new reward supplier's `claim_rewards` enforces:

```cairo
let unclaimed_rewards = self.unclaimed_rewards.read();
assert!(amount <= unclaimed_rewards, "{}", GenericError::AMOUNT_TOO_HIGH);
``` [5](#0-4) 

Any staker whose `unclaimed_rewards_own` exceeds 1 STRK will hit `AMOUNT_TOO_HIGH` and revert.

**`unstake_action` is also blocked:**

`unstake_action` calls `send_rewards_to_staker` before returning the principal:

```cairo
self.send_rewards_to_staker(:staker_address, ref :staker_info, :token_dispatcher);
// ...
token_dispatcher.checked_transfer(recipient: staker_address, amount: staker_amount.into());
``` [6](#0-5) 

If `send_rewards_to_staker` reverts, the entire `unstake_action` reverts, meaning the staker cannot recover their principal either.

---

### Impact Explanation

After `set_reward_supplier` is called while the old reward supplier holds accumulated `unclaimed_rewards`:

- Every staker with `unclaimed_rewards_own > 1 STRK` cannot call `claim_rewards` — **temporary freezing of unclaimed yield**.
- Every such staker also cannot complete `unstake_action` — **temporary freezing of staked principal**.

This matches the allowed impact: **High — Temporary freezing of funds / Permanent freezing of unclaimed yield** until the admin manually corrects the situation (e.g., by reverting to the old reward supplier address).

---

### Likelihood Explanation

`set_reward_supplier` is a legitimate operational function intended for use during upgrades or contract migrations. An admin performing a routine upgrade may call it without first verifying that all stakers have claimed their rewards or that the old reward supplier's `unclaimed_rewards` is zero. The function provides no guard, warning, or precondition check to prevent this mistake. The scenario is realistic and low-friction to trigger accidentally.

---

### Recommendation

Before updating the reward supplier, enforce that the old reward supplier's `unclaimed_rewards` equals `STRK_IN_FRIS` (the initialization floor), confirming all obligations have been settled:

```cairo
fn set_reward_supplier(ref self: ContractState, reward_supplier: ContractAddress) {
    self.roles.only_token_admin();
    let old_dispatcher = self.reward_supplier_dispatcher.read();
    let params = old_dispatcher.contract_parameters_v1();
    assert!(params.unclaimed_rewards <= STRK_IN_FRIS, "UNCLAIMED_REWARDS_NOT_ZERO");
    ...
}
```

Alternatively, migrate the `unclaimed_rewards` balance from the old supplier to the new one as part of the update.

---

### Proof of Concept

1. Staker stakes and accumulates `unclaimed_rewards_own = 500 STRK` over several epochs.
2. Old reward supplier has `unclaimed_rewards = 500 STRK` (matching the obligation).
3. Token admin calls `set_reward_supplier(new_reward_supplier_address)`.
4. New reward supplier is freshly deployed; `unclaimed_rewards = 1 STRK`.
5. Staker calls `staking.claim_rewards(staker_address)`.
6. Staking contract calls `claim_from_reward_supplier(amount = 500 STRK)` on the new reward supplier.
7. New reward supplier asserts `500 STRK <= 1 STRK` → **REVERTS with `AMOUNT_TOO_HIGH`**.
8. Staker's 500 STRK in rewards is inaccessible.
9. Staker also calls `unstake_action` to recover principal → same revert path → **principal also frozen**.

### Citations

**File:** src/staking/staking.cairo (L495-506)
```text
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

**File:** src/staking/staking.cairo (L1294-1304)
```text
        fn set_reward_supplier(ref self: ContractState, reward_supplier: ContractAddress) {
            self.roles.only_token_admin();
            let old_reward_supplier = self.reward_supplier_dispatcher.contract_address.read();
            self.reward_supplier_dispatcher.contract_address.write(reward_supplier);
            self
                .emit(
                    ConfigEvents::RewardSupplierChanged {
                        old_reward_supplier, new_reward_supplier: reward_supplier,
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

**File:** src/reward_supplier/reward_supplier.cairo (L125-127)
```text
        // Initialize unclaimed_rewards with 1 STRK to make up for round ups of pool rewards
        // calculation in the staking contract.
        self.unclaimed_rewards.write(STRK_IN_FRIS);
```

**File:** src/reward_supplier/reward_supplier.cairo (L213-214)
```text
            let unclaimed_rewards = self.unclaimed_rewards.read();
            assert!(amount <= unclaimed_rewards, "{}", GenericError::AMOUNT_TOO_HIGH);
```

**File:** src/staking/utils.cairo (L50-60)
```text
pub(crate) fn claim_from_reward_supplier(
    reward_supplier_dispatcher: IRewardSupplierDispatcher,
    amount: Amount,
    token_dispatcher: IERC20Dispatcher,
) {
    let staking_contract = get_contract_address();
    let balance_before = token_dispatcher.balance_of(account: staking_contract);
    reward_supplier_dispatcher.claim_rewards(:amount);
    let balance_after = token_dispatcher.balance_of(account: staking_contract);
    assert!(balance_after - balance_before == amount.into(), "{}", Error::UNEXPECTED_BALANCE);
}
```
