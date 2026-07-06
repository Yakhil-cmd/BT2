### Title
Reentrancy in `claim_rewards` Allows Draining of Reward Supplier via Malicious `reward_address` - (File: src/staking/staking.cairo)

### Summary

The `claim_rewards` function in `staking.cairo` transfers STRK rewards to the staker's `reward_address` before committing the zeroed `unclaimed_rewards_own` to storage. A staker who sets `reward_address` to a malicious contract can re-enter `claim_rewards` during the token transfer, reading the still-non-zero `unclaimed_rewards_own` from storage and claiming the same rewards repeatedly until the `RewardSupplier`'s global `unclaimed_rewards` balance is exhausted.

### Finding Description

**Root cause — checks-effects-interactions violation in `send_rewards_to_staker`:**

`claim_rewards` delegates the actual payout to the internal helper `send_rewards_to_staker`:

```cairo
// src/staking/staking.cairo  lines 411-431
fn claim_rewards(ref self: ContractState, staker_address: ContractAddress) -> Amount {
    self.general_prerequisites();
    let mut staker_info = self.internal_staker_info(:staker_address);
    let caller_address = get_caller_address();
    let reward_address = staker_info.reward_address;
    assert!(
        caller_address == staker_address || caller_address == reward_address, ...
    );
    let amount = staker_info.unclaimed_rewards_own;
    let token_dispatcher = strk_token_dispatcher();
    self.send_rewards_to_staker(:staker_address, ref :staker_info, :token_dispatcher);
    self.write_staker_info(:staker_address, :staker_info);   // ← storage write AFTER transfer
    amount
}
``` [1](#0-0) 

Inside `send_rewards_to_staker`, the sequence is:

1. Read `amount = staker_info.unclaimed_rewards_own` (local copy).
2. Call `claim_from_reward_supplier(amount)` → reward supplier decrements its global `unclaimed_rewards` and sends `amount` STRK to the staking contract.
3. **Transfer `amount` STRK to `reward_address`** (external call — reentrancy window opens here).
4. Set `staker_info.unclaimed_rewards_own = Zero::zero()` on the **local** variable only.

```cairo
// src/staking/staking.cairo  lines 1614-1629
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
    token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into()); // ← external call
    staker_info.unclaimed_rewards_own = Zero::zero();  // ← local var only, storage not yet updated
    self.emit(Events::StakerRewardClaimed { staker_address, reward_address, amount });
}
``` [2](#0-1) 

Because `write_staker_info` is only called in `claim_rewards` **after** `send_rewards_to_staker` returns, the on-chain storage value of `unclaimed_rewards_own` remains `X` throughout the entire transfer. Any re-entrant call to `claim_rewards` reads `X` from storage and repeats the payout.

The re-entrant call passes the caller check because `caller_address == reward_address` is satisfied by the malicious contract:

```cairo
assert!(
    caller_address == staker_address || caller_address == reward_address, ...
);
``` [3](#0-2) 

The `RewardSupplier.claim_rewards` correctly updates its own `unclaimed_rewards` before transferring, but that global counter accumulates rewards for **all** stakers, so it typically holds far more than a single staker's `X`:

```cairo
// src/reward_supplier/reward_supplier.cairo  lines 213-219
let unclaimed_rewards = self.unclaimed_rewards.read();
assert!(amount <= unclaimed_rewards, "{}", GenericError::AMOUNT_TOO_HIGH);
self.unclaimed_rewards.write(unclaimed_rewards - amount);
let token_dispatcher = self.token_dispatcher.read();
token_dispatcher.checked_transfer(recipient: staking_contract, amount: amount.into());
``` [4](#0-3) 

The same reentrancy window exists in `unstake_action`, which also calls `send_rewards_to_staker` before writing staker state:

```cairo
// src/staking/staking.cairo  lines 494-498
self.send_rewards_to_staker(:staker_address, ref :staker_info, :token_dispatcher);
// Update staker info to storage (it will be erased later).
// This is done here to avoid re-entrancy.
self.write_staker_info(:staker_address, :staker_info);
``` [5](#0-4) 

The comment acknowledges a reentrancy concern but only guards the subsequent stake-return transfer; the reward transfer in `send_rewards_to_staker` is still unprotected.

### Impact Explanation

A malicious staker can drain the `RewardSupplier`'s entire `unclaimed_rewards` balance — which represents the accumulated, not-yet-claimed yield of **all** stakers in the protocol. Each re-entrant iteration extracts `X` (the attacker's own `unclaimed_rewards_own`) from the global pool. The attack terminates only when the reward supplier's balance falls below `X`. This constitutes **theft of unclaimed yield** (High severity per the allowed impact scope).

### Likelihood Explanation

Any unprivileged user can become a staker and freely choose their `reward_address` at stake time or change it later via `change_reward_address`. No privileged access, leaked keys, or external dependency compromise is required. The attacker only needs to accumulate a non-zero `unclaimed_rewards_own`, which happens automatically as rewards are distributed. The attack is straightforward to implement as a re-entrant Cairo contract.

### Recommendation

Apply the checks-effects-interactions pattern inside `send_rewards_to_staker`: zero out `staker_info.unclaimed_rewards_own` **and commit it to storage** before making any external token transfer. Concretely, move `write_staker_info` (or an equivalent targeted storage write) to occur before the `checked_transfer` call. Alternatively, add a reentrancy guard (a boolean lock in storage) that is set before any external call and cleared after.

### Proof of Concept

1. Attacker deploys malicious contract `M` implementing a `receive`/fallback that calls `staking.claim_rewards(attacker_staker_address)`.
2. Attacker calls `staking.stake(reward_address: M, ...)` with the minimum stake.
3. Attacker waits for rewards to accumulate (say `X` STRK in `unclaimed_rewards_own`).
4. Attacker calls `staking.claim_rewards(attacker_staker_address)` (or `M` calls it directly, satisfying the `caller == reward_address` check).
5. `send_rewards_to_staker` calls `claim_from_reward_supplier(X)` → reward supplier's `unclaimed_rewards` decremented by `X`; `X` STRK sent to staking contract.
6. `checked_transfer(recipient: M, amount: X)` triggers `M`'s callback.
7. `M` re-enters `claim_rewards(attacker_staker_address)`. Storage still shows `unclaimed_rewards_own = X`.
8. Steps 5–7 repeat recursively until `reward_supplier.unclaimed_rewards < X`.
9. All recursive frames unwind; `write_staker_info` writes `unclaimed_rewards_own = 0` — but the attacker has already received `N * X` STRK where `N = floor(initial_unclaimed_rewards / X)`.

### Citations

**File:** src/staking/staking.cairo (L411-431)
```text
        fn claim_rewards(ref self: ContractState, staker_address: ContractAddress) -> Amount {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let mut staker_info = self.internal_staker_info(:staker_address);
            let caller_address = get_caller_address();
            let reward_address = staker_info.reward_address;
            assert!(
                caller_address == staker_address || caller_address == reward_address,
                "{}",
                Error::CLAIM_REWARDS_FROM_UNAUTHORIZED_ADDRESS,
            );

            // Transfer rewards to staker's reward address and write updated staker info to storage.
            // Note: `send_rewards_to_staker` alters `staker_info` thus commit to storage is
            // performed only after that.
            let amount = staker_info.unclaimed_rewards_own;
            let token_dispatcher = strk_token_dispatcher();
            self.send_rewards_to_staker(:staker_address, ref :staker_info, :token_dispatcher);
            self.write_staker_info(:staker_address, :staker_info);
            amount
        }
```

**File:** src/staking/staking.cairo (L494-498)
```text
            let token_dispatcher = strk_token_dispatcher();
            self.send_rewards_to_staker(:staker_address, ref :staker_info, :token_dispatcher);
            // Update staker info to storage (it will be erased later).
            // This is done here to avoid re-entrancy.
            self.write_staker_info(:staker_address, :staker_info);
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

**File:** src/reward_supplier/reward_supplier.cairo (L213-219)
```text
            let unclaimed_rewards = self.unclaimed_rewards.read();
            assert!(amount <= unclaimed_rewards, "{}", GenericError::AMOUNT_TOO_HIGH);

            // Update unclaimed_rewards and transfer the requested rewards to the staking contract.
            self.unclaimed_rewards.write(unclaimed_rewards - amount);
            let token_dispatcher = self.token_dispatcher.read();
            token_dispatcher.checked_transfer(recipient: staking_contract, amount: amount.into());
```
