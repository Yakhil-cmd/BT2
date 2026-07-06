### Title
Reentrancy in `claim_rewards` Allows Repeated Theft of Staker Rewards via Malicious `reward_address` - (File: src/staking/staking.cairo)

### Summary

`staking.cairo`'s `claim_rewards` function calls `send_rewards_to_staker`, which transfers STRK to the staker's `reward_address` via an external ERC-20 call **before** the zeroed `unclaimed_rewards_own` is committed to storage. Because any staker can freely set their `reward_address` to an arbitrary contract, a malicious `reward_address` can re-enter `claim_rewards` while the stale storage value is still non-zero, draining the `RewardSupplier`'s `unclaimed_rewards` pool.

---

### Finding Description

The execution order in `claim_rewards` is:

1. Read `staker_info` from storage (`unclaimed_rewards_own = X`).
2. Call `send_rewards_to_staker` → internally calls `claim_from_reward_supplier(X)` (external call to `RewardSupplier`) then `token_dispatcher.checked_transfer(recipient: reward_address, X)` (external call to `reward_address`).
3. Inside `send_rewards_to_staker`, **after** the transfer, set `staker_info.unclaimed_rewards_own = 0` in the local in-memory copy only.
4. Back in `claim_rewards`, call `write_staker_info` to persist the zeroed value. [1](#0-0) 

The critical window is between steps 2 and 4: the storage still holds `unclaimed_rewards_own = X` while the external transfer at step 2 is executing. [2](#0-1) 

`reward_address` is attacker-controlled — any staker can set it to any contract via `change_reward_address`. [3](#0-2) 

The access control on `claim_rewards` allows `reward_address` itself to be the caller: [4](#0-3) 

So a malicious `reward_address` contract can re-enter `claim_rewards(staker_address)` from within its token-receive hook, pass the caller check (`caller == reward_address`), read the still-stale `unclaimed_rewards_own = X` from storage, and trigger another full reward payout.

The `RewardSupplier.claim_rewards` does decrement its own `unclaimed_rewards` before transferring: [5](#0-4) 

However, in a live system the `RewardSupplier` accumulates rewards for **all** stakers, so its `unclaimed_rewards` balance is typically much larger than any single staker's reward, making repeated re-entrant claims feasible until the pool is exhausted.

The same pattern exists in `unstake_action` — `send_rewards_to_staker` is called at line 495 before `write_staker_info` at line 498, with the developer comment "This is done here to avoid re-entrancy" referring only to the subsequent `remove_staker` call, not to the reward transfer itself: [6](#0-5) 

There is no reentrancy guard anywhere in the codebase.

---

### Impact Explanation

**High — Theft of unclaimed yield.**

A malicious staker can drain the `RewardSupplier`'s `unclaimed_rewards` balance, stealing yield that belongs to all other stakers and pool members. The `RewardSupplier` is the single source of STRK rewards for the entire protocol; draining it permanently freezes yield for every other participant.

---

### Likelihood Explanation

**Medium-High.** The attacker only needs to:
1. Stake the minimum amount (permissionless).
2. Set `reward_address` to a malicious contract (permissionless, via `change_reward_address`).
3. Wait for any rewards to accumulate (one epoch is sufficient).
4. Call `claim_rewards`.

No privileged access, leaked keys, or external dependency compromise is required. The only constraint is that the `RewardSupplier` must hold enough `unclaimed_rewards` to cover the re-entrant claim, which is virtually guaranteed in a live multi-staker system.

---

### Recommendation

Apply the checks-effects-interactions pattern: zero `staker_info.unclaimed_rewards_own` and write it to storage **before** making any external call. Concretely, in `send_rewards_to_staker`, move the storage write ahead of both external calls:

```cairo
fn send_rewards_to_staker(...) {
    let reward_address = staker_info.reward_address;
    let amount = staker_info.unclaimed_rewards_own;
    // Zero out BEFORE any external call
    staker_info.unclaimed_rewards_own = Zero::zero();
    // Caller must write staker_info to storage here (or do it inside this fn)
    // ...then make external calls
    claim_from_reward_supplier(...);
    token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
}
```

Alternatively, add an explicit reentrancy guard (lock flag in storage) to `claim_rewards` and `unstake_action`.

---

### Proof of Concept

```
1. Attacker deploys MaliciousReward contract with a hook on STRK receipt that calls
   staking.claim_rewards(attacker_staker_address).

2. Attacker calls staking.stake(...) with reward_address = MaliciousReward.

3. One epoch passes; attacker accumulates unclaimed_rewards_own = R in storage.

4. Attacker (or MaliciousReward) calls staking.claim_rewards(attacker_staker_address).
   - caller == reward_address check passes.
   - send_rewards_to_staker:
       a. claim_from_reward_supplier(R) → RewardSupplier.unclaimed_rewards -= R,
          R tokens sent to Staking contract.
       b. STRK.transfer(MaliciousReward, R) → triggers MaliciousReward hook.
          [Storage still has unclaimed_rewards_own = R]

5. MaliciousReward hook calls staking.claim_rewards(attacker_staker_address).
   - caller == reward_address check passes.
   - send_rewards_to_staker:
       a. claim_from_reward_supplier(R) → RewardSupplier.unclaimed_rewards -= R again
          (succeeds if RewardSupplier still has >= R from other stakers' accrued rewards).
       b. STRK.transfer(MaliciousReward, R) → triggers hook again.

6. Steps 5–6 repeat until RewardSupplier.unclaimed_rewards < R, at which point
   the inner claim_from_reward_supplier reverts and the recursion unwinds.

Net result: Attacker received k*R tokens while only being owed R,
draining (k-1)*R from other stakers' yield.
```

### Citations

**File:** src/staking/staking.cairo (L415-421)
```text
            let caller_address = get_caller_address();
            let reward_address = staker_info.reward_address;
            assert!(
                caller_address == staker_address || caller_address == reward_address,
                "{}",
                Error::CLAIM_REWARDS_FROM_UNAUTHORIZED_ADDRESS,
            );
```

**File:** src/staking/staking.cairo (L426-430)
```text
            let amount = staker_info.unclaimed_rewards_own;
            let token_dispatcher = strk_token_dispatcher();
            self.send_rewards_to_staker(:staker_address, ref :staker_info, :token_dispatcher);
            self.write_staker_info(:staker_address, :staker_info);
            amount
```

**File:** src/staking/staking.cairo (L492-498)
```text
            // Send rewards to staker's reward address.
            // It must be part of this function's flow because staker_info is about to be erased.
            let token_dispatcher = strk_token_dispatcher();
            self.send_rewards_to_staker(:staker_address, ref :staker_info, :token_dispatcher);
            // Update staker info to storage (it will be erased later).
            // This is done here to avoid re-entrancy.
            self.write_staker_info(:staker_address, :staker_info);
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
