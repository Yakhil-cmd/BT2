### Title
Re-entrancy in `claim_rewards` Allows Repeated Draining of Staker Unclaimed Yield Before State Commit - (File: src/staking/staking.cairo)

---

### Summary

`Staking.claim_rewards` transfers STRK rewards to the staker's `reward_address` **before** committing the zeroed `unclaimed_rewards_own` to storage. If `reward_address` is a malicious contract, it can re-enter `claim_rewards` during the token transfer, observe the stale (non-zero) `unclaimed_rewards_own` in storage, and claim the same rewards again. This can be repeated until the `RewardSupplier`'s `unclaimed_rewards` balance is exhausted.

---

### Finding Description

In `src/staking/staking.cairo`, `claim_rewards` (lines 411–431) follows this sequence:

1. **Read** `staker_info` from storage — `unclaimed_rewards_own` is non-zero (line 414).
2. Call `send_rewards_to_staker` (line 428), which internally:
   - Calls `claim_from_reward_supplier` — pulls tokens into the staking contract (line 1624).
   - Calls `token_dispatcher.checked_transfer(recipient: reward_address, ...)` — **external call, re-entry point** (line 1625).
   - Sets `staker_info.unclaimed_rewards_own = Zero::zero()` — **local variable only, not storage** (line 1626).
3. **Write** updated `staker_info` to storage (line 429) — **only after the external transfer returns**.

During step 2b, if `reward_address` is a contract, it can call back into `claim_rewards(staker_address)`. At that moment, on-chain storage still holds the original `staker_info` with non-zero `unclaimed_rewards_own`. The re-entrant call:
- Passes the access-control check (`caller == reward_address == staker_info.reward_address`).
- Reads the stale `staker_info` with non-zero rewards.
- Calls `claim_from_reward_supplier` again, pulling more tokens from the `RewardSupplier`.
- Transfers those tokens to `reward_address` again.
- Writes `unclaimed_rewards_own = 0` to storage.
- Returns; the outer call then also writes `unclaimed_rewards_own = 0` (already done, no harm).

The `RewardSupplier.claim_rewards` (reward_supplier.cairo lines 205–220) does decrement its own `unclaimed_rewards` before transferring, so each re-entrant iteration requires the reward supplier to still hold enough balance. However, the reward supplier accumulates rewards for all stakers, so its balance is typically much larger than any single staker's claim, enabling multiple re-entrant iterations.

The developers were explicitly aware of this pattern in `unstake_action` (staking.cairo lines 496–498), where they write:
```
// Update staker info to storage (it will be erased later).
// This is done here to avoid re-entrancy.
self.write_staker_info(:staker_address, :staker_info);
```
This protection was applied to `unstake_action` but **not** to `claim_rewards`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

---

### Impact Explanation

**High — Theft of unclaimed yield.**

An attacker who controls the `reward_address` of a staker can drain the `RewardSupplier`'s `unclaimed_rewards` balance far beyond their own legitimate entitlement. Each re-entrant iteration claims the staker's full `unclaimed_rewards_own` again from the reward supplier. The reward supplier holds pooled rewards for all stakers, so the attacker can steal yield belonging to other stakers and the protocol. [5](#0-4) 

---

### Likelihood Explanation

**Medium-High.** The attacker only needs to:
1. Be a staker (no privileged role — any address can call `stake()`).
2. Call `change_reward_address` to set their reward address to a malicious contract. The only restriction is that the address must not be a registered token address.
3. Wait for rewards to accumulate, then trigger `claim_rewards`.

No leaked keys, bridge compromise, or governance access is required. The entry path is fully permissionless. [6](#0-5) 

---

### Recommendation

Commit the updated `staker_info` (with `unclaimed_rewards_own = 0`) to storage **before** making any external token transfer, exactly as `unstake_action` does. In `claim_rewards`, move `self.write_staker_info` to before the `send_rewards_to_staker` call, or zero out `staker_info.unclaimed_rewards_own` and write it to storage before the transfer occurs inside `send_rewards_to_staker`.

```cairo
// Recommended fix in claim_rewards:
let amount = staker_info.unclaimed_rewards_own;
staker_info.unclaimed_rewards_own = Zero::zero();
self.write_staker_info(:staker_address, :staker_info); // commit BEFORE transfer
let token_dispatcher = strk_token_dispatcher();
self.send_rewards_to_staker(:staker_address, ref :staker_info, :token_dispatcher);
``` [7](#0-6) 

---

### Proof of Concept

1. Attacker deploys `MaliciousRewardAddress`, a contract whose token-receive hook calls `IStaking(staking).claim_rewards(attacker_staker_address)`.
2. Attacker calls `staking.stake(...)` with minimum stake, becoming a valid staker.
3. Attacker calls `staking.change_reward_address(MaliciousRewardAddress)`.
4. After K epochs and attestation, `staker_info.unclaimed_rewards_own` becomes non-zero (e.g., `R`).
5. Attacker (or anyone) calls `staking.claim_rewards(attacker_staker_address)`.
6. Staking contract calls `claim_from_reward_supplier(amount=R)` — reward supplier decrements its `unclaimed_rewards` by `R` and transfers `R` STRK to staking contract.
7. Staking contract calls `checked_transfer(recipient: MaliciousRewardAddress, amount: R)`.
8. `MaliciousRewardAddress` receives `R` STRK and immediately calls `staking.claim_rewards(attacker_staker_address)` again.
9. Storage still shows `unclaimed_rewards_own = R` (not yet zeroed). Re-entrant call passes auth check, calls `claim_from_reward_supplier(R)` again (succeeds if reward supplier still has ≥ R), transfers another `R` STRK to `MaliciousRewardAddress`.
10. Steps 8–9 repeat until the reward supplier's `unclaimed_rewards` is exhausted.
11. Re-entrant calls unwind; outer call writes `unclaimed_rewards_own = 0`.

Net result: attacker receives `N * R` STRK where `N` is the number of successful re-entrant iterations, stealing yield from the reward supplier that belongs to all other stakers. [8](#0-7) [4](#0-3)

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

**File:** src/staking/staking.cairo (L495-498)
```text
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

**File:** src/reward_supplier/reward_supplier.cairo (L205-220)
```text
        fn claim_rewards(ref self: ContractState, amount: Amount) {
            // Asserts.
            let staking_contract = self.staking_contract.read();
            assert!(
                get_caller_address() == staking_contract,
                "{}",
                GenericError::CALLER_IS_NOT_STAKING_CONTRACT,
            );
            let unclaimed_rewards = self.unclaimed_rewards.read();
            assert!(amount <= unclaimed_rewards, "{}", GenericError::AMOUNT_TOO_HIGH);

            // Update unclaimed_rewards and transfer the requested rewards to the staking contract.
            self.unclaimed_rewards.write(unclaimed_rewards - amount);
            let token_dispatcher = self.token_dispatcher.read();
            token_dispatcher.checked_transfer(recipient: staking_contract, amount: amount.into());
        }
```
