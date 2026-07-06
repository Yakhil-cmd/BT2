### Title
Race Condition in `change_reward_address` Allows Compromised Reward Address to Front-Run and Steal Unclaimed Yield - (File: src/staking/staking.cairo, src/pool/pool.cairo)

### Summary
Both the `Staking` and `Pool` contracts grant the registered `reward_address` active authority to call `claim_rewards`. When a staker or pool member attempts to revoke a compromised `reward_address` by calling `change_reward_address`, there is a race condition window in which the attacker controlling the old `reward_address` can front-run the address-change transaction and drain all accumulated unclaimed rewards to the compromised address.

### Finding Description
In `src/staking/staking.cairo`, `claim_rewards` explicitly authorizes the `reward_address` as a valid caller:

```cairo
assert!(
    caller_address == staker_address || caller_address == reward_address,
    "{}",
    Error::CLAIM_REWARDS_FROM_UNAUTHORIZED_ADDRESS,
);
```

The same pattern exists in `src/pool/pool.cairo` for pool members:

```cairo
assert!(
    caller_address == pool_member || caller_address == reward_address,
    "{}",
    Error::POOL_CLAIM_REWARDS_FROM_UNAUTHORIZED_ADDRESS,
);
```

`change_reward_address` in both contracts performs an immediate, single-step overwrite of the stored `reward_address` with no time-lock, no pending-state, and no mechanism to atomically revoke the old address's claim authority at the same time as the address update. There is no way for a staker to atomically (a) revoke the old `reward_address`'s claim authority and (b) claim outstanding rewards to a safe address in a single transaction.

### Impact Explanation
If the `reward_address` is compromised, the attacker can call `claim_rewards(staker_address)` from the old `reward_address` at any time. When the staker submits `change_reward_address(new_safe_address)` to revoke the compromised address, the attacker can observe the pending transaction and submit `claim_rewards` first. Because the Starknet sequencer orders transactions and can see the pending queue, the attacker's `claim_rewards` transaction can be included before the `change_reward_address` transaction, sending all accumulated unclaimed STRK rewards to the compromised address. This constitutes **theft of unclaimed yield** (High severity).

### Likelihood Explanation
The `reward_address` is commonly set to a hot wallet or a separate contract for operational convenience. Compromise of such an address is a realistic scenario (phishing, key exposure, contract exploit). Once compromised, the attacker has an indefinitely open window to drain rewards at any time, and specifically can front-run any revocation attempt. The attack requires no privileged protocol role — only control of the `reward_address`, which is a user-level authorization the staker themselves granted.

### Recommendation
**Short term:** Document that `reward_address` holders have active claim authority, not merely passive receipt. Advise users to call `claim_rewards` themselves (as `staker_address`) before calling `change_reward_address` to minimize the unclaimed balance at risk.

**Long term:** Introduce a two-step `reward_address` change with a time-lock (similar to the existing `unstake_intent`/`unstake_action` pattern), or allow `change_reward_address` to atomically claim outstanding rewards to the new address in the same transaction, eliminating the race window entirely.

### Proof of Concept
1. Alice stakes and sets `reward_address = HotWallet`.
2. `HotWallet` is compromised by an attacker.
3. Alice submits `change_reward_address(SafeWallet)` to revoke `HotWallet`'s authority.
4. The attacker observes Alice's pending transaction and submits `claim_rewards(alice_staker_address)` from `HotWallet` with a higher fee (or simply races the sequencer ordering).
5. If the attacker's `claim_rewards` is sequenced before Alice's `change_reward_address`, all of Alice's accumulated `unclaimed_rewards_own` are transferred to `HotWallet` via `send_rewards_to_staker` at line 1625 of `staking.cairo`.
6. Alice's `change_reward_address` then confirms, but the rewards are already gone.

The identical race condition exists for pool members via `Pool::claim_rewards` (line 366, `pool.cairo`) and `Pool::change_reward_address` (line 505, `pool.cairo`).

---

**Root cause — Staking contract:** [1](#0-0) [2](#0-1) [3](#0-2) 

**Root cause — Pool contract:** [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** src/staking/staking.cairo (L529-531)
```text
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

**File:** src/pool/pool.cairo (L338-344)
```text
            let caller_address = get_caller_address();
            let reward_address = pool_member_info.reward_address;
            assert!(
                caller_address == pool_member || caller_address == reward_address,
                "{}",
                Error::POOL_CLAIM_REWARDS_FROM_UNAUTHORIZED_ADDRESS,
            );
```

**File:** src/pool/pool.cairo (L364-366)
```text
            // Transfer rewards to the pool member.
            let reward_token = IERC20Dispatcher { contract_address: STRK_TOKEN_ADDRESS };
            reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
```

**File:** src/pool/pool.cairo (L515-517)
```text
            // Update reward_address and commit to storage.
            pool_member_info.reward_address = reward_address;
            self.write_pool_member_info(:pool_member, :pool_member_info);
```
