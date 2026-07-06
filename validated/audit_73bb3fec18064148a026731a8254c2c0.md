### Title
Missing `reward_address != contract_address` Validation Permanently Freezes Unclaimed Yield - (File: `src/staking/staking.cairo`, `src/pool/pool.cairo`)

---

### Summary
Both the `Staking` and `DelegationPool` contracts accept a `reward_address` parameter in multiple entry points without validating that it is not the contract's own address. A staker or pool member who (accidentally or deliberately) supplies the staking contract's address or the pool contract's address as their `reward_address` will have all future reward transfers silently sent to the contract itself, where they are permanently irrecoverable.

---

### Finding Description

**Staking contract — `stake` and `change_reward_address`**

`stake()` validates only that `reward_address` is not a registered token address:

```cairo
assert!(
    !self.does_token_exist(token_address: reward_address),
    "{}",
    GenericError::REWARD_ADDRESS_IS_TOKEN,
);
``` [1](#0-0) 

`change_reward_address()` applies the identical single check:

```cairo
assert!(
    !self.does_token_exist(token_address: reward_address),
    "{}",
    GenericError::REWARD_ADDRESS_IS_TOKEN,
);
``` [2](#0-1) 

Neither function checks `reward_address != get_contract_address()`. When rewards are later paid out, `send_rewards_to_staker` unconditionally transfers to whatever address is stored:

```cairo
token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
``` [3](#0-2) 

If `reward_address` is the staking contract itself, the transfer is a no-op on the contract's balance, `unclaimed_rewards_own` is zeroed, and the tokens are permanently unaccounted for.

---

**Pool contract — `enter_delegation_pool` and `change_reward_address`**

`enter_delegation_pool()` validates only that `reward_address` is not the token address:

```cairo
assert!(token_address != reward_address, "{}", GenericError::REWARD_ADDRESS_IS_TOKEN);
``` [4](#0-3) 

`change_reward_address()` in the pool applies the same single check:

```cairo
assert!(
    self.token_dispatcher.contract_address.read() != reward_address,
    "{}",
    GenericError::REWARD_ADDRESS_IS_TOKEN,
);
``` [5](#0-4) 

Neither function checks `reward_address != get_contract_address()`. When `claim_rewards` is called, the pool transfers directly to the stored `reward_address`:

```cairo
reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
``` [6](#0-5) 

If `reward_address` is the pool contract itself, the transfer is a self-transfer (no-op on balance), the pool member's unclaimed rewards are zeroed, and the STRK tokens remain in the pool contract's balance — outside the cumulative rewards trace — and are never distributed to anyone.

---

### Impact Explanation

Rewards sent to the staking contract or pool contract are permanently frozen:

- The staking contract has no sweep/recovery function for arbitrary token balances.
- The pool contract distributes rewards exclusively through the `cumulative_rewards_trace` mechanism; tokens that arrive outside that mechanism (i.e., via a self-transfer) are never accounted for and cannot be claimed by any pool member.
- The affected user's `unclaimed_rewards_own` / pool member reward state is zeroed, so the loss is final and irreversible.

Impact: **Permanent freezing of unclaimed yield** — High severity per the allowed impact scope.

---

### Likelihood Explanation

Any unprivileged staker or pool member can trigger this:

- By calling `stake(reward_address = staking_contract_address, ...)` directly.
- By calling `change_reward_address(reward_address = staking_contract_address)` on the staking contract after staking.
- By calling `enter_delegation_pool(reward_address = pool_contract_address, ...)` on the pool contract.
- By calling `change_reward_address(reward_address = pool_contract_address)` on the pool contract after joining.

No privileged role, leaked key, or external dependency is required. The entry paths are fully public and reachable by any wallet. Accidental misconfiguration (e.g., copy-paste of the contract address) is a realistic scenario.

---

### Recommendation

Add an explicit guard in each of the four affected entry points:

```cairo
// In staking.cairo — stake() and change_reward_address()
assert!(
    reward_address != get_contract_address(),
    "Reward address cannot be the staking contract",
);

// In pool.cairo — enter_delegation_pool() and change_reward_address()
assert!(
    reward_address != get_contract_address(),
    "Reward address cannot be the pool contract",
);
```

Additionally, consider rejecting the staking contract address as a pool `reward_address` and vice versa, to close the cross-contract variant of the same bug.

---

### Proof of Concept

**Pool variant (most direct analog):**

1. Staker deploys a pool via `set_open_for_delegation`.
2. Attacker (pool member) calls `enter_delegation_pool(reward_address: pool_contract_address, amount: X)`. No assertion fires because `pool_contract_address != token_address`.
3. Staker attests; rewards accumulate; staking contract calls `update_rewards_from_staking_contract(rewards, pool_balance)` — the cumulative trace is updated.
4. Attacker calls `claim_rewards(pool_member: attacker_address)`. The pool calculates `rewards > 0`, then executes `reward_token.checked_transfer(recipient: pool_contract_address, amount: rewards)` — a self-transfer. The pool member's state is zeroed.
5. The STRK tokens remain in the pool contract's balance, outside the cumulative trace. No pool member can ever claim them. They are permanently frozen.

**Staking variant:**

1. Staker calls `stake(reward_address: staking_contract_address, ...)`. No assertion fires because `staking_contract_address` is not a registered token.
2. Staker attests; `unclaimed_rewards_own` accumulates.
3. Anyone calls `claim_rewards(staker_address)`. `send_rewards_to_staker` claims from the reward supplier and executes `token_dispatcher.checked_transfer(recipient: staking_contract_address, amount: rewards)` — a self-transfer. `unclaimed_rewards_own` is zeroed.
4. The STRK tokens remain in the staking contract's balance, indistinguishable from staked principal. They are permanently frozen.

### Citations

**File:** src/staking/staking.cairo (L307-311)
```text
            assert!(
                !self.does_token_exist(token_address: reward_address),
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
```

**File:** src/staking/staking.cairo (L520-524)
```text
            assert!(
                !self.does_token_exist(token_address: reward_address),
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
```

**File:** src/staking/staking.cairo (L1625-1625)
```text
            token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
```

**File:** src/pool/pool.cairo (L195-195)
```text
            assert!(token_address != reward_address, "{}", GenericError::REWARD_ADDRESS_IS_TOKEN);
```

**File:** src/pool/pool.cairo (L366-366)
```text
            reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
```

**File:** src/pool/pool.cairo (L506-510)
```text
            assert!(
                self.token_dispatcher.contract_address.read() != reward_address,
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
```
