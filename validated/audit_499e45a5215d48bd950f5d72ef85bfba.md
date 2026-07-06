### Title
Missing Zero Address Validation on `reward_address` Allows Permanent Freezing of Unclaimed Yield — (`src/staking/staking.cairo`, `src/pool/pool.cairo`)

---

### Summary

Both `change_reward_address` in the staking and pool contracts, as well as the initial `stake` and `enter_delegation_pool` entry points, accept a zero address (`0x0`) as a valid `reward_address` without any validation. Once set, any subsequent call to `claim_rewards` or `unstake_action` will attempt to transfer STRK tokens to the zero address via `checked_transfer`, which reverts under the OpenZeppelin ERC20 implementation used on Starknet. This permanently blocks reward withdrawal and, critically, also blocks `unstake_action` (which calls `send_rewards_to_staker` before returning principal), trapping the staker's principal until the reward address is corrected.

---

### Finding Description

**Root cause — `change_reward_address` in `staking.cairo`:** [1](#0-0) 

The only validation performed is that `reward_address` is not a registered token address. There is no `assert!(reward_address.is_non_zero(), ...)` guard.

**Root cause — `change_reward_address` in `pool.cairo`:** [2](#0-1) 

Same omission: only the token-address check is present; zero address is accepted.

**Root cause — `stake` in `staking.cairo`:** [3](#0-2) 

`reward_address` is only checked against registered token addresses; zero address passes.

**Root cause — `enter_delegation_pool` in `pool.cairo`:** [4](#0-3) 

Same pattern: only the token-address check, no zero address guard.

**Downstream failure — `send_rewards_to_staker`:** [5](#0-4) 

`checked_transfer(recipient: reward_address, ...)` is called unconditionally. When `reward_address == 0x0`, the OZ ERC20 `_transfer` rejects the zero recipient and reverts.

**Downstream failure — `unstake_action` calls `send_rewards_to_staker` before returning principal:** [6](#0-5) 

Because `send_rewards_to_staker` is called before the principal transfer, a revert here blocks the entire `unstake_action`, trapping the staker's principal.

**Downstream failure — pool `claim_rewards`:** [7](#0-6) 

Same pattern: unconditional `checked_transfer` to `reward_address`.

---

### Impact Explanation

A staker or pool member who sets (or initially registers) `reward_address = 0x0` will find:

1. **`claim_rewards` permanently reverts** — unclaimed yield is frozen.
2. **`unstake_action` permanently reverts** — because `send_rewards_to_staker` is called first and reverts, the staker cannot retrieve their principal either.

The freeze persists until the staker calls `change_reward_address` with a valid address. If the staker is a smart contract without that capability, or if the account is inaccessible, the freeze is permanent.

**Matched allowed impact**: *Permanent freezing of unclaimed yield* (High) and *Temporary/permanent freezing of funds* (High/Critical).

---

### Likelihood Explanation

- Any staker or pool member can call `change_reward_address(0x0)` directly — no privileged role required.
- A staker can also pass `reward_address = 0x0` at initial `stake()` time.
- The `ZERO_ADDRESS` error variant already exists in `GenericError` [8](#0-7)  confirming the protocol intends to guard against zero addresses in other contexts, making this omission an oversight rather than a design choice.
- No external dependency, oracle, or privileged key is required to trigger this.

---

### Recommendation

Add a zero address guard in all four entry points:

1. `staking.cairo` → `stake`: assert `reward_address.is_non_zero()`
2. `staking.cairo` → `change_reward_address`: assert `reward_address.is_non_zero()`
3. `pool.cairo` → `enter_delegation_pool`: assert `reward_address.is_non_zero()`
4. `pool.cairo` → `change_reward_address`: assert `reward_address.is_non_zero()`

Use the existing `GenericError::ZERO_ADDRESS` error for consistency.

---

### Proof of Concept

1. Staker calls `staking.stake(reward_address: 0x0, operational_address: X, amount: MIN_STAKE)` — succeeds (no zero address check).
2. Epochs advance; rewards accrue in `staker_info.unclaimed_rewards_own`.
3. Staker calls `staking.claim_rewards(staker_address)` → `send_rewards_to_staker` → `checked_transfer(recipient: 0x0, amount: rewards)` → **reverts** (OZ ERC20 rejects zero recipient). Unclaimed yield is frozen.
4. Staker calls `staking.unstake_intent()` — succeeds.
5. Exit window passes.
6. Anyone calls `staking.unstake_action(staker_address)` → `send_rewards_to_staker` → same revert. **Principal is also trapped.**
7. Recovery requires the staker to call `change_reward_address` with a valid address before step 6 — if the account is inaccessible, the freeze is permanent.

### Citations

**File:** src/staking/staking.cairo (L307-311)
```text
            assert!(
                !self.does_token_exist(token_address: reward_address),
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
```

**File:** src/staking/staking.cairo (L494-506)
```text
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

**File:** src/pool/pool.cairo (L194-196)
```text
            assert!(token_address != pool_member, "{}", Error::POOL_MEMBER_IS_TOKEN);
            assert!(token_address != reward_address, "{}", GenericError::REWARD_ADDRESS_IS_TOKEN);
            // Transfer funds from the delegator to the staking contract.
```

**File:** src/pool/pool.cairo (L364-366)
```text
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

**File:** src/errors.cairo (L39-39)
```text
            GenericError::ZERO_ADDRESS => "Address is zero",
```
