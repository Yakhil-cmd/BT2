### Title
Missing Zero-Address Validation on `reward_address` Enables Permanent Freezing of Unclaimed Yield — (`src/staking/staking.cairo`, `src/pool/pool.cairo`)

---

### Summary

Both `change_reward_address` in the `Staking` contract and `change_reward_address` in the `Pool` contract accept an arbitrary `ContractAddress` for `reward_address` without checking whether it is the zero address. Any active staker or pool member can call these functions with `reward_address = 0`, causing all subsequent reward claims to attempt a transfer to address(0). Because OpenZeppelin's ERC20 on Starknet rejects transfers to the zero address, `claim_rewards` (and `unstake_action`) will permanently revert for that staker/pool member, freezing their unclaimed yield forever.

---

### Finding Description

**`change_reward_address` in `staking.cairo`** (lines 517–540) validates only that the new address is not a registered token address (`REWARD_ADDRESS_IS_TOKEN`), but performs no zero-address check:

```cairo
fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
    self.general_prerequisites();
    assert!(
        !self.does_token_exist(token_address: reward_address),
        "{}",
        GenericError::REWARD_ADDRESS_IS_TOKEN,
    );
    // ← No assert!(reward_address.is_non_zero(), ...)
    let staker_address = get_caller_address();
    let mut staker_info = self.internal_staker_info(:staker_address);
    staker_info.reward_address = reward_address;   // zero is written here
    self.write_staker_info(:staker_address, :staker_info);
    ...
}
```

The same gap exists in **`change_reward_address` in `pool.cairo`** (lines 505–526):

```cairo
fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
    assert!(
        self.token_dispatcher.contract_address.read() != reward_address,
        "{}",
        GenericError::REWARD_ADDRESS_IS_TOKEN,
    );
    // ← No zero-address check
    let pool_member = get_caller_address();
    let mut pool_member_info = self.internal_pool_member_info(:pool_member);
    pool_member_info.reward_address = reward_address;   // zero is written here
    ...
}
```

The same gap also exists at initial entry points: `stake()` in `staking.cairo` (line 288) and `enter_delegation_pool()` in `pool.cairo` (line 182) both accept `reward_address` without a zero check.

Once `reward_address = 0` is stored, every downstream reward-routing call hits the zero address:

- **`send_rewards_to_staker`** (`staking.cairo` line 1625): `token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into())` — reverts if `reward_address` is zero.
- **`claim_rewards`** in `pool.cairo` (line 366): `reward_token.checked_transfer(recipient: reward_address, amount: rewards.into())` — same revert.

Because `unstake_action` also calls `send_rewards_to_staker` before returning the principal (line 495), a staker who has set `reward_address = 0` cannot even exit the protocol: the unstake action itself reverts, permanently locking both rewards **and** principal.

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield (and principal for stakers).**

- A staker who sets `reward_address = 0` can never successfully call `claim_rewards` or `unstake_action`. Their accrued STRK rewards are permanently frozen in the staking contract, and their staked principal is also unrecoverable because `unstake_action` reverts before the principal transfer.
- A pool member who sets `reward_address = 0` can never call `claim_rewards`; their accumulated pool rewards are permanently frozen.

---

### Likelihood Explanation

**Medium.** The call is permissionless for any active staker or pool member — no privileged role is required. The scenario is reachable by:
1. Accidental user error (passing zero as the reward address).
2. A griefing attack where an attacker controls a staker/pool-member key and deliberately sets the reward address to zero to permanently freeze that account's yield.

The `CALLER_IS_ZERO_ADDRESS` guard in `general_prerequisites` only prevents the *caller* from being zero; it does not protect the *reward_address parameter*.

---

### Recommendation

Add an explicit zero-address assertion in every function that accepts or stores a `reward_address`:

```cairo
// In staking.cairo change_reward_address and stake:
assert!(reward_address.is_non_zero(), "{}", GenericError::ZERO_ADDRESS);

// In pool.cairo change_reward_address and enter_delegation_pool:
assert!(reward_address.is_non_zero(), "{}", GenericError::ZERO_ADDRESS);
```

The error string `"Zero address"` already exists in the error catalogue (`src/errors.cairo` line 39, `GenericError::ZERO_ADDRESS`), so no new error variant is needed.

---

### Proof of Concept

1. Deploy the system and stake normally.
2. Call `staking.change_reward_address(reward_address: 0)` as the staker — succeeds (no zero check).
3. Accumulate rewards over several epochs.
4. Call `staking.claim_rewards(staker_address)` — reverts because `checked_transfer(recipient: 0, ...)` panics.
5. Call `staking.unstake_intent()` then `staking.unstake_action(staker_address)` after the exit window — also reverts at `send_rewards_to_staker` (line 1625), permanently locking the staker's principal.

The same sequence applies to a pool member via `pool.change_reward_address(0)` followed by `pool.claim_rewards(pool_member)`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L493-496)
```text
            // It must be part of this function's flow because staker_info is about to be erased.
            let token_dispatcher = strk_token_dispatcher();
            self.send_rewards_to_staker(:staker_address, ref :staker_info, :token_dispatcher);
            // Update staker info to storage (it will be erased later).
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

**File:** src/pool/pool.cairo (L364-367)
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
