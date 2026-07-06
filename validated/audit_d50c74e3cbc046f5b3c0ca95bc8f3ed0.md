### Title
Missing Zero-Address Validation in `change_reward_address` Allows Permanent Loss of Unclaimed Yield - (File: `src/staking/staking.cairo`, `src/pool/pool.cairo`)

---

### Summary

Both `Staking.change_reward_address` and `Pool.change_reward_address` accept `ContractAddress(0)` as a valid new reward address without reverting. When rewards are subsequently claimed via `claim_rewards` or `unstake_action`, the protocol unconditionally transfers accumulated yield to whatever address is stored — including address(0) — resulting in permanent loss of unclaimed yield.

---

### Finding Description

**`Staking.change_reward_address`** (`src/staking/staking.cairo`, line 517) performs only one validation on the incoming address: it checks that the address is not a registered token address. There is no zero-address guard:

```cairo
fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
    self.general_prerequisites();
    assert!(
        !self.does_token_exist(token_address: reward_address),
        "{}",
        GenericError::REWARD_ADDRESS_IS_TOKEN,
    );
    // No check: reward_address.is_non_zero()
    staker_info.reward_address = reward_address;
    self.write_staker_info(:staker_address, :staker_info);
    ...
}
``` [1](#0-0) 

**`Pool.change_reward_address`** (`src/pool/pool.cairo`, line 505) mirrors the same pattern — it only checks that the address is not the pool's token address, with no zero-address guard:

```cairo
fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
    assert!(
        self.token_dispatcher.contract_address.read() != reward_address,
        "{}",
        GenericError::REWARD_ADDRESS_IS_TOKEN,
    );
    // No check: reward_address.is_non_zero()
    pool_member_info.reward_address = reward_address;
    ...
}
``` [2](#0-1) 

The same gap exists at initial registration: `Staking.stake` checks that `reward_address` is not a token address but does not check for zero, and `Pool.enter_delegation_pool` stores the caller-supplied `reward_address` directly without a zero check. [3](#0-2) 

**Downstream transfer — staker path**: `send_rewards_to_staker` unconditionally transfers `unclaimed_rewards_own` to whatever `reward_address` is stored in `staker_info`:

```cairo
fn send_rewards_to_staker(...) {
    let reward_address = staker_info.reward_address;
    let amount = staker_info.unclaimed_rewards_own;
    ...
    token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
``` [4](#0-3) 

This internal function is called from both `claim_rewards` and `unstake_action`. [5](#0-4) [6](#0-5) 

**Downstream transfer — pool member path**: `Pool.claim_rewards` transfers directly to the stored `reward_address`:

```cairo
reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
``` [7](#0-6) 

---

### Impact Explanation

If the Starknet STRK ERC-20 implementation does not revert on a transfer to `ContractAddress(0)` (which is the common behavior in Cairo's standard ERC-20 — unlike Solidity OZ which added a zero-address guard), all accumulated `unclaimed_rewards_own` or pool member rewards are sent to the zero address and are **permanently unrecoverable**. This constitutes **permanent freezing of unclaimed yield** (High impact per the allowed scope).

Even if the ERC-20 does revert on zero-address transfer, the effect is that `claim_rewards` and `unstake_action` both revert for the affected staker/pool member until they call `change_reward_address` again — constituting a self-inflicted but protocol-visible griefing / temporary freeze of funds (Medium impact).

---

### Likelihood Explanation

The entry point is fully unprivileged: any active staker or pool member can call `change_reward_address` at any time. The scenario is realistic for:
- A staker who accidentally passes `0` as the reward address (e.g., a scripting error or uninitialized variable).
- A staker who intentionally sets it to zero to "park" the address and forgets to restore it before rewards accumulate.
- A pool member who does the same via `Pool.change_reward_address`.

No privileged role, bridge compromise, or external dependency is required.

---

### Recommendation

Add an explicit zero-address guard in both `change_reward_address` implementations, and also in `stake` and `enter_delegation_pool` at the point where `reward_address` is first stored:

```cairo
assert!(reward_address.is_non_zero(), "{}", GenericError::ZERO_ADDRESS);
```

The pattern is already used elsewhere in the codebase (e.g., `add_token` at line 1346 asserts `token_address.is_non_zero()`). [8](#0-7) 

---

### Proof of Concept

1. Staker `A` calls `Staking.stake(reward_address: 0, operational_address: X, amount: MIN_STAKE)`. The call succeeds because the only reward-address check is `!does_token_exist(0)`, which is `false` (zero is not a registered token). [3](#0-2) 

2. Alternatively, an existing staker calls `Staking.change_reward_address(reward_address: 0)`. The call succeeds for the same reason. [9](#0-8) 

3. Rewards accumulate in `staker_info.unclaimed_rewards_own` over subsequent epochs via `update_rewards_from_attestation_contract` / `update_rewards_from_consensus_contract`.

4. Staker (or anyone) calls `Staking.claim_rewards(staker_address: A)`. Internally, `send_rewards_to_staker` reads `reward_address = 0` and executes `checked_transfer(recipient: 0, amount: rewards)`. [4](#0-3) 

5. If the ERC-20 does not guard against zero-address recipients, the STRK tokens are transferred to address(0) and permanently lost. If it does guard, `claim_rewards` and `unstake_action` both revert, freezing the staker's ability to exit until `change_reward_address` is called with a valid address.

The identical path applies to pool members via `Pool.change_reward_address(0)` followed by `Pool.claim_rewards`. [2](#0-1) [10](#0-9)

### Citations

**File:** src/staking/staking.cairo (L307-311)
```text
            assert!(
                !self.does_token_exist(token_address: reward_address),
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
```

**File:** src/staking/staking.cairo (L426-429)
```text
            let amount = staker_info.unclaimed_rewards_own;
            let token_dispatcher = strk_token_dispatcher();
            self.send_rewards_to_staker(:staker_address, ref :staker_info, :token_dispatcher);
            self.write_staker_info(:staker_address, :staker_info);
```

**File:** src/staking/staking.cairo (L494-495)
```text
            let token_dispatcher = strk_token_dispatcher();
            self.send_rewards_to_staker(:staker_address, ref :staker_info, :token_dispatcher);
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

**File:** src/staking/staking.cairo (L1346-1346)
```text
            assert!(token_address.is_non_zero(), "{}", GenericError::ZERO_ADDRESS);
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
