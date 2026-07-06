### Title
Pool `change_reward_address` Only Guards Against Its Own Token, Allowing Reward Address to Be Set to Any Other Managed Token Address — (File: `src/pool/pool.cairo`)

### Summary

`Pool.change_reward_address` validates the new reward address only against the pool's own token. When the system has multiple managed tokens (STRK + BTC), a pool member in a STRK pool can set their reward address to the BTC token contract address (and vice versa). When `claim_rewards` is subsequently called, STRK rewards are transferred directly to the BTC token contract, permanently freezing the unclaimed yield.

### Finding Description

The staking contract's `change_reward_address` correctly uses `does_token_exist`, which checks the reward address against **all** managed tokens (STRK and every registered BTC token): [1](#0-0) 

```cairo
fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
    self.general_prerequisites();
    assert!(
        !self.does_token_exist(token_address: reward_address),
        "{}",
        GenericError::REWARD_ADDRESS_IS_TOKEN,
    );
```

`does_token_exist` covers the full managed token set: [2](#0-1) 

```cairo
fn does_token_exist(self: @ContractState, token_address: ContractAddress) -> bool {
    token_address == STRK_TOKEN_ADDRESS || self.btc_tokens.read(token_address).is_some()
}
```

The pool contract's `change_reward_address`, however, only compares against the single token the pool was deployed for: [3](#0-2) 

```cairo
fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
    assert!(
        self.token_dispatcher.contract_address.read() != reward_address,
        "{}",
        GenericError::REWARD_ADDRESS_IS_TOKEN,
    );
```

If the pool is a STRK pool, `self.token_dispatcher.contract_address` is the STRK token address. The check passes silently when `reward_address` is the BTC token contract address (a different managed token). The pool has no reference to the staking contract's full token registry, so it cannot replicate the `does_token_exist` guard.

When `claim_rewards` is later called, STRK rewards are unconditionally transferred to whatever `reward_address` is stored: [4](#0-3) 

```cairo
let reward_token = IERC20Dispatcher { contract_address: STRK_TOKEN_ADDRESS };
reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
```

A standard ERC-20 token contract has no handler for receiving arbitrary token transfers on its behalf; the STRK sent to the BTC token contract address is irrecoverable.

The same partial check is present in `enter_delegation_pool`, which also only guards against the pool's own token when a new pool member supplies a `reward_address`.

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

Any pool member whose reward address is set to a different managed token contract will have all future STRK reward claims sent to that token contract. The tokens are unrecoverable because the token contract has no withdrawal mechanism for foreign ERC-20 deposits. The loss is permanent and proportional to the accumulated rewards of the affected pool member.

### Likelihood Explanation

The system explicitly supports multiple tokens (STRK + one or more BTC tokens). A pool member who knows the BTC token address (publicly discoverable via `get_active_tokens`) can call `change_reward_address(btc_token_address)` at any time with no special privileges. The call succeeds silently. The damage materialises on the next `claim_rewards` call, which can be triggered by anyone (the pool member or the reward address holder per the access check at line 340–344 of `pool.cairo`).

### Recommendation

The pool contract should call back to the staking contract to validate the proposed reward address against the full managed token set before accepting it. Concretely, expose a view function on the staking contract (or reuse the existing `get_active_tokens` / `get_tokens`) and assert that the reward address is not present in that set, mirroring the `does_token_exist` guard already used in `staking.cairo:change_reward_address`.

### Proof of Concept

1. System is deployed with STRK and BTC tokens both registered.
2. A staker opens a STRK delegation pool via `set_open_for_delegation(strk_token_address)`.
3. A pool member enters the pool via `enter_delegation_pool(reward_address: honest_address, amount: X)`.
4. Pool member calls `pool.change_reward_address(btc_token_address)`.
   - Check at `pool.cairo:507`: `strk_token_address != btc_token_address` → **passes**.
   - `pool_member_info.reward_address` is now `btc_token_address`.
5. Epochs advance; rewards accumulate.
6. Anyone calls `pool.claim_rewards(pool_member)`.
   - `reward_address = btc_token_address` (line 339).
   - `STRK.transfer(recipient: btc_token_address, amount: rewards)` executes (line 365–366).
7. STRK rewards land in the BTC token contract with no recovery path. Yield is permanently frozen.

### Citations

**File:** src/staking/staking.cairo (L517-524)
```text
        fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(
                !self.does_token_exist(token_address: reward_address),
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
```

**File:** src/staking/staking.cairo (L2227-2229)
```text
        fn does_token_exist(self: @ContractState, token_address: ContractAddress) -> bool {
            token_address == STRK_TOKEN_ADDRESS || self.btc_tokens.read(token_address).is_some()
        }
```

**File:** src/pool/pool.cairo (L364-366)
```text
            // Transfer rewards to the pool member.
            let reward_token = IERC20Dispatcher { contract_address: STRK_TOKEN_ADDRESS };
            reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
```

**File:** src/pool/pool.cairo (L505-510)
```text
        fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
            assert!(
                self.token_dispatcher.contract_address.read() != reward_address,
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
```
