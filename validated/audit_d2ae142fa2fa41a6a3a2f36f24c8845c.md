### Title
Pool `change_reward_address` and `enter_delegation_pool` only validate against the pool's own token, not STRK (the actual reward token), allowing permanent freezing of unclaimed yield - (File: `src/pool/pool.cairo`)

---

### Summary

The Pool contract's `change_reward_address` and `enter_delegation_pool` functions validate the `reward_address` only against the pool's own staking token (e.g., BTC for a BTC pool). They do **not** validate against STRK, which is the token in which rewards are always paid. A delegator in a BTC pool can set their `reward_address` to the STRK token contract address. When `claim_rewards` is subsequently called, STRK rewards are transferred to the STRK token contract itself, where they are permanently frozen.

---

### Finding Description

The staking contract's `change_reward_address` and `stake` functions use `does_token_exist`, which checks against **all** registered tokens (STRK + all BTC tokens):

```cairo
// src/staking/staking.cairo:517-524
fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
    self.general_prerequisites();
    assert!(
        !self.does_token_exist(token_address: reward_address),
        "{}",
        GenericError::REWARD_ADDRESS_IS_TOKEN,
    );
``` [1](#0-0) 

Where `does_token_exist` checks all registered tokens:

```cairo
// src/staking/staking.cairo:2227-2229
fn does_token_exist(self: @ContractState, token_address: ContractAddress) -> bool {
    token_address == STRK_TOKEN_ADDRESS || self.btc_tokens.read(token_address).is_some()
}
``` [2](#0-1) 

In contrast, the Pool contract's `change_reward_address` only checks against the pool's **own** token:

```cairo
// src/pool/pool.cairo:505-510
fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
    assert!(
        self.token_dispatcher.contract_address.read() != reward_address,
        "{}",
        GenericError::REWARD_ADDRESS_IS_TOKEN,
    );
``` [3](#0-2) 

And `enter_delegation_pool` has the same incomplete check:

```cairo
// src/pool/pool.cairo:192-195
let token_address = token_dispatcher.contract_address;
assert!(token_address != pool_member, "{}", Error::POOL_MEMBER_IS_TOKEN);
assert!(token_address != reward_address, "{}", GenericError::REWARD_ADDRESS_IS_TOKEN);
``` [4](#0-3) 

For a BTC pool, `token_dispatcher.contract_address` is the BTC token address. The check only prevents `reward_address == BTC_token_address`. It does **not** prevent `reward_address == STRK_TOKEN_ADDRESS`.

Critically, pool rewards are **always paid in STRK**, regardless of the pool's staking token:

```cairo
// src/pool/pool.cairo:365-366
let reward_token = IERC20Dispatcher { contract_address: STRK_TOKEN_ADDRESS };
reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
``` [5](#0-4) 

---

### Impact Explanation

A delegator in a BTC pool who sets `reward_address = STRK_TOKEN_ADDRESS` (either at entry via `enter_delegation_pool` or later via `change_reward_address`) will cause all their STRK reward claims to be transferred into the STRK token contract itself. Standard ERC20 contracts have no recovery mechanism for tokens sent to their own address. The STRK rewards are permanently frozen.

**Impact:** Permanent freezing of unclaimed yield (High).

---

### Likelihood Explanation

Any unprivileged delegator in a BTC pool can trigger this. The call path is fully permissionless:
1. Call `enter_delegation_pool(reward_address: STRK_TOKEN_ADDRESS, amount: X)` on a BTC pool, **or**
2. As an existing BTC pool member, call `change_reward_address(STRK_TOKEN_ADDRESS)`.

No privileged role is required. The only precondition is that a BTC pool exists and is active, which is a normal protocol state.

---

### Recommendation

Replace the single-token check in `Pool::change_reward_address` and `Pool::enter_delegation_pool` with a call to the staking contract's `does_token_exist` (or an equivalent cross-contract query), so that the `reward_address` is validated against **all** registered tokens — including STRK — not just the pool's own staking token.

Alternatively, add an explicit check against `STRK_TOKEN_ADDRESS` in the pool contract, mirroring the comprehensive validation already present in the staking contract.

---

### Proof of Concept

```cairo
// Assume a BTC pool exists and is active.
// Delegator calls enter_delegation_pool with reward_address = STRK_TOKEN_ADDRESS.
btc_pool_dispatcher.enter_delegation_pool(
    reward_address: STRK_TOKEN_ADDRESS,  // passes the BTC-only check
    amount: delegation_amount,
);

// After rewards accrue, anyone calls claim_rewards.
btc_pool_dispatcher.claim_rewards(pool_member: delegator_address);
// STRK rewards are transferred to STRK_TOKEN_ADDRESS itself — permanently frozen.

// Alternatively, an existing BTC pool member changes their reward address:
btc_pool_dispatcher.change_reward_address(reward_address: STRK_TOKEN_ADDRESS);
// Subsequent claim_rewards calls will freeze all STRK rewards.
```

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

**File:** src/pool/pool.cairo (L192-195)
```text
            let token_dispatcher = self.token_dispatcher.read();
            let token_address = token_dispatcher.contract_address;
            assert!(token_address != pool_member, "{}", Error::POOL_MEMBER_IS_TOKEN);
            assert!(token_address != reward_address, "{}", GenericError::REWARD_ADDRESS_IS_TOKEN);
```

**File:** src/pool/pool.cairo (L365-366)
```text
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
