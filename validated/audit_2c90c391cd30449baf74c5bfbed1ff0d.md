### Title
Pool `change_reward_address` Validates Only Against Pool's Own Token, Allowing Reward Address to Be Set to Other Registered Token Contracts - (File: `src/pool/pool.cairo`)

### Summary
`pool.cairo`'s `change_reward_address` (and `enter_delegation_pool`) only checks the new `reward_address` against the pool's own token, while `staking.cairo`'s equivalent function checks against **all** registered tokens. This inconsistency allows a STRK pool member to set their `reward_address` to a registered BTC token contract address, causing their STRK rewards to be permanently transferred to and locked in that contract.

### Finding Description

**In `staking.cairo` `change_reward_address`**, the validation uses `does_token_exist()`, which covers STRK and every registered BTC token:

```cairo
assert!(
    !self.does_token_exist(token_address: reward_address),
    "{}",
    GenericError::REWARD_ADDRESS_IS_TOKEN,
);
``` [1](#0-0) 

where `does_token_exist` is:

```cairo
fn does_token_exist(self: @ContractState, token_address: ContractAddress) -> bool {
    token_address == STRK_TOKEN_ADDRESS || self.btc_tokens.read(token_address).is_some()
}
``` [2](#0-1) 

**In `pool.cairo` `change_reward_address`**, the validation only checks against the pool's single token:

```cairo
assert!(
    self.token_dispatcher.contract_address.read() != reward_address,
    "{}",
    GenericError::REWARD_ADDRESS_IS_TOKEN,
);
``` [3](#0-2) 

For a STRK pool, `self.token_dispatcher.contract_address` is `STRK_TOKEN_ADDRESS`. The check therefore only blocks `STRK_TOKEN_ADDRESS` — it does **not** block any registered BTC token address. The same gap exists in `enter_delegation_pool`:

```cairo
assert!(token_address != reward_address, "{}", GenericError::REWARD_ADDRESS_IS_TOKEN);
``` [4](#0-3) 

When `claim_rewards()` executes, it transfers STRK rewards directly to the stored `reward_address` with no further validation:

```cairo
let reward_token = IERC20Dispatcher { contract_address: STRK_TOKEN_ADDRESS };
reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
``` [5](#0-4) 

If `reward_address` is a BTC token contract, the STRK rewards are sent there and permanently locked, since standard ERC20 contracts have no mechanism to withdraw foreign tokens.

The same inconsistency is present in `staking.cairo`'s `stake()` function, which also uses `does_token_exist()`: [6](#0-5) 

### Impact Explanation

A pool member can permanently destroy their own unclaimed STRK yield by setting `reward_address` to any registered BTC token contract. Every subsequent `claim_rewards()` call silently transfers STRK into the BTC token contract, where it is irrecoverable. This satisfies **High: Permanent freezing of unclaimed yield**.

### Likelihood Explanation

The precondition is that at least one BTC token is registered in the staking system (a normal operational state). Any pool member — an unprivileged, permissionless role — can trigger this by calling `change_reward_address` with a BTC token address. The call succeeds silently with no warning. Accidental misconfiguration (e.g., pasting a token address instead of a wallet address) is a realistic path.

### Recommendation

Replace the single-token check in `pool.cairo`'s `change_reward_address` and `enter_delegation_pool` with a cross-contract call to the staking contract's token registry, mirroring the `does_token_exist()` logic used in `staking.cairo`. Alternatively, expose a view function on the staking contract that the pool can call to validate any address against all registered tokens before accepting it as a `reward_address`.

### Proof of Concept

1. System is deployed with STRK and a BTC token (`btc_token_address`) both registered.
2. A staker creates a STRK pool via `set_open_for_delegation`.
3. A pool member enters via `pool.cairo::enter_delegation_pool(reward_address: wallet, amount)`.
4. Pool member calls `pool.cairo::change_reward_address(reward_address: btc_token_address)`.
5. The

### Citations

**File:** src/staking/staking.cairo (L307-311)
```text
            assert!(
                !self.does_token_exist(token_address: reward_address),
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
```

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

**File:** src/pool/pool.cairo (L194-195)
```text
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
