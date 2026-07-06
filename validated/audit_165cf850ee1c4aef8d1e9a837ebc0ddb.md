### Title
Incomplete `reward_address` Validation in BTC Pool Contract Allows Permanent Freezing of Delegator Yield - (File: `src/pool/pool.cairo`)

---

### Summary

The `Pool` contract's `enter_delegation_pool` and `change_reward_address` functions validate `reward_address` only against the pool's own staking token, but not against `STRK_TOKEN_ADDRESS`. For BTC delegation pools, a pool member can set `reward_address = STRK_TOKEN_ADDRESS`. When `claim_rewards` is subsequently called, STRK rewards are transferred to the STRK token contract itself, permanently locking the delegator's unclaimed yield.

---

### Finding Description

In `src/pool/pool.cairo`, both entry points that set `reward_address` perform an incomplete token-address check:

**`enter_delegation_pool`** (lines 193–195):
```rust
let token_address = token_dispatcher.contract_address;
assert!(token_address != pool_member, "{}", Error::POOL_MEMBER_IS_TOKEN);
assert!(token_address != reward_address, "{}", GenericError::REWARD_ADDRESS_IS_TOKEN);
```

**`change_reward_address`** (lines 506–510):
```rust
assert!(
    self.token_dispatcher.contract_address.read() != reward_address,
    "{}",
    GenericError::REWARD_ADDRESS_IS_TOKEN,
);
``` [1](#0-0) [2](#0-1) 

In both cases, `token_dispatcher.contract_address` is the pool's staking token (BTC for a BTC pool). The check only blocks `reward_address == BTC_token_address`. It does **not** block `reward_address == STRK_TOKEN_ADDRESS`.

Rewards are always paid in STRK regardless of the pool's staking token. In `claim_rewards` (lines 364–366):
```rust
let reward_token = IERC20Dispatcher { contract_address: STRK_TOKEN_ADDRESS };
reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
``` [3](#0-2) 

If `reward_address` was set to `STRK_TOKEN_ADDRESS`, the STRK rewards are transferred into the STRK token contract itself, where they are permanently inaccessible.

**Contrast with the staking contract**, which correctly validates against all registered tokens via `does_token_exist()`:
```rust
assert!(
    !self.does_token_exist(token_address: reward_address),
    "{}",
    GenericError::REWARD_ADDRESS_IS_TOKEN,
);
```
```rust
fn does_token_exist(self: @ContractState, token_address: ContractAddress) -> bool {
    token_address == STRK_TOKEN_ADDRESS || self.btc_tokens.read(token_address).is_some()
}
``` [4](#0-3) [5](#0-4) 

The pool contract lacks this comprehensive check.

---

### Impact Explanation

A BTC pool member who sets `reward_address = STRK_TOKEN_ADDRESS` (via `enter_delegation_pool` or `change_reward_address`) will have all future STRK reward claims permanently transferred into the STRK ERC-20 contract address. The STRK token contract has no recovery mechanism for tokens sent to itself. This constitutes **permanent freezing of unclaimed yield** for the affected pool member.

Impact: **High** — Permanent freezing of unclaimed yield (allowed impact scope).

---

### Likelihood Explanation

This requires a BTC pool member to supply or change their `reward_address` to `STRK_TOKEN_ADDRESS`. This can occur through:
- A front-end bug or copy-paste error where the user pastes the STRK token address instead of a wallet address.
- A malicious dApp that tricks a user into calling `change_reward_address(STRK_TOKEN_ADDRESS)`.

The staking contract's analogous function already guards against this, demonstrating the protocol's intent to prevent it. The absence of the guard in the pool contract is an oversight. Likelihood: **Low**, but the consequence is irreversible.

---

### Recommendation

In `src/pool/pool.cairo`, replace the single-token check in both `enter_delegation_pool` and `change_reward_address` with a check against all protocol tokens. The pool contract should query the staking contract for the full token list, or at minimum hard-code a check against `STRK_TOKEN_ADDRESS` in addition to the pool's own token:

```rust
// In enter_delegation_pool and change_reward_address:
assert!(token_address != reward_address, "{}", GenericError::REWARD_ADDRESS_IS_TOKEN);
assert!(STRK_TOKEN_ADDRESS != reward_address, "{}", GenericError::REWARD_ADDRESS_IS_TOKEN);
```

Alternatively, expose a `does_token_exist` query on the staking contract and call it from the pool contract, mirroring the validation already present in `Staking::change_reward_address`.

---

### Proof of Concept

1. Token admin adds and enables a BTC token; staker opens a BTC delegation pool.
2. Pool member calls `enter_delegation_pool(reward_address: STRK_TOKEN_ADDRESS, amount: X)` on the BTC pool. The check `token_address != reward_address` passes because `BTC_token_address != STRK_TOKEN_ADDRESS`.
3. Rewards accrue to the pool member over epochs.
4. Pool member (or anyone) calls `claim_rewards(pool_member)`.
5. `claim_rewards` executes `reward_token.checked_transfer(recipient: STRK_TOKEN_ADDRESS, amount: rewards)` — STRK rewards are sent to the STRK token contract and permanently locked.
6. The pool member's unclaimed yield is irretrievably lost. [6](#0-5) [7](#0-6)

### Citations

**File:** src/pool/pool.cairo (L182-219)
```text
        fn enter_delegation_pool(
            ref self: ContractState, reward_address: ContractAddress, amount: Amount,
        ) {
            // Asserts.
            self.assert_staker_is_active();
            let pool_member = get_caller_address();
            assert!(
                self.pool_member_info.read(pool_member).is_none(), "{}", Error::POOL_MEMBER_EXISTS,
            );
            assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);
            let token_dispatcher = self.token_dispatcher.read();
            let token_address = token_dispatcher.contract_address;
            assert!(token_address != pool_member, "{}", Error::POOL_MEMBER_IS_TOKEN);
            assert!(token_address != reward_address, "{}", GenericError::REWARD_ADDRESS_IS_TOKEN);
            // Transfer funds from the delegator to the staking contract.
            let staker_address = self.staker_address.read();
            transfer_from_delegator(:pool_member, :amount, :token_dispatcher);
            self.transfer_to_staking_contract(:amount, :token_dispatcher, :staker_address);

            self.set_member_balance(:pool_member, :amount);

            // Create the pool member record.
            self
                .pool_member_info
                .write(pool_member, VInternalPoolMemberInfoTrait::new_latest(:reward_address));

            // Emit events.
            self
                .emit(
                    Events::NewPoolMember { pool_member, staker_address, reward_address, amount },
                );
            self
                .emit(
                    Events::PoolMemberBalanceChanged {
                        pool_member, old_delegated_stake: Zero::zero(), new_delegated_stake: amount,
                    },
                );
        }
```

**File:** src/pool/pool.cairo (L335-377)
```text
        fn claim_rewards(ref self: ContractState, pool_member: ContractAddress) -> Amount {
            // Asserts.
            let mut pool_member_info = self.internal_pool_member_info(:pool_member);
            let caller_address = get_caller_address();
            let reward_address = pool_member_info.reward_address;
            assert!(
                caller_address == pool_member || caller_address == reward_address,
                "{}",
                Error::POOL_CLAIM_REWARDS_FROM_UNAUTHORIZED_ADDRESS,
            );

            let until_checkpoint = self.get_current_checkpoint(:pool_member);

            // Calculate rewards and update entry_to_claim_from.
            let (mut rewards, updated_entry_to_claim_from) = self
                .calculate_rewards(
                    :pool_member,
                    from_checkpoint: pool_member_info.reward_checkpoint,
                    :until_checkpoint,
                    entry_to_claim_from: pool_member_info.entry_to_claim_from,
                );
            rewards += pool_member_info._unclaimed_rewards_from_v0;
            pool_member_info._unclaimed_rewards_from_v0 = Zero::zero();
            pool_member_info.entry_to_claim_from = updated_entry_to_claim_from;
            pool_member_info.reward_checkpoint = until_checkpoint;

            // Write the updated pool member info to storage.
            self.write_pool_member_info(:pool_member, :pool_member_info);

            // Transfer rewards to the pool member.
            let reward_token = IERC20Dispatcher { contract_address: STRK_TOKEN_ADDRESS };
            reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());

            // Emit event.
            self
                .emit(
                    Events::PoolMemberRewardClaimed {
                        pool_member, reward_address, amount: rewards,
                    },
                );

            rewards
        }
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

**File:** src/staking/staking.cairo (L519-524)
```text
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
