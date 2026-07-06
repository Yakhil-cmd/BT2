### Title
`set_open_for_delegation` allows deploying a delegation pool for a disabled token — (File: `src/staking/staking.cairo`)

---

### Summary

The `set_open_for_delegation` function in the `Staking` contract checks that a token **exists** but does not check whether it is currently **active/enabled**. This is the direct analog of the `DelegatorFactory::create` missing-blacklist-check: a new pool contract can be deployed for a disabled token, allowing pool members to lock funds in a pool that earns no rewards.

---

### Finding Description

The `Staking` contract maintains a token enable/disable mechanism via `btc_tokens: IterableMap<ContractAddress, (Epoch, bool)>`, where the `bool` flag tracks whether the token is active. The `disable_token` function (callable by the security agent) sets this flag to `false`, preventing the token from contributing to staking power or rewards. [1](#0-0) 

The `set_open_for_delegation` function, which deploys a new delegation pool contract for a given token, performs only an existence check: [2](#0-1) 

Specifically, line 551 asserts `does_token_exist` but never calls `is_active_token`. The distinction between these two checks is demonstrated elsewhere in the contract — for example, `get_total_stake_for_token` explicitly requires **both**: [3](#0-2) 

Because `set_open_for_delegation` omits the active-status check, a staker can deploy a delegation pool for a token that has been disabled by the security agent. Once the pool is deployed, `enter_delegation_pool` in `pool.cairo` only checks `assert_staker_is_active()` (i.e., that the staker has not been removed), with no check on the token's active status: [4](#0-3) 

The downstream `add_stake_from_pool` call in `staking.cairo` also performs no active-token check: [5](#0-4) 

---

### Impact Explanation

Pool members who enter a delegation pool for a disabled token:

1. Transfer real funds (BTC-equivalent tokens) to the staking contract.
2. Earn **zero rewards** for the duration of their membership, because the disabled token contributes no staking power and no rewards are distributed for it.
3. Must wait through the full `exit_wait_window` (default: 1 week, up to 12 weeks) to recover their principal via `exit_delegation_pool_intent` → `exit_delegation_pool_action`.

This constitutes **temporary freezing of funds** (funds locked for up to the exit wait window with no yield) and **theft of unclaimed yield** (pool members lose rewards they would have earned in a legitimate active-token pool during the same period).

Impact classification: **High — Temporary freezing of funds / Theft of unclaimed yield.**

---

### Likelihood Explanation

- A malicious staker calls `set_open_for_delegation` with a disabled token address. No privileged role is required for this call — any staker can do it.
- The staker advertises the pool. Pool members who do not independently verify the token's active status (an off-chain check not enforced by the contract) enter the pool.
- The staker has no financial cost beyond the minimum stake already deposited.

Likelihood: **Medium** — requires a malicious staker and pool members who do not verify token status, but the entry path is fully unprivileged.

---

### Recommendation

Add an `is_active_token` check inside `set_open_for_delegation`, mirroring the pattern already used in `get_total_stake_for_token`:

```cairo
fn set_open_for_delegation(
    ref self: ContractState, token_address: ContractAddress,
) -> ContractAddress {
    self.general_prerequisites();
    let staker_address = get_caller_address();
    let staker_info = self.internal_staker_info(:staker_address);
    let staker_pool_info = self.staker_pool_info.entry(staker_address);
    assert!(staker_info.unstake_time.is_none(), "{}", Error::UNSTAKE_IN_PROGRESS);
    assert!(self.does_token_exist(:token_address), "{}", Error::TOKEN_NOT_EXISTS);
+   assert!(
+       self.is_active_token(:token_address, epoch_id: self.get_current_epoch()),
+       "{}",
+       Error::TOKEN_NOT_ACTIVE,
+   );
    assert!(
        !staker_pool_info.has_pool_for_token(:token_address),
        "{}",
        Error::STAKER_ALREADY_HAS_POOL,
    );
    ...
}
```

---

### Proof of Concept

```
1. Token T is added via `add_token(T)` and enabled via `enable_token(T)`.
2. Security agent calls `disable_token(T)` — T is now inactive.
3. Staker S (already staked) calls `set_open_for_delegation(T)`.
   → No revert. Pool contract P is deployed for disabled token T.
4. Pool member M calls P.enter_delegation_pool(reward_addr, amount).
   → No revert. M's funds are transferred to the staking contract.
5. M earns zero rewards (T is disabled, contributes no staking power).
6. M must call exit_delegation_pool_intent() and wait the full exit_wait_window
   before recovering principal via exit_delegation_pool_action().
   → Funds temporarily frozen; yield permanently lost for the lock period.
``` [2](#0-1) [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L542-572)
```text
        fn set_open_for_delegation(
            ref self: ContractState, token_address: ContractAddress,
        ) -> ContractAddress {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let staker_address = get_caller_address();
            let staker_info = self.internal_staker_info(:staker_address);
            let staker_pool_info = self.staker_pool_info.entry(staker_address);
            assert!(staker_info.unstake_time.is_none(), "{}", Error::UNSTAKE_IN_PROGRESS);
            assert!(self.does_token_exist(:token_address), "{}", Error::TOKEN_NOT_EXISTS);
            assert!(
                !staker_pool_info.has_pool_for_token(:token_address),
                "{}",
                Error::STAKER_ALREADY_HAS_POOL,
            );
            let commission = staker_pool_info.commission();

            // Deploy delegation pool contract.
            let pool_contract = self
                .deploy_delegation_pool_from_staking_contract(
                    :staker_address,
                    staking_contract: get_contract_address(),
                    :token_address,
                    :commission,
                );
            // Update pool to storage.
            staker_pool_info.pools.write(pool_contract, token_address);
            // Initialize the delegated balance trace.
            self.initialize_staker_delegated_balance_trace(:staker_address, :pool_contract);
            pool_contract
        }
```

**File:** src/staking/staking.cairo (L820-832)
```text
        fn get_total_stake_for_token(
            self: @ContractState, token_address: ContractAddress,
        ) -> Amount {
            let curr_epoch = self.get_current_epoch();
            assert!(self.does_token_exist(:token_address), "{}", Error::INVALID_TOKEN_ADDRESS);
            assert!(
                self.is_active_token(:token_address, epoch_id: curr_epoch),
                "{}",
                Error::TOKEN_NOT_ACTIVE,
            );
            let decimals = self.get_token_decimals(:token_address);
            self._get_total_stake(:token_address).to_native_amount(:decimals)
        }
```

**File:** src/staking/staking.cairo (L1003-1026)
```text
        fn add_stake_from_pool(
            ref self: ContractState, staker_address: ContractAddress, amount: Amount,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let staker_info = self.internal_staker_info(:staker_address);
            assert!(staker_info.unstake_time.is_none(), "{}", Error::UNSTAKE_IN_PROGRESS);
            let pool_contract = get_caller_address();
            let token_address = self
                .staker_pool_info
                .entry(staker_address)
                .get_pool_token(:pool_contract)
                .expect_with_err(Error::CALLER_IS_NOT_POOL_CONTRACT);
            let decimals = self.get_token_decimals(:token_address);
            let normalized_amount = NormalizedAmountTrait::from_native_amount(:amount, :decimals);

            // Update the staker's staked amount, and add to total_stake.
            let old_delegated_stake = self.get_delegated_balance(:staker_address, :pool_contract);
            let new_delegated_stake = old_delegated_stake + normalized_amount;
            self
                .insert_staker_delegated_balance(
                    :staker_address, :pool_contract, delegated_balance: new_delegated_stake,
                );
            self.add_to_total_stake(:token_address, amount: normalized_amount);
```

**File:** src/staking/staking.cairo (L1365-1389)
```text
        fn enable_token(ref self: ContractState, token_address: ContractAddress) {
            self.roles.only_token_admin();
            let is_active_opt: Option<(Epoch, bool)> = self.btc_tokens.read(token_address);
            assert!(is_active_opt.is_some(), "{}", Error::TOKEN_NOT_EXISTS);
            let (is_active_first_epoch, is_active) = is_active_opt.unwrap();
            let curr_epoch = self.get_current_epoch();
            assert!(curr_epoch >= is_active_first_epoch, "{}", Error::INVALID_EPOCH);
            assert!(!is_active, "{}", Error::TOKEN_ALREADY_ENABLED);
            let next_is_active_first_epoch = self.get_epoch_plus_k();
            self.btc_tokens.write(token_address, (next_is_active_first_epoch, true));
            self.emit(TokenManagerEvents::TokenEnabled { token_address });
        }

        fn disable_token(ref self: ContractState, token_address: ContractAddress) {
            self.roles.only_security_agent();
            let is_active_opt: Option<(Epoch, bool)> = self.btc_tokens.read(token_address);
            assert!(is_active_opt.is_some(), "{}", Error::TOKEN_NOT_EXISTS);
            let (is_active_first_epoch, is_active) = is_active_opt.unwrap();
            let curr_epoch = self.get_current_epoch();
            assert!(curr_epoch >= is_active_first_epoch, "{}", Error::INVALID_EPOCH);
            assert!(is_active, "{}", Error::TOKEN_ALREADY_DISABLED);
            let next_is_active_first_epoch = self.get_epoch_plus_k();
            self.btc_tokens.write(token_address, (next_is_active_first_epoch, false));
            self.emit(TokenManagerEvents::TokenDisabled { token_address });
        }
```

**File:** src/pool/pool.cairo (L182-199)
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
```
