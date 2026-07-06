### Title
Missing Zero Address Check for `reward_address` Allows Permanent Freezing of Yield - (File: src/staking/staking.cairo, src/pool/pool.cairo)

### Summary
The `stake()` function in `staking.cairo` and the `enter_delegation_pool()` function in `pool.cairo` accept a `reward_address: ContractAddress` parameter without validating that it is non-zero. If a staker or delegator passes `ContractAddress::zero()` as their reward address, all accrued rewards will be permanently transferred to the zero address (burned) upon `claim_rewards()`, with no recovery path.

### Finding Description
In `src/staking/staking.cairo`, the `stake()` function validates `reward_address` only against the token-address registry (`does_token_exist`), but performs no zero-address check: [1](#0-0) 

The check at line 308–311 guards against `reward_address` being a registered token contract, but `ContractAddress::zero()` is not a registered token, so it passes silently. The address is then stored verbatim: [2](#0-1) 

The same pattern exists in `src/pool/pool.cairo` for `enter_delegation_pool()`. The only guard on `reward_address` is the token-address check at line 195; no zero check is present: [3](#0-2) 

When `claim_rewards()` is later called, rewards are transferred to the stored `reward_address`. In the staking contract this is: [4](#0-3) 

And in the pool contract, the STRK reward token is transferred directly to `reward_address`: [5](#0-4) 

If `reward_address` is zero, the transfer succeeds (ERC-20 transfers to address 0 do not revert on Starknet) and the tokens are permanently unrecoverable.

The codebase does define and use a `ZERO_ADDRESS` error and an `assert_caller_is_not_zero()` utility, confirming the protocol is aware of the zero-address concern for callers — but this protection is not extended to address *parameters*: [6](#0-5) [7](#0-6) 

### Impact Explanation
A staker who calls `stake(reward_address: 0, ...)` or a delegator who calls `enter_delegation_pool(reward_address: 0, ...)` will have all future yield permanently routed to the zero address. There is no function to recover already-burned rewards. This constitutes **permanent freezing of unclaimed yield**, which is an explicitly listed High-severity impact in the allowed scope.

### Likelihood Explanation
The entry path is fully unprivileged — any staker or delegator can trigger this by passing zero. Realistic causes include frontend bugs, off-chain scripting errors, or copy-paste mistakes in deployment scripts. The protocol already guards the caller address against zero (via `assert_caller_is_not_zero`) but not the `reward_address` argument, creating an inconsistent and surprising gap. Likelihood is **Low-Medium**: not an active exploit, but a plausible user error with irreversible consequences.

### Recommendation
Add an explicit non-zero assertion for `reward_address` in both `stake()` and `enter_delegation_pool()`, mirroring the existing `assert_caller_is_not_zero` pattern:

```cairo
assert!(reward_address.is_non_zero(), "{}", GenericError::ZERO_ADDRESS);
```

Apply the same guard to `change_reward_address()` in both contracts to prevent an existing staker or delegator from later overwriting a valid reward address with zero.

### Proof of Concept

1. Deploy the staking system as normal.
2. Call `stake(reward_address: ContractAddress::zero(), operational_address: <valid>, amount: <min_stake>)` from any EOA.
3. The call succeeds; the staker record is created with `reward_address = 0`.
4. Advance epochs so rewards accrue.
5. Call `claim_rewards(staker_address: <staker>)`.
6. The staking contract executes `token_dispatcher.checked_transfer(recipient: 0, amount: rewards)` — the transfer succeeds and the STRK rewards are sent to address 0, permanently unrecoverable.
7. The same sequence applies to `enter_delegation_pool(reward_address: 0, amount: ...)` in the pool contract, with pool rewards burned on `pool.claim_rewards()`. [1](#0-0) [8](#0-7)

### Citations

**File:** src/staking/staking.cairo (L288-317)
```text
        fn stake(
            ref self: ContractState,
            reward_address: ContractAddress,
            operational_address: ContractAddress,
            amount: Amount,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let staker_address = get_caller_address();
            assert!(self.staker_info.read(staker_address).is_none(), "{}", Error::STAKER_EXISTS);
            assert!(
                self.operational_address_to_staker_address.read(operational_address).is_zero(),
                "{}",
                Error::OPERATIONAL_EXISTS,
            );
            self.assert_staker_address_not_reused(:staker_address);
            assert!(
                !self.does_token_exist(token_address: staker_address), "{}", Error::STAKER_IS_TOKEN,
            );
            assert!(
                !self.does_token_exist(token_address: reward_address),
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
            assert!(
                !self.does_token_exist(token_address: operational_address),
                "{}",
                Error::OPERATIONAL_IS_TOKEN,
            );
            assert!(amount >= self.min_stake.read(), "{}", Error::AMOUNT_LESS_THAN_MIN_STAKE);
```

**File:** src/staking/staking.cairo (L334-339)
```text
            self
                .staker_info
                .write(
                    staker_address,
                    VInternalStakerInfoTrait::new_latest(:reward_address, :operational_address),
                );
```

**File:** src/staking/staking.cairo (L411-431)
```text
        fn claim_rewards(ref self: ContractState, staker_address: ContractAddress) -> Amount {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let mut staker_info = self.internal_staker_info(:staker_address);
            let caller_address = get_caller_address();
            let reward_address = staker_info.reward_address;
            assert!(
                caller_address == staker_address || caller_address == reward_address,
                "{}",
                Error::CLAIM_REWARDS_FROM_UNAUTHORIZED_ADDRESS,
            );

            // Transfer rewards to staker's reward address and write updated staker info to storage.
            // Note: `send_rewards_to_staker` alters `staker_info` thus commit to storage is
            // performed only after that.
            let amount = staker_info.unclaimed_rewards_own;
            let token_dispatcher = strk_token_dispatcher();
            self.send_rewards_to_staker(:staker_address, ref :staker_info, :token_dispatcher);
            self.write_staker_info(:staker_address, :staker_info);
            amount
        }
```

**File:** src/pool/pool.cairo (L182-206)
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
```

**File:** src/pool/pool.cairo (L364-367)
```text
            // Transfer rewards to the pool member.
            let reward_token = IERC20Dispatcher { contract_address: STRK_TOKEN_ADDRESS };
            reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());

```

**File:** src/staking/utils.cairo (L62-64)
```text
pub(crate) fn assert_caller_is_not_zero() {
    assert!(get_caller_address().is_non_zero(), "{}", Error::CALLER_IS_ZERO_ADDRESS);
}
```

**File:** src/errors.cairo (L1-10)
```text
use staking::minting_curve::errors::Error as MintingError;
use staking::pool::errors::Error as PoolError;
use staking::reward_supplier::errors::Error as RewardsSupplierError;
use staking::staking::errors::Error as StakingError;
use starkware_utils::errors::{Describable, ErrorDisplay};

#[derive(Drop)]
pub enum GenericError {
    Erc20Error: Erc20Error,
    StakingError: StakingError,
```
