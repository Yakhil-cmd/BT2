### Title
Hardcoded `starkgate_address` in `on_receive` with No Admin Setter Permanently Freezes Unclaimed Yield on StarkGate Upgrade - (File: `src/reward_supplier/reward_supplier.cairo`)

---

### Summary

`RewardSupplier.on_receive` enforces a strict caller check against a hardcoded `starkgate_address` set only at construction time. There is no admin setter for this field. If StarkGate is upgraded to a new L2 bridge address, every subsequent deposit call from the new bridge will revert, permanently preventing STRK tokens from reaching the `RewardSupplier`. As the contract's token balance is never replenished, `claim_rewards` will eventually fail for all stakers and delegators, permanently freezing unclaimed yield.

---

### Finding Description

`RewardSupplier.on_receive` is the StarkGate callback invoked by the bridge after depositing STRK tokens to the contract. It enforces:

```cairo
assert!(
    get_caller_address() == self.starkgate_address.read(),
    "{}",
    Error::ON_RECEIVE_NOT_FROM_STARKGATE,
);
``` [1](#0-0) 

`starkgate_address` is written once in the constructor and never again:

```cairo
self.starkgate_address.write(starkgate_address);
``` [2](#0-1) 

Searching the entire `IRewardSupplier` and `IRewardSupplierConfig` interfaces confirms there is no `set_starkgate_address` function exposed anywhere. [3](#0-2) 

The `starkgate_address` storage field is declared but has no corresponding setter, unlike other configurable fields such as `block_duration_config` which has `set_block_duration_config`. [4](#0-3) 

The reward flow depends entirely on `on_receive` succeeding: the L1 `RewardSupplier` mints STRK and sends it via StarkGate; the L2 bridge calls `on_receive` on the `RewardSupplier`; if `on_receive` reverts, the entire L2 deposit transaction reverts, the tokens are not delivered, and `l1_pending_requested_amount` is never decremented. The contract's STRK balance stagnates while `unclaimed_rewards` grows, eventually causing `claim_rewards` to fail. [5](#0-4) 

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

Once the stored `starkgate_address` is stale:

1. Every L2 deposit from the new StarkGate bridge reverts at the `assert!` on line 234.
2. The `RewardSupplier`'s STRK balance is never replenished.
3. `unclaimed_rewards` continues to accumulate (via `update_unclaimed_rewards_from_staking_contract`) but the contract holds no tokens to back it.
4. `claim_rewards` hits `assert!(amount <= unclaimed_rewards)` successfully but the `checked_transfer` call fails because the contract balance is zero — all staker and delegator reward claims are permanently blocked. [6](#0-5) 

---

### Likelihood Explanation

StarkGate is a live, actively maintained bridge that has undergone upgrades. The `RewardSupplier` stores the StarkGate L2 bridge address at deployment with no mechanism to update it short of a full contract upgrade via `ReplaceabilityComponent`. Any StarkGate upgrade that changes the L2 bridge contract address — a routine infrastructure event — immediately triggers this condition. The protocol team cannot respond with a simple admin call; a full governance upgrade cycle is required, during which all reward claims are frozen.

---

### Recommendation

1. **Add an admin setter** for `starkgate_address` gated behind an appropriate role (e.g., `only_app_governor` or `only_security_admin`), mirroring the pattern used for `set_block_duration_config`.
2. Alternatively, remove the strict caller check and instead validate the `l2_token` and `depositor` fields only, accepting deposits from any caller that passes those checks (analogous to the external report's recommendation to remove the router `require`).
3. At minimum, add monitoring for StarkGate address changes and ensure an EIC-based upgrade path is prepared in advance.

---

### Proof of Concept

**Setup**: Deploy the system. Record `starkgate_address = S1`. StarkGate upgrades; new bridge address is `S2`.

**Step 1**: L1 `RewardSupplier` calls `tick()`, minting STRK and sending it via the new StarkGate bridge at `S2`. [7](#0-6) 

**Step 2**: New StarkGate bridge (`S2`) calls `on_receive` on the `RewardSupplier`.

**Step 3**: `get_caller_address()` returns `S2`; `self.starkgate_address.read()` returns `S1`. The assert fires:
```
assert!(S2 == S1, "Only StarkGate can call on_receive");  // REVERTS
``` [1](#0-0) 

**Step 4**: The L2 deposit transaction reverts. STRK tokens are not delivered. `l1_pending_requested_amount` remains inflated. The contract balance stays at zero.

**Step 5**: A staker calls `claim_rewards`. The staking contract calls `reward_supplier.claim_rewards(amount)`. The `checked_transfer` fails — no tokens in the contract. All staker and delegator reward claims are permanently frozen. [5](#0-4)

### Citations

**File:** src/reward_supplier/reward_supplier.cairo (L84-85)
```text
        /// Token bridge address.
        starkgate_address: ContractAddress,
```

**File:** src/reward_supplier/reward_supplier.cairo (L132-132)
```text
        self.starkgate_address.write(starkgate_address);
```

**File:** src/reward_supplier/reward_supplier.cairo (L205-219)
```text
        fn claim_rewards(ref self: ContractState, amount: Amount) {
            // Asserts.
            let staking_contract = self.staking_contract.read();
            assert!(
                get_caller_address() == staking_contract,
                "{}",
                GenericError::CALLER_IS_NOT_STAKING_CONTRACT,
            );
            let unclaimed_rewards = self.unclaimed_rewards.read();
            assert!(amount <= unclaimed_rewards, "{}", GenericError::AMOUNT_TOO_HIGH);

            // Update unclaimed_rewards and transfer the requested rewards to the staking contract.
            self.unclaimed_rewards.write(unclaimed_rewards - amount);
            let token_dispatcher = self.token_dispatcher.read();
            token_dispatcher.checked_transfer(recipient: staking_contract, amount: amount.into());
```

**File:** src/reward_supplier/reward_supplier.cairo (L233-237)
```text
            assert!(
                get_caller_address() == self.starkgate_address.read(),
                "{}",
                Error::ON_RECEIVE_NOT_FROM_STARKGATE,
            );
```

**File:** src/reward_supplier/interface.cairo (L1-103)
```text
use staking::types::Amount;
use starknet::{ContractAddress, EthAddress};

#[starknet::interface]
pub trait IRewardSupplier<TContractState> {
    /// Returns ([`Amount`](staking::types::Amount), [`Amount`](staking::types::Amount)) of rewards
    /// for the current epoch, for STRK and BTC respectively (in FRI).
    /// Used for attestation rewards.
    ///
    /// #### Internal calls:
    /// - [`minting_curve::minting_curve::interface::IMintingCurve::yearly_mint`]
    /// - [`staking::staking::interface::IStaking::get_epoch_info`]
    fn calculate_current_epoch_rewards(self: @TContractState) -> (Amount, Amount);
    /// Returns ([`Amount`](staking::types::Amount), [`Amount`](staking::types::Amount)) of rewards
    /// for block in the current epoch, for STRK and BTC respectively (in FRI).
    /// Used for the consensus rewards.
    ///
    /// This function is called once per epoch. It updates `avg_block_duration` and returns (STRK,
    /// BTC) block rewards for the current epoch.
    ///
    /// #### Errors:
    /// -
    /// [`CALLER_IS_NOT_STAKING_CONTRACT`](staking::errors::GenericError::CALLER_IS_NOT_STAKING_CONTRACT)
    ///
    /// #### Access control:
    /// Only staking contract.
    ///
    /// #### Internal calls:
    /// - [`minting_curve::minting_curve::interface::IMintingCurve::yearly_mint`]
    fn update_current_epoch_block_rewards(ref self: TContractState) -> (Amount, Amount);
    /// Updates the unclaimed rewards from the staking contract.
    ///
    /// #### Emits:
    /// - [`MintRequest`](Events::MintRequest) if funds are needed.
    ///
    /// #### Errors:
    /// -
    /// [`CALLER_IS_NOT_STAKING_CONTRACT`](staking::errors::GenericError::CALLER_IS_NOT_STAKING_CONTRACT)
    ///
    /// #### Access control:
    /// Only staking contract.
    fn update_unclaimed_rewards_from_staking_contract(ref self: TContractState, rewards: Amount);
    /// Transfers the given `amount` (FRI) of rewards to the staking contract.
    ///
    /// #### Preconditions:
    /// - `reward_supplier.unclaimed_rewards >= amount`
    ///
    /// #### Errors:
    /// -
    /// [`CALLER_IS_NOT_STAKING_CONTRACT`](staking::errors::GenericError::CALLER_IS_NOT_STAKING_CONTRACT)
    /// - [`AMOUNT_TOO_HIGH`](staking::errors::GenericError::AMOUNT_TOO_HIGH)
    ///
    /// #### Access control:
    /// Only staking contract.
    fn claim_rewards(ref self: TContractState, amount: Amount);
    /// Callback function for StarkGate deposit.
    ///
    /// Notifies the contract that a transfer of `amount` from L1 via StarkGate has occurred and
    /// returns `true` upon success.
    /// This function reverts only if `amount` exceeds 2**128 FRI, which is highly unlikely.
    ///
    /// #### Errors:
    /// -
    /// [`ON_RECEIVE_NOT_FROM_STARKGATE`](staking::reward_supplier::errors::Error::ON_RECEIVE_NOT_FROM_STARKGATE)
    /// - [`UNEXPECTED_TOKEN`](staking::reward_supplier::errors::Error::UNEXPECTED_TOKEN)
    /// - [`AMOUNT_TOO_HIGH`](staking::errors::GenericError::AMOUNT_TOO_HIGH)
    ///
    /// #### Access control:
    /// Only StarkGate.
    fn on_receive(
        ref self: TContractState,
        l2_token: ContractAddress,
        amount: u256,
        depositor: EthAddress,
        message: Span<felt252>,
    ) -> bool;
    /// Returns [`RewardSupplierInfoV1`] describing the contract.
    fn contract_parameters_v1(self: @TContractState) -> RewardSupplierInfoV1;
    /// Returns the alpha parameter, as percentage, used when computing BTC rewards.
    fn get_alpha(self: @TContractState) -> u128;
    /// Returns the block duration configuration.
    fn get_block_duration_config(self: @TContractState) -> BlockDurationConfig;
}

#[starknet::interface]
pub trait IRewardSupplierConfig<TContractState> {
    /// Sets the block duration configuration.
    ///
    /// #### Preconditions:
    /// - `block_duration_config.min_block_duration > 0`
    /// - `block_duration_config.min_block_duration <= block_duration_config.max_block_duration`
    ///
    /// #### Errors:
    /// - [`ONLY_APP_GOVERNOR`](AccessErrors::ONLY_APP_GOVERNOR)
    /// -
    /// [`INVALID_MIN_MAX_BLOCK_DURATION`](staking::reward_supplier::errors::Error::INVALID_MIN_MAX_BLOCK_DURATION)
    ///
    /// #### Access control:
    /// Only app governor.
    fn set_block_duration_config(
        ref self: TContractState, block_duration_config: BlockDurationConfig,
    );
}
```

**File:** L1/starkware/solidity/stake/RewardSupplier.sol (L1-30)
```text
// SPDX-License-Identifier: Apache-2.0.
pragma solidity 0.8.24;

import "starkware/solidity/interfaces/Identity.sol";
import "starkware/solidity/stake/RewardSupplierStorage.sol";
import "starkware/solidity/tokens/ERC20/IERC20.sol";
import "starkware/solidity/upgrade/ProxySupportImpl.sol";
import "third_party/open_zeppelin/utils/math/Math.sol";

uint256 constant TOKENS_PER_MINT_REQUEST = 1_300_000 * 10**18;
uint256 constant MAX_MESSAGES_TO_PROCESS_PER_TICK = 5;

// L1_handler selector for 'update_total_supply'.
uint256 constant UPDATE_TOTAL_SUPPLY_SELECTOR = 0x3f52d976f20d8cb65b362a5df632b87dd69039597d692d7a0c65443f0e5363;

/**
  The RewardSupplier supplies funds to designated Starknet L2 contracts.

  Upon triggering using the tick() function.
  It collects pending funding requests from its L2 counterpart,
  Request respective tokens to be minted, and send them to L2 using StarkGate.
*/
contract RewardSupplier is RewardSupplierStorage, Identity, ProxySupportImpl {
    using Addresses for address;
    event ConsumedL2MintRequests(uint256 messagesConsumed, uint256 amountMinted);

    function identify() external pure override returns (string memory) {
        return "StarkWare_RewardSupplier_2024_1";
    }

```
