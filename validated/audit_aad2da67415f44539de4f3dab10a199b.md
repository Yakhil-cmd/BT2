### Title
Unchecked `approve()` Return Value in `RewardSupplier.initializeContractState()` Silently Fails, Permanently Blocking Reward Distribution — (`L1/starkware/solidity/stake/RewardSupplier.sol`)

---

### Summary

`RewardSupplier.sol::initializeContractState()` calls `IERC20(token).approve(bridge, type(uint256).max)` without checking the boolean return value. If the token returns `false` instead of reverting, the bridge receives no spending allowance. Every subsequent `tick()` call then fails when the bridge attempts to pull tokens, permanently blocking reward delivery to L2 stakers and delegators.

---

### Finding Description

In `initializeContractState()`, the contract grants the bridge a max allowance so that `tick()` can later deposit minted tokens:

```solidity
IERC20(token).approve(bridge, type(uint256).max);   // return value silently discarded
``` [1](#0-0) 

The `IERC20` interface declares `approve` as returning `bool`:

```solidity
function approve(address spender, uint256 amount) external returns (bool);
``` [2](#0-1) 

No `SafeERC20` wrapper is imported or used anywhere in `RewardSupplier.sol`. [3](#0-2) 

If `approve()` returns `false` without reverting, `initializeContractState()` completes normally, the proxy is marked initialized (`isInitialized()` returns `true`), and there is no on-chain record of the failure. There is no separate re-approval function in the contract.

When `tick()` is later called, `mintManager().mintRequest(token(), amountToMint)` mints tokens to the `RewardSupplier`, and then `bridge().depositWithMessage{value: msgFee}(token(), amountToMint, ...)` attempts to pull those tokens via `transferFrom`. Because the allowance is zero, the bridge's internal `transferFrom` reverts, causing the entire `tick()` transaction to revert (rolling back the mint as well). [4](#0-3) 

There is no fallback path: `tick()` is the sole mechanism for delivering minted STRK to L2. With `tick()` permanently broken, the L2 `RewardSupplier`'s `unclaimed_rewards` counter grows but no tokens ever arrive, so `claim_rewards` (which calls `checked_transfer`) will always fail for stakers and delegators. [5](#0-4) 

---

### Impact Explanation

**Permanent freezing of unclaimed yield.** Stakers and delegators accumulate `unclaimed_rewards` on L2 but can never receive them because the token bridge pipeline is broken from the moment of initialization. The only recovery path is a contract upgrade to re-approve the bridge, which requires governance action.

---

### Likelihood Explanation

Low. The STRK token is a standard ERC20 that returns `true` or reverts on `approve()`. However:

1. The code pattern is objectively incorrect — the return value is never checked and no `SafeERC20` wrapper is used.
2. The contract is deployed behind an upgradeable proxy; a future token upgrade or token replacement could introduce non-reverting `false` returns.
3. The initialization is a one-shot operation with no re-approval escape hatch, so a single silent failure is unrecoverable without governance intervention.

---

### Recommendation

Use OpenZeppelin's `SafeERC20.safeApprove` (or `forceApprove`) which reverts on a `false` return:

```solidity
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

// inside initializeContractState:
SafeERC20.safeApprove(IERC20(token), bridge, type(uint256).max);
```

Alternatively, assert the return value explicitly:

```solidity
bool ok = IERC20(token).approve(bridge, type(uint256).max);
require(ok, "APPROVE_FAILED");
```

---

### Proof of Concept

1. Deploy a mock STRK token whose `approve()` returns `false` without reverting.
2. Initialize `RewardSupplier` with this token — `initializeContractState()` succeeds silently.
3. Call `tick()` with sufficient ETH and pending L2 mint messages.
4. `mintManager().mintRequest()` succeeds (tokens minted to `RewardSupplier`).
5. `bridge().depositWithMessage()` reverts because `transferFrom` sees zero allowance.
6. Entire `tick()` transaction reverts; no tokens reach L2.
7. Repeat indefinitely — `tick()` can never succeed; all staker/delegator reward claims on L2 revert at `checked_transfer`.

### Citations

**File:** L1/starkware/solidity/stake/RewardSupplier.sol (L1-8)
```text
// SPDX-License-Identifier: Apache-2.0.
pragma solidity 0.8.24;

import "starkware/solidity/interfaces/Identity.sol";
import "starkware/solidity/stake/RewardSupplierStorage.sol";
import "starkware/solidity/tokens/ERC20/IERC20.sol";
import "starkware/solidity/upgrade/ProxySupportImpl.sol";
import "third_party/open_zeppelin/utils/math/Math.sol";
```

**File:** L1/starkware/solidity/stake/RewardSupplier.sol (L82-82)
```text
        IERC20(token).approve(bridge, type(uint256).max);
```

**File:** L1/starkware/solidity/stake/RewardSupplier.sol (L121-131)
```text
            // Reuest minting of the requested amount from the mint manager.
            mintManager().mintRequest(token(), amountToMint);

            // Deposit the minted amount onto the bridge to the credit of `mintDestination`.
            uint256 msgFee = msg.value / 2;
            bridge().depositWithMessage{value: msgFee}(
                token(),
                amountToMint,
                mintDestination(),
                new uint256[](0)
            );
```

**File:** L1/starkware/solidity/tokens/ERC20/IERC20.sol (L17-17)
```text
    function approve(address spender, uint256 amount) external returns (bool);
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
