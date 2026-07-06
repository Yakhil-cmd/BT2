### Title
ETH Permanently Locked in `RewardSupplier` When `tick()` Called With `msg.value > 0` and No Pending Mint Requests — (File: `L1/starkware/solidity/stake/RewardSupplier.sol`)

---

### Summary
`RewardSupplier.tick()` is declared `external payable`, but the only code path that consumes `msg.value` is gated behind `if (amountToMint > 0)`. When no L2-to-L1 mint-request messages are pending, the function silently returns and any ETH sent by the caller is permanently locked. No `receive()`, `fallback()`, `withdraw`, or ETH-recovery function exists anywhere in the contract or its inheritance chain.

---

### Finding Description
`tick()` splits `msg.value` between two payable external calls:

```solidity
uint256 msgFee = msg.value / 2;
bridge().depositWithMessage{value: msgFee}(...);   // L1→L2 bridge fee
msgFee = msg.value - msgFee;
messagingContract().sendMessageToL2{value: msgFee}(...); // L1→L2 messaging fee
```

Both calls are inside the `if (amountToMint > 0)` block. [1](#0-0) 

When `requiredMinting()` returns `(0, 0)` — i.e., `messagingContract().l2ToL1Messages(msgHash) == 0` — the entire block is skipped and the function returns without touching `msg.value`. [2](#0-1) 

A grep across all L1 Solidity files confirms there is no `receive()`, `fallback()`, `withdraw`, or ETH-rescue function anywhere in `RewardSupplier`, `ProxySupportImpl`, or any parent contract. [3](#0-2) 

The root cause is structurally analogous to the reported SwiftSource bug: in both cases, native ETH is accepted by a payable function but is not forwarded to the intended recipient under a specific execution branch, causing the ETH to be silently lost/locked rather than correctly accounted for.

---

### Impact Explanation
Any ETH sent to `tick()` when `amountToMint == 0` is permanently locked in the `RewardSupplier` contract with no recovery path. This maps to **Medium: Griefing with no profit motive but damage to users or protocol** — a keeper/bot that calls `tick()` with ETH to pre-pay L1→L2 message fees loses those funds permanently if the call lands in the zero-mint-request state.

---

### Likelihood Explanation
`tick()` has no access control — it is callable by any address. [4](#0-3)  The zero-mint-request state is the normal state between reward cycles (L2 mint requests are batched and finite). A griefing attacker can:

1. Monitor the mempool for a keeper's `tick()` call that includes ETH.
2. Front-run it with their own `tick()` call (zero ETH) to consume all pending L2→L1 messages, driving `amountToMint` to 0.
3. The keeper's transaction then executes with `amountToMint == 0`, permanently locking the keeper's ETH.

This is a realistic, low-cost attack requiring no privileged access.

---

### Recommendation
Add a guard at the top of `tick()` to revert if ETH is sent but will not be used:

```solidity
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();
    require(amountToMint > 0 || msg.value == 0, "ETH_SENT_WITH_NO_MINT_REQUEST");
    ...
}
```

Alternatively, refund unused ETH at the end of the function, or add an ETH-rescue function restricted to governance.

---

### Proof of Concept

```solidity
// Attacker front-runs the keeper:
// Step 1: Attacker calls tick() with 0 ETH, consuming all pending L2→L1 messages.
rewardSupplier.tick{value: 0}();

// Step 2: Keeper's pending transaction executes.
// requiredMinting() now returns (0, 0).
// The if-block is skipped. keeperEth is permanently locked.
rewardSupplier.tick{value: keeperEth}();

// Result: keeperEth is stuck in RewardSupplier with no recovery path.
assert(address(rewardSupplier).balance >= keeperEth);
``` [1](#0-0)

### Citations

**File:** L1/starkware/solidity/stake/RewardSupplier.sol (L93-105)
```text
    function requiredMinting() public view returns (uint256, uint256) {
        uint256[] memory messagePayload = new uint256[](1);
        messagePayload[0] = TOKENS_PER_MINT_REQUEST;

        bytes32 msgHash = l2ToL1MsgHash(mintRequestSource(), address(this), messagePayload);
        // Limit the number of msgs to consume to limit.
        uint256 numMsgsToConsume = Math.min(
            messagingContract().l2ToL1Messages(msgHash),
            MAX_MESSAGES_TO_PROCESS_PER_TICK
        );

        return (TOKENS_PER_MINT_REQUEST * numMsgsToConsume, numMsgsToConsume);
    }
```

**File:** L1/starkware/solidity/stake/RewardSupplier.sol (L107-143)
```text
    function tick() external payable {
        // Check if minting is required, and how much.
        (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();

        if (amountToMint > 0) {
            // Prepare the L2->L1 mintRequest message for consumption.
            uint256[] memory messagePayload = new uint256[](1);
            messagePayload[0] = TOKENS_PER_MINT_REQUEST;

            // Consume the mintRequest messages.
            for (uint256 i = 0; i < numMsgsToConsume; i++) {
                messagingContract().consumeMessageFromL2(mintRequestSource(), messagePayload);
            }

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
            emit ConsumedL2MintRequests(numMsgsToConsume, amountToMint);

            // Send a totalSupply update to L2MintCurve.
            msgFee = msg.value - msgFee;
            messagePayload[0] = IERC20(token()).totalSupply();
            messagingContract().sendMessageToL2{value: msgFee}(
                mintingCurve(),
                UPDATE_TOTAL_SUPPLY_SELECTOR,
                messagePayload
            );
        }
    }
```

**File:** L1/starkware/solidity/upgrade/ProxySupportImpl.sol (L1-36)
```text
// SPDX-License-Identifier: Apache-2.0.
pragma solidity 0.8.24;

import "starkware/solidity/components/GovernanceStub.sol";
import "starkware/solidity/interfaces/ProxySupport.sol";

/**
  Implements the ProxySupport required code for the trivial case
  of a proxied contract that has no initialization and no sub-contracts.
  It can also be used for non-trivial cases simply by overriding what's needed.
*/
abstract contract ProxySupportImpl is ProxySupport, GovernanceStub {
    function validateInitData(bytes calldata data) internal view virtual override {
        require(data.length == 0, "ILLEGAL_DATA_SIZE");
    }

    function initializeContractState(bytes calldata data) internal virtual override {
        require(data.length == 0, "UNEXPECTED_DATA");
    }

    function isInitialized() internal view virtual override returns (bool) {
        return true;
    }

    function processSubContractAddresses(bytes calldata subContractAddresses)
        internal
        virtual
        override
    {
        require(subContractAddresses.length == 0, "UNEXPECTED_DATA");
    }

    function numOfSubContracts() internal pure virtual override returns (uint256) {
        return 0;
    }
}
```
