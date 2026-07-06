### Title
ETH Sent to `tick()` Is Permanently Locked When No Minting Is Required - (File: L1/starkware/solidity/stake/RewardSupplier.sol)

### Summary
The `tick()` function in `RewardSupplier.sol` is `payable` and accepts ETH as messaging fees for L1→L2 bridge and minting-curve calls. However, when `amountToMint == 0` (no pending mint requests), the entire `msg.value` is silently discarded — the ETH is never forwarded and there is no withdrawal mechanism, so it is permanently locked in the contract.

### Finding Description
`tick()` is declared `external payable`. Its body only spends `msg.value` inside the `if (amountToMint > 0)` branch:

```solidity
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();

    if (amountToMint > 0) {
        ...
        uint256 msgFee = msg.value / 2;
        bridge().depositWithMessage{value: msgFee}(...);   // uses half
        ...
        msgFee = msg.value - msgFee;
        messagingContract().sendMessageToL2{value: msgFee}(...); // uses other half
    }
    // ← if amountToMint == 0, msg.value is never touched
}
``` [1](#0-0) 

When `requiredMinting()` returns `(0, 0)` — which happens whenever there are no unconsumed L2→L1 mint-request messages — the function returns immediately without using or refunding `msg.value`. There is no `receive()`, `fallback()`, or ETH-sweep function in the contract, so any ETH sent in this call is permanently locked. [2](#0-1) 

### Impact Explanation
Any caller who sends ETH to `tick()` when no minting is pending loses that ETH permanently. The contract has no recovery path. This constitutes a permanent freezing of the caller's funds. The impact maps to **Medium: Griefing with no profit motive but damage to users or protocol** (caller's ETH is irrecoverably locked).

### Likelihood Explanation
`tick()` is a public, permissionless function intended to be called by keepers or any external actor. A caller who sends ETH to cover messaging fees without first checking `requiredMinting()` — or who races with another caller that already consumed the pending messages — will have their ETH locked. This is a realistic operational mistake, especially for automated keeper bots that always attach a fee budget.

### Recommendation
Add a guard that reverts if ETH is sent but no minting work will be performed:

```solidity
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();

    if (amountToMint > 0) {
        // existing logic
    } else {
        require(msg.value == 0, "No minting required: ETH would be locked");
    }
}
```

Alternatively, refund any unused ETH at the end of the function.

### Proof of Concept
1. No L2→L1 mint-request messages are pending, so `requiredMinting()` returns `(0, 0)`.
2. A keeper calls `tick{value: 1 ether}()` to pre-fund messaging fees.
3. The `if (amountToMint > 0)` branch is skipped; `msg.value` is never forwarded.
4. The 1 ETH is now held by `RewardSupplier` with no function to retrieve it.
5. The keeper's ETH is permanently lost. [1](#0-0)

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
