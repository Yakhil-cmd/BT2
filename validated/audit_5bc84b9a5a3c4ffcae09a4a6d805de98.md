### Title
`tick()` is `payable` but silently discards ETH when no minting is required - (File: `L1/starkware/solidity/stake/RewardSupplier.sol`)

### Summary
`RewardSupplier.tick()` is declared `payable` and uses `msg.value` to pay L1→L2 bridge and messaging fees, but only inside a conditional block that executes when `amountToMint > 0`. When no pending mint requests exist (`amountToMint == 0`), the function returns without consuming `msg.value`, permanently trapping any ETH sent by the caller in the contract with no recovery path.

### Finding Description
In `RewardSupplier.sol`, `tick()` is marked `payable` at line 107. Inside the function, `msg.value` is split between two fee-bearing calls:

```solidity
uint256 msgFee = msg.value / 2;
bridge().depositWithMessage{value: msgFee}(...);   // line 126
msgFee = msg.value - msgFee;
messagingContract().sendMessageToL2{value: msgFee}(...); // line 137
```

Both of these calls are gated behind `if (amountToMint > 0)` at line 111. When `requiredMinting()` returns `(0, 0)` — which happens whenever there are no pending L2→L1 mint-request messages — the entire body of the `if` block is skipped and the function returns. Any ETH attached to the call is left in the contract.

The contract defines no `receive()`, `fallback()`, or ETH-withdrawal function, so trapped ETH is unrecoverable. [1](#0-0) 

### Impact Explanation
Any caller who sends ETH with `tick()` during a period when no mint requests are pending permanently loses that ETH. The contract has no mechanism to refund or withdraw stranded ETH. This constitutes a direct, permanent loss of caller funds — matching the **Medium** impact class: *griefing with no profit motive but damage to users or protocol*, and also *temporary/permanent freezing of funds*.

### Likelihood Explanation
`tick()` is a public, permissionless function intended to be called by any keeper or automation bot. Callers are expected to supply ETH as messaging fees. The condition `amountToMint == 0` is the normal steady-state between reward cycles (when the L2 reward supplier has sufficient balance and has not yet emitted a new mint request). A caller who does not first query `requiredMinting()` off-chain — or who races with another `tick()` call that drains the pending messages — will silently lose their ETH. This is a realistic, reachable scenario for any unprivileged public caller.

### Recommendation
Add a guard at the top of `tick()` to revert when no ETH is needed:

```solidity
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();
+   require(amountToMint > 0 || msg.value == 0, "NO_MINT_REQUIRED");
    if (amountToMint > 0) {
        ...
    }
}
```

Alternatively, refund unused ETH at the end of the function, or remove `payable` and require callers to pre-fund the contract separately.

### Proof of Concept
1. Observe that `requiredMinting()` returns `(0, 0)` when `messagingContract().l2ToL1Messages(msgHash) == 0` (no pending mint requests). [2](#0-1) 
2. Call `tick{value: 1 ether}()` while no mint requests are pending.
3. The `if (amountToMint > 0)` block is skipped entirely. [3](#0-2) 
4. The function returns. `address(rewardSupplier).balance` increases by `1 ether`; the caller's ETH is gone with no event emitted and no revert.
5. No `withdraw` or `receive` function exists in the contract to recover the ETH. [4](#0-3)

### Citations

**File:** L1/starkware/solidity/stake/RewardSupplier.sol (L23-30)
```text
contract RewardSupplier is RewardSupplierStorage, Identity, ProxySupportImpl {
    using Addresses for address;
    event ConsumedL2MintRequests(uint256 messagesConsumed, uint256 amountMinted);

    function identify() external pure override returns (string memory) {
        return "StarkWare_RewardSupplier_2024_1";
    }

```

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
