### Title
ETH Sent to `tick()` Is Permanently Trapped When No Minting Is Required — (`File: L1/starkware/solidity/stake/RewardSupplier.sol`)

---

### Summary

`RewardSupplier.tick()` is an unrestricted `payable` function that accepts ETH as L1→L2 message fees. When called with `msg.value > 0` but no pending L2 mint requests exist (`amountToMint == 0`), the function silently returns without forwarding or refunding the ETH. The ETH is trapped in the contract with no built-in recovery path.

---

### Finding Description

`RewardSupplier.tick()` is declared `external payable` with no access control. Its logic is gated on `amountToMint > 0`:

```solidity
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();

    if (amountToMint > 0) {
        // ... forwards msg.value to bridge and messagingContract ...
        uint256 msgFee = msg.value / 2;
        bridge().depositWithMessage{value: msgFee}(...);
        msgFee = msg.value - msgFee;
        messagingContract().sendMessageToL2{value: msgFee}(...);
    }
    // ← if amountToMint == 0, msg.value is silently discarded
}
``` [1](#0-0) 

When `amountToMint == 0`, the `if` block is skipped entirely. `msg.value` is never forwarded and never returned. The contract has no `receive()` fallback, no ETH withdrawal function, and no sweep mechanism. [1](#0-0) 

The contract inherits `ProxySupportImpl` (making it upgradeable via proxy), but there is no built-in ETH recovery — recovery would require a privileged governance upgrade. [2](#0-1) 

---

### Impact Explanation

Any caller who sends ETH with `tick()` when no L2 mint requests are pending loses that ETH. The ETH accumulates in the contract with no direct withdrawal path. Recovery requires a governance-controlled contract upgrade. This constitutes **temporary freezing of funds** (High).

---

### Likelihood Explanation

`tick()` has no access control — any public caller can invoke it. A realistic scenario is a race condition: a caller queries `requiredMinting()`, observes pending mints, prepares a transaction with ETH, but by the time the transaction is mined another caller has already processed the mint requests. The caller's ETH is then trapped. This is a realistic, low-effort scenario requiring no special privileges. [3](#0-2) 

---

### Recommendation

Add a refund of unused ETH at the end of `tick()`:

```solidity
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();

    if (amountToMint > 0) {
        // ... existing logic ...
    } else if (msg.value > 0) {
        // Refund ETH if no minting was needed.
        (bool ok, ) = msg.sender.call{value: msg.value}("");
        require(ok, "ETH_REFUND_FAILED");
    }
}
```

Alternatively, remove the `payable` modifier and require callers to send ETH only when minting is confirmed necessary, or add a `require(amountToMint > 0 || msg.value == 0)` guard at the top.

---

### Proof of Concept

1. L2 reward supplier has no pending mint requests (all previously consumed, or none yet emitted).
2. Caller calls `requiredMinting()` — returns `(0, 0)`.
3. Caller (or a racing caller) calls `tick{value: 1 ether}()`.
4. `amountToMint == 0`, the `if` block is skipped.
5. Function returns. The 1 ETH is now held by `RewardSupplier` with no recovery path.
6. `address(rewardSupplier).balance` increases by 1 ETH permanently (until a governance upgrade). [1](#0-0)

### Citations

**File:** L1/starkware/solidity/stake/RewardSupplier.sol (L23-23)
```text
contract RewardSupplier is RewardSupplierStorage, Identity, ProxySupportImpl {
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
