### Title
ETH Sent to `RewardSupplier::tick()` Is Permanently Locked When No Minting Is Required - (File: `L1/starkware/solidity/stake/RewardSupplier.sol`)

---

### Summary

`RewardSupplier::tick()` is declared `external payable` and accepts ETH as message fees for L1→L2 bridge calls. However, when `amountToMint == 0` (no pending mint requests), the entire `if` block is skipped and the function returns without using or refunding `msg.value`. The ETH is permanently locked in the contract with no recovery mechanism.

---

### Finding Description

`tick()` is a permissionless, payable function that any caller can invoke with ETH to cover StarkGate bridge fees and `sendMessageToL2` fees:

```solidity
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();

    if (amountToMint > 0) {
        // ... uses msg.value / 2 for bridge, msg.value - msgFee for sendMessageToL2
    }
    // ← if amountToMint == 0, returns here; msg.value is never used or refunded
}
```

Two distinct loss paths exist:

1. **`amountToMint == 0`**: The `if` block is entirely skipped. All `msg.value` ETH is silently absorbed by the contract and never returned to the caller.
2. **`amountToMint > 0` but caller overpays**: The split `msg.value / 2` and `msg.value - msg.value/2` consumes exactly `msg.value`, but if the caller sends more ETH than the actual bridge and messaging fees require, the excess is forwarded to the external calls only up to what those calls consume — any remainder stays in the contract.

There is no `receive()`, `fallback()`, `withdraw()`, or any ETH-recovery function anywhere in `RewardSupplier.sol` or its visible storage contract. [1](#0-0) 

---

### Impact Explanation

Any caller who sends ETH to `tick()` when `requiredMinting()` returns zero loses their entire `msg.value` permanently. The ETH is locked in the `RewardSupplier` contract with no mechanism to recover it. This constitutes a **permanent freezing (loss) of the caller's funds** — mapping to the **High** impact tier: *"Permanent freezing of unclaimed yield or unclaimed royalties; Temporary freezing of funds."*

---

### Likelihood Explanation

`tick()` has no access control — any address may call it. Callers are economically motivated to trigger it to advance reward minting. A race condition is trivially reachable: a caller checks `requiredMinting()` off-chain, sees `amountToMint > 0`, prepares a transaction with ETH, but by the time the transaction lands another caller has already consumed all pending messages, making `amountToMint == 0` for the late transaction. The ETH is lost. This is a realistic, low-effort scenario requiring no privileged access. [2](#0-1) 

---

### Recommendation

Add a refund of unused ETH at the end of `tick()`:

```solidity
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();

    if (amountToMint > 0) {
        // ... existing logic ...
    }

    // Refund any unused ETH to the caller
    uint256 remaining = address(this).balance;
    if (remaining > 0) {
        (bool ok, ) = msg.sender.call{value: remaining}("");
        require(ok, "ETH_REFUND_FAILED");
    }
}
```

Alternatively, revert if `amountToMint == 0` and `msg.value > 0`, or require `msg.value == 0` when there is nothing to mint.

---

### Proof of Concept

1. L2 has no pending mint requests → `requiredMinting()` returns `(0, 0)`.
2. Caller submits `tick{value: 1 ether}()`.
3. `amountToMint == 0` → `if` block is skipped.
4. Function returns. `address(this).balance` increases by `1 ether`.
5. No function exists to withdraw that ETH. It is permanently locked. [1](#0-0)

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
