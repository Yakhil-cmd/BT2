### Title
ETH Permanently Locked in `RewardSupplier` When `tick()` Called With No Pending Mint Requests - (File: `L1/starkware/solidity/stake/RewardSupplier.sol`)

---

### Summary
`RewardSupplier.tick()` is declared `payable` and accepts ETH as L1→L2 message fees, but when there are no pending mint requests (`amountToMint == 0`), the entire `msg.value` is silently consumed by the contract with no refund and no recovery path. The contract has no `receive()` fallback, no `withdraw()` function, and no other ETH-recovery mechanism.

---

### Finding Description
The `tick()` function in `RewardSupplier.sol` is callable by any unprivileged address and is marked `payable`. Its intended use is to forward ETH as fees for two L1→L2 messages: one to the StarkGate bridge (`depositWithMessage`) and one to the messaging contract (`sendMessageToL2`). [1](#0-0) 

The critical path is:

```solidity
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();

    if (amountToMint > 0) {
        // ... msg.value is split and forwarded to bridge + messaging contract
    }
    // ← If amountToMint == 0, execution ends here.
    //   msg.value is NOT refunded and NOT used.
}
```

When `requiredMinting()` returns `(0, 0)` — which is the normal state between minting cycles when no L2 mint-request messages are pending — the entire `if` block is skipped. Any ETH attached to the call is permanently locked inside the `RewardSupplier` proxy contract. There is no `receive()` function, no `fallback()`, and no `withdraw()` or sweep function anywhere in the contract or its storage layout. [2](#0-1) 

The fee-splitting logic itself also introduces a secondary loss vector: when `msg.value` is odd, integer division `msg.value / 2` truncates, and the remainder is consumed by the second message fee assignment (`msg.value - msgFee`). Neither path refunds dust. [3](#0-2) 

---

### Impact Explanation
Any ETH sent to `tick()` when `amountToMint == 0` is permanently frozen inside the `RewardSupplier` contract. Because there is no withdrawal or sweep mechanism, the funds are irrecoverable. This maps to **High: Permanent freezing of funds** — the caller's ETH is locked with no recovery path, which is at least as severe as the listed "Temporary freezing of funds" impact.

---

### Likelihood Explanation
`tick()` is a public, permissionless function intended to be called by any keeper or bot. Between minting cycles — the majority of the time — `requiredMinting()` returns zero. Any caller who attaches ETH (e.g., a keeper script that always sends a fee budget) during this window permanently loses that ETH. The scenario is realistic and requires no special privileges or coordination.

---

### Recommendation
Add a guard that either rejects ETH when there is nothing to mint, or refunds it:

```solidity
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();

    if (amountToMint > 0) {
        // ... existing logic
    } else {
        // Refund any accidentally attached ETH.
        if (msg.value > 0) {
            (bool ok, ) = msg.sender.call{value: msg.value}("");
            require(ok, "ETH_REFUND_FAILED");
        }
    }
}
```

Alternatively, remove `payable` from `tick()` entirely and require callers to pre-fund the contract with ETH via a separate, access-controlled deposit function, eliminating the per-call ETH attachment pattern.

---

### Proof of Concept
1. No L2 mint-request messages are pending (normal state between reward cycles).
2. A keeper calls `tick{value: 0.1 ether}()`.
3. `requiredMinting()` returns `(0, 0)`.
4. The `if (amountToMint > 0)` block is skipped entirely.
5. The function returns without touching `msg.value`.
6. `0.1 ETH` is now held by the `RewardSupplier` contract with no mechanism to recover it.
7. Repeating this across multiple keeper calls accumulates permanently locked ETH. [1](#0-0)

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
