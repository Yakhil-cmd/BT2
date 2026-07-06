### Title
ETH Permanently Locked in `RewardSupplier` When `tick()` Called With No Pending Mint Requests - (File: `L1/starkware/solidity/stake/RewardSupplier.sol`)

---

### Summary

The `tick()` function in `RewardSupplier.sol` is `payable` and splits `msg.value` between two downstream calls. However, the entire ETH-spending logic is gated behind `if (amountToMint > 0)`. When there are no pending L2 mint-request messages, `amountToMint == 0`, the branch is skipped, and any ETH sent by the caller is silently absorbed by the contract with no refund and no recovery path.

---

### Finding Description

`tick()` is declared `payable` and uses `msg.value` in two places: [1](#0-0) 

```solidity
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();

    if (amountToMint > 0) {
        ...
        uint256 msgFee = msg.value / 2;                          // line 125
        bridge().depositWithMessage{value: msgFee}(...);
        ...
        msgFee = msg.value - msgFee;                             // line 135
        messagingContract().sendMessageToL2{value: msgFee}(...);
    }
    // ← if amountToMint == 0, execution ends here; msg.value is never used
}
```

`msg.value` is only consumed inside the `if (amountToMint > 0)` block. [2](#0-1) 

When `requiredMinting()` returns `(0, 0)` — which happens whenever there are no pending L2→L1 mint-request messages — the function body is a no-op, yet the contract has already accepted the caller's ETH. [3](#0-2) 

There is no `receive()`, `fallback()`, withdrawal, or rescue function anywhere in the L1 contract suite, so the ETH has no exit path. 

---

### Impact Explanation

Any ETH sent to `tick()` during a no-op call is **permanently frozen** inside `RewardSupplier`. This matches the allowed impact: **Temporary/Permanent freezing of funds (High)**.

---

### Likelihood Explanation

`tick()` is a public, permissionless function intended to be called by keepers or automated bots. The condition `amountToMint == 0` is the normal steady-state between reward epochs — it is not an edge case. Any caller who sends ETH (e.g., to pre-pay bridge fees) during such a window loses those funds permanently. The likelihood is **High**.

---

### Recommendation

Add an ETH refund when `amountToMint == 0`:

```solidity
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();

    if (amountToMint > 0) {
        // ... existing logic ...
    } else if (msg.value > 0) {
        // Refund unused ETH
        (bool ok, ) = msg.sender.call{value: msg.value}("");
        require(ok, "ETH_REFUND_FAILED");
    }
}
```

Alternatively, document that callers must not send ETH when there are no pending mint requests, and enforce `require(msg.value == 0)` in the no-op branch.

---

### Proof of Concept

1. No L2 mint-request messages are pending (normal between epochs).
2. A keeper bot calls `tick{value: 0.1 ether}()` to pre-fund bridge fees.
3. `requiredMinting()` returns `(0, 0)` → `amountToMint == 0`.
4. The `if` block is skipped entirely; `msg.value` is never forwarded.
5. `0.1 ETH` is now held by `RewardSupplier` with no withdrawal mechanism.
6. The ETH is permanently locked. [1](#0-0)

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
