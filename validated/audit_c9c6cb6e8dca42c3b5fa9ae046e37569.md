### Title
ETH Permanently Locked in `RewardSupplier.sol` When `tick()` Called With No Pending Mint Requests - (File: `L1/starkware/solidity/stake/RewardSupplier.sol`)

---

### Summary
The L1 `RewardSupplier.sol` contract exposes a `payable` `tick()` function that accepts ETH to cover L1→L2 messaging fees. When there are no pending mint requests (`amountToMint == 0`), the function returns immediately without consuming `msg.value`. Because the contract has no `withdraw()` function and no `receive()`/`fallback()` recovery path, any ETH sent in this scenario is permanently locked.

---

### Finding Description

The `tick()` function in `RewardSupplier.sol` is declared `external payable` and uses `msg.value` to fund two StarkGate/messaging calls when minting is required:

```solidity
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();

    if (amountToMint > 0) {
        // ...
        uint256 msgFee = msg.value / 2;
        bridge().depositWithMessage{value: msgFee}(...);   // consumes half
        msgFee = msg.value - msgFee;
        messagingContract().sendMessageToL2{value: msgFee}(...); // consumes rest
    }
    // ← if amountToMint == 0, msg.value is silently discarded
}
``` [1](#0-0) 

When `amountToMint == 0` (no L2→L1 mint-request messages are pending), the `if` block is skipped entirely. `msg.value` is never forwarded, refunded, or stored for later use. The contract contains no `withdraw`, `rescue`, or `receive` function to recover stranded ETH. [2](#0-1) 

---

### Impact Explanation

Any ETH sent to `tick()` during a no-op call (no pending mint requests) is permanently locked in the `RewardSupplier` contract with no recovery path. This constitutes **permanent freezing of caller funds** (ETH). The impact maps to:

> **High: Permanent freezing of unclaimed yield or unclaimed royalties; Temporary freezing of funds**

The ETH lost is the caller's own funds (messaging-fee ETH), not protocol-internal tokens, but the freeze is permanent and irrecoverable.

---

### Likelihood Explanation

The condition `amountToMint == 0` is the **normal state** of the contract: it is true whenever the L2 `RewardSupplier` has not yet emitted a `MintRequest` L2→L1 message, or all pending messages have already been consumed. Any caller (permissionless — `tick()` is `external`) who sends ETH while the queue is empty loses those funds. Off-chain keepers or bots that call `tick()` speculatively (e.g., to trigger a supply update) are the most realistic victims. [3](#0-2) 

---

### Recommendation

1. **Refund unused ETH**: At the end of `tick()`, return any unspent `msg.value` to `msg.sender`:
   ```solidity
   if (amountToMint == 0 && msg.value > 0) {
       (bool ok,) = msg.sender.call{value: msg.value}("");
       require(ok, "ETH_REFUND_FAILED");
   }
   ```
2. **Or add a guarded `withdraw` function** restricted to a governance/admin role to recover accidentally locked ETH.
3. **Or remove `payable`** from `tick()` entirely if the intent is that callers should only call it when minting is needed (enforced off-chain).

---

### Proof of Concept

1. The L2 `RewardSupplier` has not yet sent any `MintRequest` messages to L1 (or all have been consumed). `messagingContract().l2ToL1Messages(msgHash) == 0`.
2. An unprivileged caller (keeper bot, MEV searcher, or any EOA) calls `RewardSupplier.tick{value: 1 ether}()`.
3. `requiredMinting()` returns `(0, 0)` because `numMsgsToConsume == 0`.
4. The `if (amountToMint > 0)` block is skipped.
5. `tick()` returns. The 1 ETH is now held by the contract.
6. No function exists to withdraw it. The ETH is permanently locked. [1](#0-0)

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
