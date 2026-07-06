### Title
ETH Sent to `tick()` is Permanently Locked When No Minting is Required - (File: `L1/starkware/solidity/stake/RewardSupplier.sol`)

---

### Summary

The `tick()` function in `RewardSupplier.sol` is `external payable` and accepts ETH from any caller to fund L1→L2 message fees. However, when `amountToMint == 0` (no minting is required), the function exits the `if` block without consuming or refunding `msg.value`. Any ETH sent in this case is permanently locked in the `RewardSupplier` contract, which has no ETH withdrawal or recovery mechanism.

---

### Finding Description

`tick()` first calls `requiredMinting()` to determine whether minting is needed:

```solidity
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();

    if (amountToMint > 0) {
        // ... consumes msg.value across two sub-calls
        uint256 msgFee = msg.value / 2;
        bridge().depositWithMessage{value: msgFee}(...);
        msgFee = msg.value - msgFee;
        messagingContract().sendMessageToL2{value: msgFee}(...);
    }
    // If amountToMint == 0: msg.value is silently retained by the contract
}
``` [1](#0-0) 

When `amountToMint == 0`, the `if` block is skipped entirely. `msg.value` is already in the contract's balance and there is no `else` branch, no `require(msg.value == 0)` guard, and no refund call. The `RewardSupplier` contract defines no `receive()`, `fallback()`, or ETH-withdrawal function, so the ETH is irrecoverable. [2](#0-1) 

This is the direct analog of the reported pattern: a payable function that accepts ETH ≥ the required fee but forwards none of the excess to the original caller, causing it to be locked in an intermediate contract.

---

### Impact Explanation

Any ETH sent to `tick()` when `amountToMint == 0` is permanently locked in `RewardSupplier`. The contract has no withdrawal path and no `receive()` hook. This constitutes **permanent freezing of funds** for the caller. The impact maps to the allowed scope: *Griefing with no profit motive but damage to users or protocol* (Medium).

---

### Likelihood Explanation

`tick()` is callable by any account (`anyAccount` per the spec diagram). [3](#0-2) 

A caller cannot atomically check `requiredMinting()` and call `tick()` in a single transaction without a wrapper contract. A naive caller (e.g., a keeper bot or off-chain script) may send ETH speculatively to ensure the transaction does not revert due to insufficient fee, without knowing whether `amountToMint > 0`. This is a realistic operational scenario, making likelihood Medium.

---

### Recommendation

Add a guard or refund at the end of `tick()`:

```solidity
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();
    if (amountToMint > 0) {
        // ... existing logic
    }
    // Refund any unused ETH to the caller
    if (address(this).balance > 0) {
        (bool ok,) = msg.sender.call{value: address(this).balance}("");
        require(ok, "ETH_REFUND_FAILED");
    }
}
```

Alternatively, add `require(msg.value == 0 || amountToMint > 0, "NO_MINT_NEEDED")` at the top of the function to prevent ETH from being sent when it will not be used.

---

### Proof of Concept

1. Ensure `requiredMinting()` returns `(0, 0)` — i.e., the L2 reward supplier has not sent any pending mint-request messages to L1.
2. Call `RewardSupplier.tick{value: 1 ether}()`.
3. The `if (amountToMint > 0)` block is skipped.
4. `address(rewardSupplier).balance` increases by `1 ether`.
5. No function exists on `RewardSupplier` to withdraw or recover this ETH.
6. The 1 ETH is permanently locked. [1](#0-0)

### Citations

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

**File:** docs/spec.md (L555-560)
```markdown
  anyAccount ->>+ RewardSupplier: tick(tokensPerMintAmount, maxMessagesToProcess)
  RewardSupplier ->>+ MintingManager: mintRequest(totalAmountToMint)
  MintingManager ->>- STRK ERC20: mint
  RewardSupplier ->>+ StarkGate bridge: depositWithMessage
  deactivate RewardSupplier
```
```
