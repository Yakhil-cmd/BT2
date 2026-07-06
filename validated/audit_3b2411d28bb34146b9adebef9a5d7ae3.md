The vulnerability is real and confirmed by the code.

**Key facts:**

1. `tick()` is declared `external payable` — it accepts ETH from any caller. [1](#0-0) 

2. `msg.value` is only consumed inside the `if (amountToMint > 0)` branch — the two `{value: msgFee}` calls to `bridge().depositWithMessage` and `messagingContract().sendMessageToL2`. [2](#0-1) 

3. When `amountToMint == 0` (no pending L2→L1 mint-request messages), the function returns immediately after the `if` block without touching `msg.value`. [3](#0-2) 

4. No `withdraw`, `rescue`, `receive()`, or `fallback()` function exists anywhere in the L1 stake contracts — confirmed by exhaustive grep across all `.sol` files in `L1/starkware/solidity/stake/`. 

---

### Title
ETH permanently locked in `RewardSupplier` when `tick()` is called with `msg.value > 0` and no pending mint messages — (`L1/starkware/solidity/stake/RewardSupplier.sol`)

### Summary
`tick()` is `payable` but only forwards `msg.value` to downstream calls inside the `if (amountToMint > 0)` branch. When no L2→L1 mint-request messages are pending, the branch is skipped and any ETH sent by the caller is silently retained by the contract with no recovery path.

### Finding Description
`requiredMinting()` queries the messaging contract for pending messages. If the count is zero, `amountToMint == 0` and the `if` block is never entered. The two fee-forwarding lines (`msg.value / 2` to the bridge, remainder to the messaging contract) are never reached. Because the contract has no `receive()`, `fallback()`, or any ETH-withdrawal function, the ETH is irrecoverably locked.

```
tick() called with msg.value = 1 wei, 0 pending messages
  → requiredMinting() returns (0, 0)
  → if (0 > 0) → false, branch skipped
  → function returns
  → 1 wei locked in contract forever
```

### Impact Explanation
Any ETH sent to `tick()` during a zero-pending-message window is permanently frozen. The function is callable by any unprivileged account (`external`), and the zero-pending-message state is the normal steady-state between L2 mint-request cycles. Repeated calls accumulate locked ETH with no bound. Impact: **permanent freezing of caller ETH**.

### Likelihood Explanation
High. The zero-pending-message state is the default between reward cycles. Any caller who passes a non-zero `msg.value` (e.g., to pre-pay fees speculatively, or by mistake) loses those funds permanently. The function signature gives no indication that ETH is only safe to send when messages are pending.

### Recommendation
Add a guard at the top of `tick()` that refunds `msg.value` when `amountToMint == 0`, or restructure so ETH is only accepted when it will actually be used:

```solidity
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();
    if (amountToMint == 0) {
        if (msg.value > 0) {
            (bool ok,) = msg.sender.call{value: msg.value}("");
            require(ok, "ETH_REFUND_FAILED");
        }
        return;
    }
    // ... existing logic ...
}
```

Alternatively, remove `payable` and require callers to hold ETH in the contract beforehand, or split into two entry points.

### Proof of Concept
```solidity
// Precondition: no L2→L1 mint-request messages pending (normal steady state)
for (uint i = 0; i < 100; i++) {
    rewardSupplier.tick{value: 1}();
}
assert(address(rewardSupplier).balance == 100);
// No withdrawal function exists → 100 wei permanently locked
```

### Citations

**File:** L1/starkware/solidity/stake/RewardSupplier.sol (L107-107)
```text
    function tick() external payable {
```

**File:** L1/starkware/solidity/stake/RewardSupplier.sol (L109-142)
```text
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
```
