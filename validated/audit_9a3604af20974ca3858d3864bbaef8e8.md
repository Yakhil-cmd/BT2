### Title
ETH Permanently Locked in `RewardSupplier` When `tick()` Called With No Pending Mints - (File: `L1/starkware/solidity/stake/RewardSupplier.sol`)

---

### Summary

`RewardSupplier.tick()` is `external payable` but contains no refund path when `amountToMint == 0`. Any ETH sent by a caller in that case is permanently locked in the contract with no recovery mechanism.

---

### Finding Description

`tick()` accepts ETH to cover two L1→L2 messaging fees: one for `bridge().depositWithMessage` and one for `messagingContract().sendMessageToL2`. However, the entire function body that uses `msg.value` is gated behind `if (amountToMint > 0)`:

```solidity
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();

    if (amountToMint > 0) {
        // ... uses msg.value ...
        uint256 msgFee = msg.value / 2;
        bridge().depositWithMessage{value: msgFee}(...);
        msgFee = msg.value - msgFee;
        messagingContract().sendMessageToL2{value: msgFee}(...);
    }
    // No else branch, no refund, no revert
}
```

When `amountToMint == 0`, the function returns silently. `msg.value` is accepted by the contract but never forwarded or returned. The contract has no `withdraw()`, no `receive()` fallback, and no other ETH-recovery mechanism across all Solidity files in scope.

A realistic race condition:
1. Caller queries `requiredMinting()` off-chain — sees pending mint requests.
2. Caller submits `tick()` with sufficient ETH for both fees.
3. A front-runner (or another legitimate keeper) calls `tick()` first, consuming all pending messages.
4. Caller's transaction executes: `amountToMint == 0`, the `if` branch is skipped, and the caller's ETH is permanently locked.

A malicious actor can deliberately front-run any `tick()` call in the mempool to grief the caller and cause permanent ETH loss.

---

### Impact Explanation

ETH sent to `tick()` under the race/front-run condition is permanently locked in `RewardSupplier` with no recovery path. This constitutes permanent freezing of the caller's funds. Matches: **High — Permanent freezing of funds**.

---

### Likelihood Explanation

`tick()` is a public, permissionless, payable function. Callers must read `requiredMinting()` off-chain before sending ETH, creating a classic TOCTOU window. On Ethereum mainnet, front-running is trivially achievable via MEV bots. Any time a legitimate keeper submits `tick()` with ETH, a front-runner can consume the pending messages first, causing the keeper's ETH to be locked. This is a realistic, repeatable attack.

---

### Recommendation

Add a refund for unused ETH when `amountToMint == 0`, mirroring the fix in the referenced external report:

```solidity
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();

    if (amountToMint > 0) {
        // ... existing logic ...
    } else if (msg.value > 0) {
        // Refund ETH if there is nothing to mint.
        (bool ok, ) = msg.sender.call{value: msg.value}("");
        require(ok, "ETH_REFUND_FAILED");
    }
}
```

---

### Proof of Concept

1. State: one pending L2→L1 mint request exists (`requiredMinting()` returns `(1_300_000e18, 1)`).
2. Keeper A submits `tick{value: 0.01 ether}()`.
3. Attacker sees the mempool entry and submits `tick{value: 0.001 ether}()` with higher gas price.
4. Attacker's `tick()` mines first: consumes the mint request, uses `0.001 ether` for fees.
5. Keeper A's `tick()` mines: `requiredMinting()` returns `(0, 0)`, `amountToMint == 0`, the `if` block is skipped, `0.01 ether` is accepted and permanently locked.
6. No function in `RewardSupplier` can recover the locked ETH. [1](#0-0) [2](#0-1)

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
