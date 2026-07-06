### Title
Excess `msg.value` Permanently Lost in `tick()` When No Minting Is Required - (File: `L1/starkware/solidity/stake/RewardSupplier.sol`)

---

### Summary

`RewardSupplier.sol`'s `tick()` function is `external payable` but contains no guard against receiving ETH when no minting work is performed. Any ETH sent by a caller when `amountToMint == 0` is permanently trapped in the contract with no recovery path.

---

### Finding Description

`tick()` is declared `external payable` and splits `msg.value` between two bridge calls only inside the `if (amountToMint > 0)` branch:

```solidity
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();

    if (amountToMint > 0) {
        // ...
        uint256 msgFee = msg.value / 2;
        bridge().depositWithMessage{value: msgFee}(...);   // consumes half

        msgFee = msg.value - msgFee;
        messagingContract().sendMessageToL2{value: msgFee}(...); // consumes other half
    }
    // ← if amountToMint == 0, msg.value is never used and never refunded
}
``` [1](#0-0) 

Two distinct loss scenarios exist:

1. **`amountToMint == 0`**: The entire `if` block is skipped. `msg.value` is silently accepted and permanently locked in the contract.
2. **`amountToMint > 0` with excess ETH**: The function only uses exactly `msg.value` for the two bridge calls, but there is no validation that `msg.value` equals the precise fee required by those calls. Any ETH above the minimum accepted by the bridge is consumed from the contract balance but provides no benefit to the caller.

There is no `receive()` fallback, no `withdraw()` function, and no ETH refund path anywhere in the contract, so trapped ETH cannot be recovered.

---

### Impact Explanation

Any ETH sent to `tick()` when `amountToMint == 0` is permanently frozen in the `RewardSupplier` contract. The contract has no ETH withdrawal mechanism. This constitutes **permanent freezing of funds** belonging to the caller.

Mapped allowed impact: **High — Permanent freezing of funds / Temporary freezing of funds**.

---

### Likelihood Explanation

`tick()` is a public, permissionless function intended to be called by off-chain keepers or bots. A caller that:
- polls `requiredMinting()` off-chain but races with another caller who already consumed the pending messages, or
- sends ETH speculatively to ensure the bridge call succeeds,

will have their ETH permanently lost. This is a realistic operational mistake, analogous to the original report's "software performing trading contains an error." Likelihood is **Low** but the scenario is reachable by any unprivileged external caller.

---

### Recommendation

Add a guard that rejects non-zero `msg.value` when no minting work will be done, and validate the exact fee when minting is performed:

```diff
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();

+   if (amountToMint == 0) {
+       require(msg.value == 0, "No minting needed: refund ETH");
+       return;
+   }

    if (amountToMint > 0) {
        ...
    }
}
```

Alternatively, refund any unused ETH at the end of the function.

---

### Proof of Concept

1. Off-chain keeper calls `requiredMinting()` — returns `(X, N)` with `X > 0`.
2. A second keeper races and calls `tick{value: 1 ether}()` first, consuming all pending L2→L1 messages.
3. The first keeper's transaction lands: `requiredMinting()` now returns `(0, 0)`.
4. The `if (amountToMint > 0)` block is skipped entirely.
5. The 1 ETH sent by the first keeper is permanently locked in `RewardSupplier.sol` with no recovery path. [1](#0-0)

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
