### Title
ETH Sent as Fee to `tick()` Is Permanently Locked When No Minting Is Required - (File: `L1/starkware/solidity/stake/RewardSupplier.sol`)

---

### Summary

`RewardSupplier.tick()` is a `payable` function that accepts ETH to cover L1→L2 messaging fees. When there are no pending L2 mint requests (`amountToMint == 0`), the entire fee-spending block is skipped and the ETH sent by the caller is never refunded, permanently locking it in the contract.

---

### Finding Description

`tick()` is declared `external payable` and is callable by any address with no access control. The caller is expected to supply ETH to fund two cross-chain operations:

1. `bridge().depositWithMessage{value: msgFee}(...)` — deposits minted tokens to L2 via StarkGate.
2. `messagingContract().sendMessageToL2{value: msgFee}(...)` — sends a `totalSupply` update to the L2 minting curve.

Both operations are gated behind `if (amountToMint > 0)`:

```solidity
// RewardSupplier.sol lines 107-143
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();

    if (amountToMint > 0) {
        // ... consume messages, mint, bridge, send L2 message ...
        uint256 msgFee = msg.value / 2;
        bridge().depositWithMessage{value: msgFee}(...);
        msgFee = msg.value - msgFee;
        messagingContract().sendMessageToL2{value: msgFee}(...);
    }
    // No else branch — msg.value is silently consumed when amountToMint == 0
}
```

When `requiredMinting()` returns `(0, 0)` — which happens whenever the L2 reward supplier has not yet emitted any pending `MintRequest` messages — the `if` block is entirely skipped. `msg.value` is never forwarded to any external call and is never returned to the caller. The contract has no `receive()`, `fallback()`, or `withdraw()` function, so the ETH is permanently irrecoverable. [1](#0-0) 

---

### Impact Explanation

Any ETH sent by a caller to `tick()` when no minting is required is permanently locked in the `RewardSupplier` contract. There is no sweep, rescue, or withdrawal mechanism. This constitutes a **permanent freezing / direct loss of caller funds** — matching the allowed impact of **Temporary/Permanent freezing of funds (High)** or **Direct theft of user funds (Critical)** depending on classification, since the funds are irrecoverable.

---

### Likelihood Explanation

- `tick()` is a public, permissionless function with no access control — any EOA or keeper bot can call it.
- The function is designed to be called periodically by off-chain keepers who supply ETH for fees.
- A keeper calling `tick()` speculatively (e.g., to check if minting is needed) or during a period with no pending L2 mint requests will lose all ETH sent.
- The condition `amountToMint == 0` is the normal steady-state between reward epochs, making this a frequently reachable path. [2](#0-1) 

---

### Recommendation

Add a refund path for the case where no minting is performed:

```solidity
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();

    if (amountToMint > 0) {
        // ... existing logic ...
    } else if (msg.value > 0) {
        // Refund unused fee to caller
        (bool ok, ) = msg.sender.call{value: msg.value}("");
        require(ok, "ETH_REFUND_FAILED");
    }
}
```

Alternatively, remove `payable` from `tick()` and require callers to send ETH only when `requiredMinting()` confirms minting is needed.

---

### Proof of Concept

1. L2 reward supplier has no pending `MintRequest` messages (normal steady-state between epochs).
2. A keeper calls `RewardSupplier.tick{value: 1 ether}()`.
3. `requiredMinting()` returns `(0, 0)` because `messagingContract().l2ToL1Messages(msgHash) == 0`.
4. The `if (amountToMint > 0)` branch is skipped entirely.
5. The function returns without refunding `msg.value`.
6. The 1 ETH is permanently locked in `RewardSupplier` with no recovery path. [1](#0-0)

### Citations

**File:** L1/starkware/solidity/stake/RewardSupplier.sol (L93-143)
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
