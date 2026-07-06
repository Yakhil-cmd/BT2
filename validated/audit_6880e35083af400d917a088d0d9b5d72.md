### Title
ETH Permanently Stuck in `RewardSupplier` When `tick()` Called With No Pending Mint Requests - (File: `L1/starkware/solidity/stake/RewardSupplier.sol`)

---

### Summary

The `tick()` function in `RewardSupplier.sol` is marked `payable` and uses `msg.value` to pay L1→L2 message fees — but only inside a conditional block that executes when `amountToMint > 0`. When there are no pending mint requests (`amountToMint == 0`), the entire fee-forwarding block is skipped and any ETH sent by the caller is permanently locked in the contract with no recovery path.

---

### Finding Description

`tick()` is an `external payable` function callable by any address:

```solidity
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();

    if (amountToMint > 0) {
        // ...
        uint256 msgFee = msg.value / 2;
        bridge().depositWithMessage{value: msgFee}(...);
        // ...
        msgFee = msg.value - msgFee;
        messagingContract().sendMessageToL2{value: msgFee}(...);
    }
    // ← if amountToMint == 0, msg.value is never used
}
``` [1](#0-0) 

`msg.value` is only consumed at lines 125–141 inside the `if (amountToMint > 0)` branch. When `requiredMinting()` returns `(0, 0)` — which happens whenever there are no pending L2→L1 `MintRequest` messages — the branch is never entered, the function returns silently, and all ETH sent with the call is trapped in the contract. [2](#0-1) 

The contract has no `receive()` fallback, no `withdraw` function, and no sweep mechanism, so trapped ETH is unrecoverable.

---

### Impact Explanation

Any ETH sent to `tick()` during a period with no pending mint requests is permanently frozen in the `RewardSupplier` contract. There is no admin withdrawal path in the contract. This constitutes **permanent freezing of funds** for the caller. [1](#0-0) 

---

### Likelihood Explanation

`tick()` is a public, permissionless function intended to be called by keepers or bots. Callers are expected to supply ETH to cover StarkNet messaging fees. The condition `amountToMint == 0` is routine — it occurs whenever the L2 reward supplier has not yet emitted a `MintRequest` message (e.g., between epochs, or when the L2 contract's `l1_pending_requested_amount` is already satisfied). A keeper that sends ETH speculatively (or that races with another keeper) will silently lose their ETH. [3](#0-2) 

---

### Recommendation

Add a guard at the top of `tick()` that reverts (or refunds) when no minting is needed but ETH was sent:

```solidity
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();
    if (amountToMint == 0) {
        require(msg.value == 0, "NO_MINT_NEEDED_NO_ETH_EXPECTED");
        return;
    }
    // ... rest of logic
}
```

This mirrors the recommendation in the original report for `zapFromVesting()`: validate that when the ETH-consuming branch will not execute, `msg.value` must be zero.

---

### Proof of Concept

1. The L2 reward supplier has no pending `MintRequest` messages (normal inter-epoch state).
2. A keeper calls `RewardSupplier.tick{value: 1 ether}()` to proactively cover fees.
3. `requiredMinting()` returns `(0, 0)` because `messagingContract().l2ToL1Messages(msgHash) == 0`.
4. The `if (amountToMint > 0)` block is skipped entirely.
5. The function returns. The 1 ETH is now held by the `RewardSupplier` contract.
6. There is no function in the contract to recover it — the ETH is permanently frozen. [4](#0-3)

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
