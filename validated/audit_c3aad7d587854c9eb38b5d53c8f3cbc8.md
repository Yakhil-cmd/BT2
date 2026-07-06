### Title
ETH Permanently Locked in `RewardSupplier` When `tick()` Called With No Pending Mint Requests — (File: `L1/starkware/solidity/stake/RewardSupplier.sol`)

---

### Summary
`RewardSupplier.sol` declares `tick()` as `payable` and relies on `msg.value` to fund L1→L2 messaging fees. However, when there are no pending mint requests (`amountToMint == 0`), the entire `if` block is skipped and `msg.value` is never forwarded or refunded. Because the contract has no `receive` function, no `fallback` function, and no ETH withdrawal mechanism anywhere in the L1 codebase, any ETH sent with such a call is permanently locked.

---

### Finding Description
`tick()` splits `msg.value` between two payable calls:

```solidity
uint256 msgFee = msg.value / 2;
bridge().depositWithMessage{value: msgFee}(...);
msgFee = msg.value - msgFee;
messagingContract().sendMessageToL2{value: msgFee}(...);
```

Both calls are inside `if (amountToMint > 0)`. [1](#0-0) 

When `requiredMinting()` returns `(0, 0)` — which happens whenever the L2→L1 message queue is empty — the function returns immediately without touching `msg.value`. [2](#0-1) 

A grep across all L1 Solidity files confirms there is no `receive()`, no `fallback()`, and no `withdraw` function anywhere in the contract hierarchy. 

The contract inherits `RewardSupplierStorage`, `Identity`, and `ProxySupportImpl` — none of which add an ETH recovery path. [3](#0-2) 

---

### Impact Explanation
Any ETH sent to `tick()` during a period with no pending L2 mint requests is permanently irrecoverable. The contract balance grows with each such call and there is no owner-callable drain function. This constitutes a permanent, irreversible loss of caller funds and constitutes **griefing with damage to users** (Medium).

---

### Likelihood Explanation
`tick()` is `external` with no access control — any address can call it. [4](#0-3) 

Callers must supply ETH to cover StarkGate and StarknetMessaging fees; the function signature gives no indication that ETH is silently discarded when there is nothing to mint. Periods with an empty mint-request queue are routine (between reward epochs), making accidental ETH loss a realistic, recurring scenario.

---

### Recommendation
Add a refund path for the no-op case and/or a `receive`/`fallback` guard:

```solidity
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();

    if (amountToMint > 0) {
        // ... existing logic ...
    } else if (msg.value > 0) {
        // Refund unused ETH to caller
        (bool ok, ) = msg.sender.call{value: msg.value}("");
        require(ok, "ETH_REFUND_FAILED");
    }
}
```

Alternatively, add an owner-restricted `rescueETH()` function and document that `tick()` should only be called with ETH when `requiredMinting()` returns a non-zero amount.

---

### Proof of Concept
1. L2 mint-request queue is empty (`messagingContract().l2ToL1Messages(msgHash) == 0`). [5](#0-4) 
2. Caller invokes `RewardSupplier.tick{value: 0.1 ether}()`.
3. `requiredMinting()` returns `(0, 0)` → `amountToMint == 0`.
4. The `if` block is skipped; function returns without spending or refunding `msg.value`.
5. `address(rewardSupplier).balance` increases by `0.1 ether` permanently.
6. No `receive`, `fallback`, or withdrawal function exists to recover the ETH. [1](#0-0)

### Citations

**File:** L1/starkware/solidity/stake/RewardSupplier.sol (L23-24)
```text
contract RewardSupplier is RewardSupplierStorage, Identity, ProxySupportImpl {
    using Addresses for address;
```

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
