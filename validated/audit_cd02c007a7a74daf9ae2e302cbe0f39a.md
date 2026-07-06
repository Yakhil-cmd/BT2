### Title
ETH Permanently Stuck in `RewardSupplier.sol` When `tick()` Called With No Pending Mint Requests - (File: `L1/starkware/solidity/stake/RewardSupplier.sol`)

---

### Summary
`RewardSupplier.sol::tick()` is a `payable` function that accepts ETH as message fees for L1→L2 bridge calls. When `requiredMinting()` returns zero (no pending mint requests), the entire `msg.value` is silently trapped in the contract with no refund and no withdrawal mechanism. This is a direct structural analog to the reported `FeePayer.sol` bug: in both cases, a conditional code path causes ETH to bypass the spending logic and become permanently frozen.

---

### Finding Description

`tick()` is declared `external payable` with no access control:

```solidity
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();

    if (amountToMint > 0) {
        // ... ETH is spent here via bridge().depositWithMessage{value: msgFee}
        //     and messagingContract().sendMessageToL2{value: msgFee}
    }
    // No else branch, no refund, no require(msg.value == 0)
}
``` [1](#0-0) 

When `amountToMint == 0`, the entire `if` block is skipped. Any ETH sent with the call is never forwarded to the bridge or messaging contract, and is never refunded. The contract has no `receive()`, `fallback()`, or ETH-withdrawal function anywhere in `RewardSupplier.sol` or its inherited contracts (`RewardSupplierStorage`, `Identity`, `ProxySupportImpl`). [2](#0-1) 

A secondary freeze path exists even when `amountToMint > 0`: the fee is split as `msgFee = msg.value / 2` (integer division). If `msg.value` is odd, 1 wei is permanently lost. More significantly, if the caller over-estimates the required fee and sends excess ETH, the surplus is also permanently stuck. [3](#0-2) 

---

### Impact Explanation

ETH sent to `tick()` when no minting is pending is permanently frozen in the `RewardSupplier` contract. There is no recovery path. This constitutes **permanent freezing of funds** (ETH) for any caller who sends ETH to `tick()` under the wrong conditions. The impact is **High**: permanent freezing of funds.

---

### Likelihood Explanation

`tick()` is callable by any account with no access restriction. The condition `amountToMint == 0` is the normal state of the contract between minting cycles — the L2 reward supplier only sends mint requests periodically. A caller who monitors the contract and calls `tick()` with ETH when no requests are pending (e.g., a bot that does not first call `requiredMinting()` to check) will permanently lose their ETH. This is a realistic operational scenario.

---

### Recommendation

Add a guard at the top of `tick()` to reject ETH when there is nothing to mint, mirroring the fix described in the original report ("validate that `msg.value` equals 0 so that no ETH gets stuck"):

```solidity
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();
    if (amountToMint == 0) {
        require(msg.value == 0, "NO_MINT_NEEDED_NO_ETH_ACCEPTED");
        return;
    }
    // ... rest of logic
}
```

Alternatively, refund any unspent ETH at the end of the function.

---

### Proof of Concept

1. Observe that `requiredMinting()` returns `(0, 0)` when there are no pending L2→L1 mint-request messages (normal state between epochs).
2. Any EOA calls `tick{value: 1 ether}()`.
3. `amountToMint == 0`, so the `if` block is skipped entirely.
4. The 1 ETH is now held by `RewardSupplier` with no mechanism to retrieve it.
5. Confirm: `RewardSupplier.sol` has no `withdraw`, `receive`, or `fallback` function. [1](#0-0)

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
