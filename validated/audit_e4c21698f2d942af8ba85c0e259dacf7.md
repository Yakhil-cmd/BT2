### Title
ETH Permanently Locked in `RewardSupplier` When `tick()` Called With `msg.value > 0` and No Pending Mint Requests — (File: `L1/starkware/solidity/stake/RewardSupplier.sol`)

---

### Summary
`RewardSupplier.tick()` is declared `payable` but only forwards `msg.value` to downstream calls inside the `if (amountToMint > 0)` branch. When `amountToMint == 0`, any ETH sent by the caller is permanently trapped in the contract. No `receive()`, `fallback()`, or `withdraw()` function exists anywhere in the L1 contract suite, making recovery impossible.

---

### Finding Description
`tick()` is the public entry point for the L1 reward-minting flow. It is marked `payable` because it must forward ETH as fees to two downstream payable calls:

1. `bridge().depositWithMessage{value: msgFee}(...)` — StarkGate bridge fee
2. `messagingContract().sendMessageToL2{value: msgFee}(...)` — Starknet L1→L2 message fee

Both calls are gated inside `if (amountToMint > 0)`:

```solidity
// L1/starkware/solidity/stake/RewardSupplier.sol  lines 107-143
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();

    if (amountToMint > 0) {
        ...
        uint256 msgFee = msg.value / 2;
        bridge().depositWithMessage{value: msgFee}(...);   // line 126

        msgFee = msg.value - msgFee;
        messagingContract().sendMessageToL2{value: msgFee}(...);  // line 137
    }
    // ← no else branch; ETH is silently retained when amountToMint == 0
}
```

When `amountToMint == 0` the function returns without touching `msg.value`. A grep across all L1 Solidity files confirms there is no `receive()`, `fallback()`, or `withdraw()` function anywhere in the contract hierarchy (`RewardSupplier`, `RewardSupplierStorage`, `Identity`, `ProxySupportImpl`), so the ETH has no exit path.

The `IStarknetMessaging` interface documents that `sendMessageToL2` is payable and "the paid amount is the message fee," directly mirroring the Wormhole `publishMessage` fee requirement. [1](#0-0) [2](#0-1) 

---

### Impact Explanation
Any ETH sent to `tick()` when `amountToMint == 0` is permanently frozen inside `RewardSupplier` with no recovery path. This constitutes **permanent freezing of funds** for the caller. The loss is bounded per call by however much ETH the caller attaches, but it is irrecoverable.

Matches allowed impact: **High — Permanent freezing of funds / Temporary freezing of funds**. [3](#0-2) 

---

### Likelihood Explanation
`tick()` is an unrestricted `external` function callable by any address. Two realistic paths trigger the loss:

1. **Race condition (most likely):** A keeper bot reads `requiredMinting()` off-chain, sees pending requests, and submits `tick{value: X}()`. A competing transaction (another keeper or a griefing attacker) executes first and consumes all pending L2→L1 mint-request messages. When the original `tick()` lands, `amountToMint == 0` and the ETH is locked.

2. **Honest mistake:** A caller sends ETH to `tick()` when there are simply no pending requests (e.g., during a quiet period). The ETH is silently absorbed. [4](#0-3) 

---

### Recommendation
Refund any unspent ETH at the end of `tick()`, or revert if `msg.value > 0` and `amountToMint == 0`:

```solidity
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();

    if (amountToMint > 0) {
        // ... existing logic ...
    } else {
        require(msg.value == 0, "NO_MINT_REQUIRED: refund ETH");
        // or: if (msg.value > 0) { payable(msg.sender).transfer(msg.value); }
    }
}
```

Alternatively, restructure so the fee-forwarding calls are not gated and always consume exactly the required fee, reverting if insufficient ETH is provided. [1](#0-0) 

---

### Proof of Concept
1. Deploy `RewardSupplier` with no pending L2→L1 mint-request messages (or consume them all first).
2. Call `tick{value: 1 ether}()` from any EOA.
3. `requiredMinting()` returns `(0, 0)` → `amountToMint == 0`.
4. The `if` block is skipped; `msg.value = 1 ether` is never forwarded.
5. Confirm: `address(rewardSupplier).balance == 1 ether`.
6. Attempt any recovery — no `withdraw`, `receive`, or `fallback` exists. ETH is permanently locked. [5](#0-4) [6](#0-5)

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

**File:** L1/starkware/starknet/solidity/IStarknetMessaging.sol (L44-53)
```text
      Sends a message to an L2 contract.
      This function is payable, the payed amount is the message fee.

      Returns the hash of the message and the nonce of the message.
    */
    function sendMessageToL2(
        uint256 toAddress,
        uint256 selector,
        uint256[] calldata payload
    ) external payable returns (bytes32, uint256);
```
