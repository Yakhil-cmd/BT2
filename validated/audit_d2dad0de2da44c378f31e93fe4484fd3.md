### Title
ETH Sent to `tick()` Is Permanently Locked When No Minting Is Required — (`File: L1/starkware/solidity/stake/RewardSupplier.sol`)

---

### Summary

`RewardSupplier.tick()` is `external payable`, allowing any public caller to send ETH as message fees. When no L2→L1 mint requests are pending (`amountToMint == 0`), the entire `msg.value` is silently absorbed by the contract with no refund. Even when minting does occur, any ETH sent in excess of the actual fees consumed by the bridge and messaging contract is permanently locked. There is no `receive()`, `fallback()`, or `withdraw()` function anywhere in the contract to recover this ETH.

---

### Finding Description

`tick()` is declared `external payable` and is callable by any account: [1](#0-0) 

The entire fee-spending logic is gated inside `if (amountToMint > 0)`: [2](#0-1) 

When `amountToMint == 0` — the common case when the reward supplier's L2 balance is already sufficient — the `if` block is skipped entirely. `msg.value` is never forwarded and never returned. It remains locked in the contract forever.

When `amountToMint > 0`, the fee is split as a fixed 50/50 halving: [3](#0-2) 

The actual fees consumed by `bridge().depositWithMessage` and `messagingContract().sendMessageToL2` depend on current L1 gas prices and are not guaranteed to equal exactly `msg.value / 2` each. Any ETH not consumed by those calls is not refunded to the caller — it accumulates in the contract.

The contract has no ETH recovery path: no `receive()`, no `fallback()`, no `withdraw()`, and no admin sweep function anywhere in `RewardSupplier.sol` or its storage base `RewardSupplierStorage.sol`. [4](#0-3) 

---

### Impact Explanation

Any caller who invokes `tick()` with `msg.value > 0` when no minting is required loses their entire ETH payment permanently. Because `requiredMinting()` is a public view function, a caller can check it off-chain before calling, but the contract itself provides no on-chain protection. ETH sent in the no-op path is irrecoverable. This constitutes **permanent freezing of caller funds** (ETH locked in the contract with no recovery mechanism).

Additionally, even in the active path, the hardcoded 50/50 fee split means any ETH above the actual bridge and messaging fees is also permanently locked.

---

### Likelihood Explanation

`tick()` is designed to be called by any account (`anyAccount` per the spec diagram): [5](#0-4) 

Minting is only triggered when the L2 reward supplier's balance falls below a threshold. Between minting events — which is the majority of the time — every call to `tick()` with nonzero `msg.value` results in a permanent ETH loss. Automated keepers or bots that call `tick()` periodically without first checking `requiredMinting()` will consistently lose ETH. Even callers who do check off-chain face a race condition where another caller processes the pending messages between their check and their transaction landing.

---

### Recommendation

1. Add an early return with a full refund when `amountToMint == 0`:
   ```solidity
   if (amountToMint == 0) {
       if (msg.value > 0) {
           payable(msg.sender).transfer(msg.value);
       }
       return;
   }
   ```
2. After spending fees in the active path, refund any remaining ETH to `msg.sender`:
   ```solidity
   uint256 remaining = address(this).balance;
   if (remaining > 0) payable(msg.sender).transfer(remaining);
   ```
3. Alternatively, require the caller to pass exact fee amounts as parameters and validate `msg.value` matches.

---

### Proof of Concept

1. Observe that `requiredMinting()` returns `(0, 0)` when no L2→L1 mint messages are pending (the normal steady-state).
2. Any account calls `tick{value: 1 ether}()`.
3. `amountToMint == 0`, so the `if` block is skipped.
4. The function returns. The 1 ETH is now held by `RewardSupplier` with no mechanism to retrieve it.
5. Confirm: `RewardSupplier.sol` has no `receive()`, no `fallback()`, no `withdraw()`, and no admin ETH sweep — the ETH is permanently locked. [6](#0-5)

### Citations

**File:** L1/starkware/solidity/stake/RewardSupplier.sol (L23-29)
```text
contract RewardSupplier is RewardSupplierStorage, Identity, ProxySupportImpl {
    using Addresses for address;
    event ConsumedL2MintRequests(uint256 messagesConsumed, uint256 amountMinted);

    function identify() external pure override returns (string memory) {
        return "StarkWare_RewardSupplier_2024_1";
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

**File:** docs/spec.md (L555-560)
```markdown
  anyAccount ->>+ RewardSupplier: tick(tokensPerMintAmount, maxMessagesToProcess)
  RewardSupplier ->>+ MintingManager: mintRequest(totalAmountToMint)
  MintingManager ->>- STRK ERC20: mint
  RewardSupplier ->>+ StarkGate bridge: depositWithMessage
  deactivate RewardSupplier
```
```
