### Title
ETH Permanently Locked in `RewardSupplier.tick()` When No Minting Is Required - (File: L1/starkware/solidity/stake/RewardSupplier.sol)

---

### Summary

`RewardSupplier.tick()` is declared `external payable` and accepts ETH as message fees for two cross-chain operations. However, the entire fee-spending logic is gated inside `if (amountToMint > 0)`. When no L2 mint requests are pending (`amountToMint == 0`), any ETH sent by the caller is silently absorbed by the contract with no refund and no recovery path, permanently freezing the caller's funds.

---

### Finding Description

In `RewardSupplier.sol`, the `tick()` function is the public entry point for the L1 reward minting pipeline:

```solidity
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();

    if (amountToMint > 0) {
        // ...
        uint256 msgFee = msg.value / 2;
        bridge().depositWithMessage{value: msgFee}(...);

        msgFee = msg.value - msgFee;
        messagingContract().sendMessageToL2{value: msgFee}(...);
    }
    // ← if amountToMint == 0, msg.value is never spent and never returned
}
```

`msg.value` is only forwarded to `bridge().depositWithMessage` and `messagingContract().sendMessageToL2` inside the `if (amountToMint > 0)` branch. If `amountToMint == 0` — which occurs whenever there are no pending L2→L1 mint-request messages — the function returns successfully while silently retaining all ETH sent by the caller.

The contract has no `receive()` fallback, no `withdraw()` function, and no ETH-recovery mechanism anywhere in `RewardSupplier.sol` or its parent `ProxySupportImpl`. Once ETH enters the contract via a no-op `tick()` call, it is permanently inaccessible.

---

### Impact Explanation

Any ETH sent to `tick()` when `amountToMint == 0` is permanently frozen inside the `RewardSupplier` contract. There is no administrative function, no sweep mechanism, and no upgrade path that recovers stranded ETH. This constitutes **permanent freezing of funds** belonging to the caller.

Mapped impact: **High — Permanent freezing of funds** (caller's ETH is irrecoverably locked).

---

### Likelihood Explanation

`tick()` is callable by any account (`anyAccount` per the spec's L1 Mint flow diagram). A caller has two realistic paths to trigger this:

1. **Race condition**: A caller reads `requiredMinting()` off-chain, sees `amountToMint > 0`, prepares a transaction with ETH, but another caller's `tick()` transaction is mined first, consuming all pending messages. The original caller's transaction then executes with `amountToMint == 0` and their ETH is locked.
2. **Mistaken call**: A caller invokes `tick()` with ETH when no mint requests are pending (e.g., polling the function periodically without pre-checking `requiredMinting()`).

Both scenarios are realistic in a live protocol where `tick()` is expected to be called by automated bots or any public actor.

---

### Recommendation

Add an ETH refund when `amountToMint == 0`, or revert if ETH is sent unnecessarily:

```solidity
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();

    if (amountToMint > 0) {
        // ... existing logic ...
    } else {
        require(msg.value == 0, "NO_MINT_REQUIRED_ETH_NOT_ACCEPTED");
    }
}
```

Alternatively, refund excess ETH after the branch:

```solidity
    if (msg.value > 0 && amountToMint == 0) {
        (bool ok, ) = msg.sender.call{value: msg.value}("");
        require(ok, "ETH_REFUND_FAILED");
    }
```

---

### Proof of Concept

1. L2 `RewardSupplier` has no pending mint requests (all prior requests already processed by a previous `tick()` call).
2. `requiredMinting()` returns `(0, 0)`.
3. Attacker (or honest caller) calls `tick{value: 1 ether}()`.
4. `amountToMint == 0` → the `if` block is skipped entirely.
5. Function returns successfully; `address(rewardSupplier).balance` increases by `1 ether`.
6. No function in `RewardSupplier.sol` or `ProxySupportImpl.sol` can recover this ETH.
7. The 1 ETH is permanently frozen. [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** L1/starkware/solidity/upgrade/ProxySupportImpl.sol (L12-36)
```text
abstract contract ProxySupportImpl is ProxySupport, GovernanceStub {
    function validateInitData(bytes calldata data) internal view virtual override {
        require(data.length == 0, "ILLEGAL_DATA_SIZE");
    }

    function initializeContractState(bytes calldata data) internal virtual override {
        require(data.length == 0, "UNEXPECTED_DATA");
    }

    function isInitialized() internal view virtual override returns (bool) {
        return true;
    }

    function processSubContractAddresses(bytes calldata subContractAddresses)
        internal
        virtual
        override
    {
        require(subContractAddresses.length == 0, "UNEXPECTED_DATA");
    }

    function numOfSubContracts() internal pure virtual override returns (uint256) {
        return 0;
    }
}
```
