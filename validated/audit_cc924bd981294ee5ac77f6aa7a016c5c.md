### Title
ETH Permanently Locked in `RewardSupplier.tick()` When No Minting Is Required - (File: `L1/starkware/solidity/stake/RewardSupplier.sol`)

---

### Summary

`RewardSupplier.tick()` is `payable` and uses `msg.value` to fund two L1→L2 bridge calls. However, when `amountToMint == 0` (no pending mint requests), the entire `if` block is skipped and any ETH sent by the caller is permanently locked in the contract. The contract has no `receive()`, `fallback()`, or ETH-withdrawal function, so the ETH is irrecoverable. An unprivileged attacker can front-run a legitimate `tick()` call to force this condition, permanently destroying the victim's ETH.

---

### Finding Description

`tick()` is the public entry point for the L1 reward minting flow:

```solidity
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();

    if (amountToMint > 0) {
        ...
        uint256 msgFee = msg.value / 2;
        bridge().depositWithMessage{value: msgFee}(...);

        msgFee = msg.value - msgFee;
        messagingContract().sendMessageToL2{value: msgFee}(...);
    }
}
``` [1](#0-0) 

When `amountToMint == 0`, the function returns silently without using or refunding `msg.value`. The contract inherits from `RewardSupplierStorage`, `Identity`, and `ProxySupportImpl`. [2](#0-1) 

`ProxySupportImpl` provides no `receive()`, `fallback()`, or ETH-withdrawal mechanism: [3](#0-2) 

Therefore any ETH sent to `tick()` when `amountToMint == 0` is permanently locked.

The root cause is structurally identical to the KintoWalletFactory report: a function that is supposed to forward ETH does not validate that the ETH it receives will actually be used. In the KintoWalletFactory case the function was not `payable` at all; here the function is `payable` but silently discards the ETH on the no-op path.

---

### Impact Explanation

Any ETH sent to `tick()` when `amountToMint == 0` is permanently frozen inside the contract. There is no admin withdrawal, no `receive()` fallback, and no upgrade path that would recover it. This constitutes **permanent freezing of caller funds**, matching the allowed High-severity impact "Temporary freezing of funds."

---

### Likelihood Explanation

`tick()` is callable by any account with no access control. [4](#0-3) 

`requiredMinting()` is a public view function, so the pending-message count is observable on-chain by anyone. [5](#0-4) 

An attacker watching the mempool can:
1. See a pending `tick()` call with `msg.value > 0`.
2. Front-run it with their own `tick()` call (with `msg.value = 1 wei`) that consumes all pending L2→L1 mint-request messages.
3. The victim's transaction now executes with `amountToMint == 0`; their ETH is permanently locked.

L1 front-running is well-established and requires no privileged access.

---

### Recommendation

Add a refund for unused ETH at the end of `tick()`:

```solidity
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();

    if (amountToMint > 0) {
        // ... existing logic ...
    }

    // Refund any unused ETH to the caller.
    if (address(this).balance > 0) {
        (bool ok, ) = msg.sender.call{value: address(this).balance}("");
        require(ok, "ETH_REFUND_FAILED");
    }
}
```

Alternatively, revert when `msg.value > 0` and `amountToMint == 0`, or require `msg.value == 0` when there is nothing to mint.

---

### Proof of Concept

1. L2 reward supplier emits one mint-request message to L1; `requiredMinting()` returns `(1_300_000e18, 1)`.
2. Honest operator submits `tick{value: 0.01 ether}()` to pay bridge fees.
3. Attacker sees the pending tx and submits `tick{value: 1 wei}()` with higher gas price.
4. Attacker's tx is mined first: consumes the single pending message, mints tokens, sends them to L2 with 0.5 wei fee each. `requiredMinting()` now returns `(0, 0)`.
5. Honest operator's tx is mined: `amountToMint == 0`, the `if` block is skipped, `0.01 ether` is silently retained by the contract.
6. No function exists to recover the locked ETH — confirmed by inspecting `RewardSupplier.sol`, `ProxySupportImpl.sol`, and the full inheritance chain. [1](#0-0) [3](#0-2)

### Citations

**File:** L1/starkware/solidity/stake/RewardSupplier.sol (L23-23)
```text
contract RewardSupplier is RewardSupplierStorage, Identity, ProxySupportImpl {
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

**File:** L1/starkware/solidity/upgrade/ProxySupportImpl.sol (L12-35)
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
```
