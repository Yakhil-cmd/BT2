### Title
ETH Permanently Locked in `RewardSupplier.tick()` When No Minting Is Required - (File: `L1/starkware/solidity/stake/RewardSupplier.sol`)

---

### Summary

`RewardSupplier.tick()` is declared `external payable` and accepts ETH intended as L1→L2 message fees. When `amountToMint == 0` (no pending L2 mint requests), the entire `msg.value` is silently swallowed by the contract with no refund and no withdrawal path, permanently locking the caller's ETH.

---

### Finding Description

The `tick()` function checks `requiredMinting()` and only spends `msg.value` inside the `if (amountToMint > 0)` branch:

```solidity
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();

    if (amountToMint > 0) {
        // ...
        uint256 msgFee = msg.value / 2;
        bridge().depositWithMessage{value: msgFee}(...);   // uses half

        msgFee = msg.value - msgFee;
        messagingContract().sendMessageToL2{value: msgFee}(...); // uses other half
    }
    // ← when amountToMint == 0, msg.value is never touched
}
``` [1](#0-0) 

When `amountToMint == 0`, the `if` block is skipped entirely. The contract has no `receive()`, no `fallback()`, and no ETH-withdrawal function anywhere in `RewardSupplier.sol` or `RewardSupplierStorage.sol`. [2](#0-1) 

The `Addresses` library exposes `performEthTransfer` but it is never called from `tick()` or any other path in this contract. [3](#0-2) 

---

### Impact Explanation

Any ETH sent to `tick()` when `amountToMint == 0` is permanently frozen inside the `RewardSupplier` contract. There is no recovery path. This maps directly to **"Temporary/Permanent freezing of funds"** (High) in the allowed impact scope. The loss is bounded per call but is irreversible.

---

### Likelihood Explanation

`tick()` is `external` with no access control — any public caller can invoke it. [4](#0-3) 

`requiredMinting()` is a view function that can be read before calling `tick()`, but:
1. There is no on-chain guard that reverts `tick()` when `msg.value > 0` and `amountToMint == 0`.
2. A race condition exists: the state can change between the off-chain read and the on-chain execution.
3. Automated bots or integrators calling `tick()` on a schedule will routinely hit the `amountToMint == 0` case and lose their ETH. [5](#0-4) 

---

### Recommendation

Add a guard at the top of `tick()` to refund unused ETH, or revert when ETH is sent but not needed:

```solidity
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();

    if (amountToMint == 0) {
        // Refund any ETH sent by mistake
        if (msg.value > 0) {
            (bool ok, ) = msg.sender.call{value: msg.value}("");
            require(ok, "ETH_REFUND_FAILED");
        }
        return;
    }
    // ... rest of logic
}
```

Alternatively, require `msg.value == 0` when `amountToMint == 0`, or add an admin ETH-rescue function.

---

### Proof of Concept

1. Confirm no pending L2 mint requests: call `requiredMinting()` → returns `(0, 0)`.
2. Call `tick{value: 1 ether}()` from any EOA.
3. The `if (amountToMint > 0)` block is skipped; 1 ETH is now held by `RewardSupplier`.
4. No function exists to recover it — the ETH is permanently locked. [6](#0-5)

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

**File:** L1/starkware/solidity/stake/RewardSupplierStorage.sol (L7-87)
```text
abstract contract RewardSupplierStorage {
    // Named storage slot tags.

    // L1 contract addresses.
    // The bridge contract address.
    string internal constant BRIDGE_TAG = "REWARD_SUPPLIER_BRIDGE_CONTRACT_SLOT_TAG";
    // The token contract address.
    string internal constant TOKEN_TAG = "REWARD_SUPPLIER_TOKEN_SLOT_TAG";
    // The mint manager contract address. this contract is responsible for minting the tokens.
    string internal constant MINT_MANAGER_TAG = "REWARD_SUPPLIER_MINT_MANAGER_SLOT_TAG";
    // Starknet messaging contract address.
    string internal constant MESSAGING_CONTRACT_TAG = "REWARD_SUPPLIER_MESSAGING_CONTRACT_SLOT_TAG";

    // L2 contract addresses.
    // The address from which reward requests are received.
    string internal constant L2_MINT_REQUEST_SOURCE_TAG =
        "REWARD_SUPPLIER_L2_MINT_REQUEST_SOURCE_SLOT_TAG";
    // The contract address that receives the minted reward tokens.
    string internal constant L2_MINT_DESTINATION_TAG =
        "REWARD_SUPPLIER_L2_MINT_DESTINATION_SLOT_TAG";
    // The contract address that determines the minting curve.
    string internal constant L2_MINTING_CURVE_TAG = "REWARD_SUPPLIER_L2_MINTING_CURVE_SLOT_TAG";

    // Storage Getters.
    function bridge() internal view returns (IBridge) {
        return IBridge(NamedStorage.getAddressValue(BRIDGE_TAG));
    }

    function token() internal view returns (address) {
        return NamedStorage.getAddressValue(TOKEN_TAG);
    }

    function mintManager() internal view returns (IMintManager) {
        return IMintManager(NamedStorage.getAddressValue(MINT_MANAGER_TAG));
    }

    function messagingContract() internal view returns (IStarknetMessaging) {
        return IStarknetMessaging(NamedStorage.getAddressValue(MESSAGING_CONTRACT_TAG));
    }

    function mintRequestSource() internal view returns (uint256) {
        return NamedStorage.getUintValue(L2_MINT_REQUEST_SOURCE_TAG);
    }

    function mintDestination() internal view returns (uint256) {
        return NamedStorage.getUintValue(L2_MINT_DESTINATION_TAG);
    }

    function mintingCurve() internal view returns (uint256) {
        return NamedStorage.getUintValue(L2_MINTING_CURVE_TAG);
    }

    // Storage Setters.
    function setBridge(address contract_) internal {
        NamedStorage.setAddressValueOnce(BRIDGE_TAG, contract_);
    }

    function setToken(address token_) internal {
        NamedStorage.setAddressValueOnce(TOKEN_TAG, token_);
    }

    function setMintManager(address mintManager_) internal {
        NamedStorage.setAddressValueOnce(MINT_MANAGER_TAG, mintManager_);
    }

    function setMessagingContract(address contract_) internal {
        NamedStorage.setAddressValueOnce(MESSAGING_CONTRACT_TAG, contract_);
    }

    function setMintRequestSource(uint256 _mintRequestSource) internal {
        NamedStorage.setUintValueOnce(L2_MINT_REQUEST_SOURCE_TAG, _mintRequestSource);
    }

    function setMintDestination(uint256 mintDestination_) internal {
        NamedStorage.setUintValueOnce(L2_MINT_DESTINATION_TAG, mintDestination_);
    }

    function setMintingCurve(uint256 mintingCurve_) internal {
        NamedStorage.setUintValueOnce(L2_MINTING_CURVE_TAG, mintingCurve_);
    }
}
```

**File:** L1/starkware/solidity/libraries/Addresses.sol (L22-26)
```text
    function performEthTransfer(address recipient, uint256 amount) internal {
        if (amount == 0) return;
        (bool success, ) = recipient.call{value: amount}(""); // NOLINT: low-level-calls.
        require(success, "ETH_TRANSFER_FAILED");
    }
```
