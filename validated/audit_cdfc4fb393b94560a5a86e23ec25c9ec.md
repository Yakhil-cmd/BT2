### Title
`tick()` Does Not Refund ETH When No Minting Is Required — Permanent ETH Lock - (File: `L1/starkware/solidity/stake/RewardSupplier.sol`)

---

### Summary

`RewardSupplier.tick()` is declared `external payable` and splits `msg.value` between two outbound calls when minting is needed. However, when `amountToMint == 0` the entire `if` block is skipped and any ETH sent by the caller is silently retained by the contract with no refund and no recovery path. The contract contains no `receive()`, no `fallback()`, and no ETH-withdrawal function, so the locked ETH is irrecoverable.

---

### Finding Description

`tick()` is the sole public entry point on the L1 `RewardSupplier` contract:

```solidity
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();

    if (amountToMint > 0) {
        // ... consume messages, mint, bridge deposit, sendMessageToL2 ...
        uint256 msgFee = msg.value / 2;
        bridge().depositWithMessage{value: msgFee}(...);
        msgFee = msg.value - msgFee;
        messagingContract().sendMessageToL2{value: msgFee}(...);
    }
    // ← no else-branch, no refund, no require(msg.value == 0)
}
``` [1](#0-0) 

When `requiredMinting()` returns `(0, 0)` — i.e., there are no pending L2→L1 mint-request messages — the `if` body is never entered. Any ETH attached to the call is absorbed by the contract balance. There is no `require(msg.value == 0)` guard, no `payable` restriction on the no-op path, and no withdrawal function anywhere in `RewardSupplier`, `RewardSupplierStorage`, or the inherited `ProxySupportImpl`. [2](#0-1) 

The analog to the ArbitrumBridgeFacet bug is direct: both share the root cause of **missing `msg.value` sufficiency/necessity validation** around an ETH-forwarding path. ArbitrumBridgeFacet failed to check `msg.value >= cost`, allowing the contract's balance to be drained outward. Here, `tick()` fails to check `msg.value == 0` on the no-op path, causing the caller's ETH to be locked inward with no escape.

---

### Impact Explanation

Any ETH sent to `tick()` when `amountToMint == 0` is permanently frozen inside the `RewardSupplier` proxy contract. The contract exposes no ETH-rescue function. This matches the allowed impact: **Permanent freezing of funds (High)**.

The funds frozen are the caller's own ETH (L1→L2 message fees). While individual amounts are small per call, the condition is reachable by any public caller and the loss is irrecoverable.

---

### Likelihood Explanation

Three realistic paths lead to this state:

1. **Race condition / front-run**: A caller reads `requiredMinting() > 0` off-chain, constructs a `tick()` call with ETH, but a competing transaction consumes the last mint-request message first. The caller's transaction lands with `amountToMint == 0` and their ETH is locked.

2. **Honest caller mistake**: A caller sends ETH "just in case" without first calling the view `requiredMinting()`.

3. **Griefing**: An attacker calls `tick()` with `msg.value = 0` (valid, no ETH lost by attacker) immediately before a victim's pending `tick()` call, consuming all pending messages and causing the victim's ETH to be locked.

`tick()` is `external` with no access control, so any address can trigger all three scenarios. [3](#0-2) 

---

### Recommendation

Add a guard at the top of `tick()` (or in the no-op branch) to reject non-zero ETH when no minting will occur:

```solidity
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();

    if (amountToMint > 0) {
        // ... existing logic ...
    } else {
        require(msg.value == 0, "NO_MINT_REQUIRED_NO_FEE_NEEDED");
    }
}
```

Alternatively, refund any unused ETH at the end of the function. This mirrors the fix recommended for ArbitrumBridgeFacet: always validate that inbound ETH matches the outbound requirement.

---

### Proof of Concept

1. Deploy `RewardSupplier` with no pending L2→L1 mint-request messages (or consume them all first).
2. Call `tick{value: 1 ether}()` from any EOA.
3. Observe: `amountToMint == 0`, the `if` block is skipped, the call succeeds, and `address(rewardSupplier).balance` increases by `1 ether`.
4. Attempt any recovery: no `withdraw`, no `receive` override, no admin rescue function exists in the contract or its storage base.
5. The 1 ETH is permanently locked. [1](#0-0) [4](#0-3)

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

**File:** L1/starkware/solidity/stake/RewardSupplierStorage.sol (L1-87)
```text
// SPDX-License-Identifier: Apache-2.0.
pragma solidity 0.8.24;

import "starkware/solidity/libraries/NamedStorage8.sol";
import "starkware/solidity/stake/RewardSupplierExternalInterfaces.sol";

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
