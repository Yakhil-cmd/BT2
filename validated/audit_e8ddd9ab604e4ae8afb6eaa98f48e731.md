### Title
Missing `msg.value == 0` Guard When `amountToMint == 0` Permanently Locks Caller ETH - (File: `L1/starkware/solidity/stake/RewardSupplier.sol`)

---

### Summary

The `tick()` function in `RewardSupplier.sol` is declared `payable` but contains no guard requiring `msg.value == 0` when there are no pending L2→L1 mint requests (`amountToMint == 0`). Any ETH sent in that case is silently accepted and permanently locked in the contract, because the entire minting body is skipped and no ETH withdrawal or refund path exists anywhere in the contract or its storage/proxy base.

---

### Finding Description

`tick()` is the sole public entry point for processing L2 mint requests on L1. It first calls `requiredMinting()` to determine how many pending messages exist and how many tokens to mint. If `amountToMint == 0`, the function body is a no-op — the `if (amountToMint > 0)` block is entirely skipped.

```solidity
// L1/starkware/solidity/stake/RewardSupplier.sol
function tick() external payable {                          // line 107
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();

    if (amountToMint > 0) {                                 // line 111
        ...
        uint256 msgFee = msg.value / 2;                     // line 125
        bridge().depositWithMessage{value: msgFee}(...);
        ...
        msgFee = msg.value - msgFee;                        // line 135
        messagingContract().sendMessageToL2{value: msgFee}(...);
    }
    // ← if amountToMint == 0, msg.value is never used and never refunded
}
```

`msg.value` is only consumed inside the `if` block. When the condition is false, the ETH is accepted by the `payable` function but never forwarded, never refunded, and never recoverable. `RewardSupplier.sol` has no `receive()`, no `fallback()`, and no ETH-sweep function. `RewardSupplierStorage.sol` only manages named storage slots for ERC-20/address state. The `ProxySupportImpl` base is an upgrade proxy with no ETH recovery. There is no path to retrieve locked ETH.

---

### Impact Explanation

**High — Permanent freezing of funds.**

Any ETH sent to `tick()` when `amountToMint == 0` is irretrievably locked in the `RewardSupplier` contract. Because `tick()` is permissionless and the condition is determined at execution time by on-chain state (number of pending L2→L1 messages), a caller cannot atomically guarantee that `amountToMint > 0` at the moment their transaction executes. The ETH is not transferred to an attacker but is permanently frozen with no protocol-level recovery.

---

### Likelihood Explanation

**Medium.**

The condition `amountToMint == 0` is the normal steady-state between reward epochs. Any caller who sends ETH to `tick()` without first verifying `requiredMinting()` in the same atomic context will lose their ETH. More critically, a front-running attack is straightforward:

1. Victim observes pending mint requests via `requiredMinting()` and submits `tick()` with ETH for message fees.
2. Attacker front-runs with their own `tick()` call (with sufficient ETH) to consume all pending messages, driving `amountToMint` to 0.
3. Victim's transaction executes with `amountToMint == 0`; their ETH is permanently locked.

This is a realistic MEV/front-running scenario on Ethereum mainnet.

---

### Recommendation

Add a guard at the top of `tick()` that rejects ETH when there is nothing to process, and optionally also when `msg.value` is zero but minting is required (to prevent silent no-fee message sends):

```solidity
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();

    if (amountToMint == 0) {
        require(msg.value == 0, "ETH sent with no-op tick");
        return;
    }
    require(msg.value > 0, "msg.value required for message fees");
    ...
}
```

This mirrors the fix pattern from the referenced report: validate that the sent value matches the expected operational need before proceeding.

---

### Proof of Concept

```
State: requiredMinting() returns (0, 0)  // no pending L2→L1 messages

1. Victim calls tick{value: 0.01 ether}()
   → amountToMint = 0
   → if (amountToMint > 0) block is skipped
   → function returns normally
   → 0.01 ETH is now held by RewardSupplier with no recovery path

OR (front-run variant):

1. Victim prepares tick{value: 0.01 ether}() after seeing 1 pending message
2. Attacker front-runs: tick{value: 0.01 ether}() — consumes the pending message
3. Victim's tick{value: 0.01 ether}() executes: amountToMint = 0
   → 0.01 ETH permanently locked
``` [1](#0-0) [2](#0-1) [3](#0-2)

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
