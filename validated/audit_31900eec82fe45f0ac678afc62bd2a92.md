The vulnerability is real and concrete. Here is the full analysis:

---

### Title
`tick()` silently absorbs `msg.value` when `amountToMint == 0`, permanently locking caller ETH with no recovery path — (`L1/starkware/solidity/stake/RewardSupplier.sol`)

### Summary
`tick()` is declared `external payable` but only forwards `msg.value` to the bridge and messaging contract inside the `if (amountToMint > 0)` branch. When there are no pending L2 mint-request messages, `amountToMint` is zero, the branch is never entered, and any ETH sent by the caller is silently retained by the contract forever. No `receive()`, `fallback()`, or ETH-withdrawal function exists anywhere in the contract or its inheritance chain.

### Finding Description
In `RewardSupplier.sol`, `tick()` is `external payable`: [1](#0-0) 

`msg.value` is consumed only inside the conditional block: [2](#0-1) 

When `requiredMinting()` returns `(0, 0)` — i.e., `messagingContract().l2ToL1Messages(msgHash) == 0` — the entire block is skipped and `msg.value` is never forwarded or refunded. [3](#0-2) 

A grep across all L1 Solidity files confirms there is no `receive()` or `fallback()` function anywhere in the contract or its parents (`RewardSupplierStorage`, `ProxySupportImpl`, `GovernanceStub`, `ProxySupport`). [4](#0-3) 

There is also no admin ETH-sweep or withdrawal function in `RewardSupplierStorage`. [5](#0-4) 

### Impact Explanation
Any ETH sent with `tick()` when no L2 mint-request messages are pending is permanently locked in the contract. There is no recovery path. The invariant that "ETH sent to `tick()` is either consumed by bridge/messaging fees or refunded" is broken. This constitutes **permanent freezing of the caller's funds**.

Matches allowed impact: **High — Temporary/Permanent freezing of funds**.

### Likelihood Explanation
`tick()` is a public, permissionless function intended to be called by any account (`anyAccount` per the spec). Callers are expected to supply ETH to cover L1→L2 messaging fees. The window where `amountToMint == 0` is the normal steady-state between L2 mint-request messages. Any caller who sends ETH during this window — whether by mistake, by front-running a message consumption, or by a race condition — permanently loses that ETH. The precondition is trivially reachable.

### Recommendation
Add an explicit refund at the end of `tick()` when the branch is not taken, or revert if `msg.value > 0` and `amountToMint == 0`:

```solidity
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();

    if (amountToMint > 0) {
        // ... existing logic ...
    } else {
        require(msg.value == 0, "NO_MINT_REQUIRED_NO_FEE_NEEDED");
        // or: if (msg.value > 0) { (bool ok,) = msg.sender.call{value: msg.value}(""); require(ok); }
    }
}
```

### Proof of Concept
```solidity
// Precondition: no pending L2->L1 mint-request messages exist.
// messagingContract().l2ToL1Messages(msgHash) == 0  =>  amountToMint == 0

rewardSupplier.tick{value: 1 ether}();

// Post-condition:
assert(address(rewardSupplier).balance == 1 ether);
// No withdrawal function exists; ETH is permanently locked.
``` [6](#0-5)

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
