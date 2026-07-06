### Title
ETH Sent to `tick()` When No Minting Is Required Is Permanently Locked in the Contract - (File: `L1/starkware/solidity/stake/RewardSupplier.sol`)

---

### Summary

`RewardSupplier.tick()` is declared `external payable` but contains no refund path and no guard requiring `msg.value == 0` when there is nothing to mint. Any ETH forwarded by a caller in a no-op invocation (i.e., when `amountToMint == 0`) is silently absorbed by the contract with no mechanism for recovery.

---

### Finding Description

`tick()` is the sole externally callable function in `RewardSupplier.sol` and is marked `payable` because it must forward ETH as L1→L2 message fees to the StarkGate bridge and the Starknet messaging contract. [1](#0-0) 

The function's control flow is:

```
tick()
 ├─ requiredMinting() → (amountToMint, numMsgsToConsume)
 ├─ if (amountToMint > 0)
 │    ├─ consume L2→L1 messages
 │    ├─ mintRequest(...)
 │    ├─ bridge().depositWithMessage{value: msg.value / 2}(...)
 │    └─ messagingContract().sendMessageToL2{value: msg.value - msg.value/2}(...)
 └─ (implicit) return   ← msg.value is NEVER refunded or used when amountToMint == 0
```

When `amountToMint == 0` the entire `if` block is skipped. There is no `else` branch, no `require(msg.value == 0)` guard, and no `payable(msg.sender).transfer(msg.value)` refund. The contract has no `receive()`, `fallback()`, or ETH-withdrawal function anywhere in its inheritance chain (`RewardSupplierStorage`, `Identity`, `ProxySupportImpl`). [1](#0-0) [2](#0-1) 

Result: any ETH sent in a no-op `tick()` call is permanently locked.

---

### Impact Explanation

ETH sent by the caller is permanently frozen inside `RewardSupplier`. There is no admin withdrawal, no sweep function, and no upgrade path that would recover it. This matches the **High** impact category: *Permanent freezing of funds*.

The locked asset is the caller's own ETH (the L1→L2 message fee they intended to pay). Because the contract is a proxy with no ETH-recovery surface, the funds cannot be retrieved by any party.

---

### Likelihood Explanation

`tick()` carries no access control — it is `external` with no `onlyOwner` or role check. [3](#0-2) 

Any unprivileged address can call it. A caller who:
1. Queries `requiredMinting()` off-chain and finds pending messages,
2. Prepares a transaction with ETH attached,
3. Has their transaction land *after* another caller already processed those messages in the same block,

will find `amountToMint == 0` at execution time and lose all attached ETH. This is a realistic race condition on a public mempool. Additionally, a caller who simply miscalculates or sends ETH "just in case" when no minting is pending suffers the same loss.

---

### Recommendation

Add one of the following mitigations:

**Option A — Revert if ETH is sent unnecessarily:**
```solidity
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();
    if (amountToMint == 0) {
        require(msg.value == 0, "NO_MINT_REQUIRED_NO_FEE_NEEDED");
        return;
    }
    // ... existing logic
}
```

**Option B — Refund excess ETH after forwarding fees:**
After the two `{value: ...}` calls, compute any remainder and return it:
```solidity
// After both forwarding calls, refund dust
uint256 remainder = address(this).balance;
if (remainder > 0) {
    (bool ok, ) = msg.sender.call{value: remainder}("");
    require(ok, "REFUND_FAILED");
}
```

**Option C — Make `tick()` non-payable when no ETH path exists for the no-mint case**, and split into two functions.

---

### Proof of Concept

1. Deploy `RewardSupplier` (or interact with the live proxy).
2. Ensure no pending L2→L1 mint-request messages exist, so `requiredMinting()` returns `(0, 0)`.
3. Call `tick{value: 1 ether}()` from any EOA.
4. Observe: the call succeeds (no revert), `amountToMint == 0` so the `if` block is skipped entirely, and `address(rewardSupplier).balance` increases by `1 ether`.
5. Attempt any recovery — there is no function to withdraw the ETH. The 1 ETH is permanently locked. [1](#0-0)

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
