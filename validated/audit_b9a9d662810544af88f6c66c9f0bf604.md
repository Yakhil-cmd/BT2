### Title
KLAY Permanently Locked in Bridge When Recipient Contract Rejects Native Transfer — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

---

### Summary

`handleKLAYTransfer` emits the `HandleValueTransfer` event and updates all nonce-tracking state **before** attempting the native KLAY transfer to `_to`. The final `require(ok, "handleKLAYTransfer: transfer failed")` causes the entire transaction to revert when `_to` is a contract that rejects KLAY. Because the revert unwinds every state write—including `closedValueTransferVotes[_requestNonce]`—operators can retry indefinitely, but every attempt will revert. The user's KLAY deposited on the source chain is permanently locked in the source bridge with no on-chain rescue path.

---

### Finding Description

`requestKLAYTransfer` accepts any `address _to` without verifying it can receive native KLAY:

```solidity
// BridgeTransferKLAY.sol
function requestKLAYTransfer(address _to, uint256 _value, bytes calldata _extraData) external payable {
    uint256 feeLimit = msg.value.sub(_value);
    _requestKLAYTransfer(_to, feeLimit, _extraData);
}
```
<cite repo="hirayap/kaia--018" path="contracts/service_chain/bridge/BridgeTransferKLAY.sol" start="132" end