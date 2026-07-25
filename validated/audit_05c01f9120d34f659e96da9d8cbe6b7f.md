### Title
`BridgeTransferKLAY` Fallback Function Hardcodes `msg.sender` as Counterpart-Chain Recipient, Permanently Losing KLAY When Called by a Contract — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

---

### Summary

The `BridgeTransferKLAY` fallback function unconditionally uses `msg.sender` as the KLAY recipient (`_to`) on the counterpart chain. When a contract (e.g., a multisig wallet or DeFi protocol) calls this fallback, the same address is used as the destination on the other chain. Because the contract may not exist there — or may exist as a different contract without a `receive()` function — the bridged KLAY is either sent to an address the caller cannot control (permanent loss) or causes every bridge-operator `handleKLAYTransfer` call to revert (bridge stuck at that nonce).

---

### Finding Description

`BridgeTransferKLAY.sol` exposes two### BridgeTransferKLAY Fallback Function Uses `msg.sender` as Destination Address, Causing KLAY Loss When Called by Contracts - (File: `contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

### Summary
The fallback function in `BridgeTransferKLAY` automatically sets the destination address (`_to`) to the caller's address (`msg.sender`). When this function is called by a smart contract (e.g., a multisig wallet or a DeFi protocol) on the source chain, the bridge will attempt to deliver the KLAY to the same address on the counterpart chain. If the contract does not exist at that address on the counterpart chain, the assets are sent to an unmanaged account, effectively blackholing them.

### Finding Description
The `BridgeTransferKLAY` contract provides a fallback function to simplify KLAY transfers to the counterpart chain. However, it hardcodes the recipient address to the caller's address [1](#0-0) :

```solidity
// () requests transfer KLAY to msg.sender address on relative chain.
function () external payable {
    _requestKLAYTransfer(msg.sender, feeOfKLAY, new bytes(0));
}
```

This implementation assumes that the caller controls the same address on both the source and destination chains. While this is true for Externally Owned Accounts (EOAs), it is not necessarily true for smart contracts. A contract address on one chain (e.g., a ServiceChain) may be unallocated or belong to a different entity on the counterpart chain (e.g., the Kaia Mainnet). 

When the bridge operators process the request on the destination chain, they call `handleKLAYTransfer` [2](#0-1) . This function attempts to send the KLAY to the `_to` address (which was set to the source contract's address) [3](#0-2) :

```solidity
(bool ok, ) = _to.call.value(_value)("");
require(ok, "handleKLAYTransfer: transfer failed");
```

If the address exists but is a contract that cannot receive KLAY (lacks `receive` or `fallback` functions), the transaction reverts, causing the bridge to get stuck for that specific nonce. If the address has no code (the contract was not deployed there), the transfer succeeds in the EVM, but the funds are inaccessible to the original caller, as they do not possess a private key for that address.

### Impact Explanation
Assets (KAIA/KLAY) are permanently lost or locked. Contracts that interact with the bridge via the fallback function will have their funds sent to an address they likely do not control on the other chain. This is a repository-native impact affecting bridged assets and system-managed funds.

### Likelihood Explanation
Smart contract wallets and multisigs are standard in the ecosystem. Since the bridge documentation does not explicitly warn against contract callers using the fallback function, and the fallback is a natural entry point for sending value, the likelihood of this occurring is significant.

### Recommendation
1. **Remove the fallback function**: Force users to use `requestKLAYTransfer`, which requires an explicit `_to` address [4](#0-3) .
2. **Add a `refundAddr` parameter**: Update the API to allow specifying a separate address for refunds and destination delivery, similar to the mitigation suggested in the external report.
3. **Contract Check**: Prevent the fallback function from being executed if `msg.sender` is a contract (though this may interfere with some valid use cases).

### Proof of Concept
1. A multisig wallet (contract) is deployed on a Kaia ServiceChain at address `0x123...`.
2. The multisig sends 100 KLAY to the `BridgeTransferKLAY` contract on the ServiceChain by calling the fallback function.
3. The bridge emits a `RequestValueTransfer` event with `from = 0x123...` and `to = 0x123...` [5](#0-4) .
4. Bridge operators pick up the event and call `handleKLAYTransfer` on the Kaia Mainnet with `_to = 0x123...`.
5. On the Kaia Mainnet, address `0x123...` is empty (no contract deployed). The 100 KLAY is successfully transferred to the empty address.
6. The multisig owners cannot access the 100 KLAY on the Mainnet because they do not have the private key for the `0x123...` EOA.

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L62-74)
```text
    function handleKLAYTransfer(
        bytes32 _requestTxHash,
        address _from,
        address payable _to,
        uint256 _value,
        uint64 _requestedNonce,
        uint64 _requestedBlockNumber,
        bytes memory _extraData
    )
        public
        onlyOperators
        nonReentrant
    {
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L98-99)
```text
        (bool ok, ) = _to.call.value(_value)("");
        require(ok, "handleKLAYTransfer: transfer failed");
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L113-122)
```text
        emit RequestValueTransfer(
            TokenType.KLAY,
            msg.sender,
            _to,
            address(0),
            msg.value.sub(_feeLimit),
            requestNonce,
            fee,
            _extraData
        );
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L127-129)
```text
    function () external payable {
        _requestKLAYTransfer(msg.sender, feeOfKLAY, new bytes(0));
    }
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L132-135)
```text
    function requestKLAYTransfer(address _to, uint256 _value, bytes calldata _extraData) external payable {
        uint256 feeLimit = msg.value.sub(_value);
        _requestKLAYTransfer(_to, feeLimit, _extraData);
    }
```
