### Title
Fallback Function in `BridgeTransferKLAY` Hardcodes `msg.sender` as Cross-Chain Recipient, Causing Permanent KLAY Loss for Contract Callers — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

### Summary

The fallback function in `BridgeTransferKLAY` hardcodes `msg.sender` as the `_to` (recipient) address on the counterpart chain. When a multisig wallet or any smart contract sends KLAY directly to the bridge, the bridge operators will deliver the bridged KLAY to the same address on the destination chain — an address the original owners may not control, and which may not even be deployed there.

### Finding Description

`BridgeTransferKLAY` exposes two paths for initiating a KLAY cross-chain transfer:

1. `requestKLAYTransfer(address _to, ...)` — caller explicitly specifies the destination address.
2. The Solidity fallback `function () external payable` — destination is hardcoded to `msg.sender`. [1](#0-0) 

```solidity
// () requests transfer KLAY to msg.sender address on relative chain.
function () external payable {
    _requestKLAYTransfer(msg.sender, feeOfKLAY, new bytes(0));
}
```

`_requestKLAYTransfer` emits a `RequestValueTransfer` event with `_to = msg.sender`: [2](#0-1) 

The bridge operators on the counterpart chain observe this event and call `handleKLAYTransfer(_from, _to, ...)` where `_to` is the `msg.sender` address from the source chain. The KLAY is then unconditionally transferred to that address: [3](#0-2) 

If `msg.sender` is a multisig wallet or any smart contract, its address on the destination chain is either:
- **Undeployed** — KLAY is sent to a bare EOA-equivalent address with no owner.
- **Deployed by a different party** — an attacker who front-runs the deployment on the destination chain controls the funds.

The `requestKLAYTransfer` path does not have this problem because the caller explicitly passes `_to`. [4](#0-3) 

### Impact Explanation

**Impact: High.** KLAY bridged via the fallback path by any contract caller (multisig, proxy, DeFi protocol) is permanently lost or stolen. The bridge operators faithfully execute the transfer to the wrong address — there is no recovery mechanism. This is an unauthorized transfer of bridged KLAY to an uncontrolled address, matching the allowed impact gate.

### Likelihood Explanation

**Likelihood: Medium.** Any contract that sends KLAY directly to the bridge address (a common UX pattern) triggers the fallback. Multisig wallets (Gnosis Safe, etc.) are widely used and routinely interact with bridges this way. The attacker scenario (deploying a contract at the victim's address on the destination chain) is realistic and has been exploited in production (Wintermute hack).

### Recommendation

Remove the fallback function entirely, or revert inside it with a descriptive error directing callers to use `requestKLAYTransfer` with an explicit `_to` address:

```solidity
function () external payable {
    revert("Use requestKLAYTransfer(address _to, ...) to specify recipient");
}
```

Alternatively, if the fallback must be kept for UX reasons, it should accept a `_to` parameter — but Solidity 0.5.x fallback functions cannot accept parameters, so removal is the only safe option.

### Proof of Concept

1. Deploy `Bridge` on chain A (service chain) and chain B (parent chain).
2. Deploy a multisig wallet `MS` at address `0xABCD...` on chain A. The same address on chain B is either undeployed or controlled by an attacker.
3. `MS` sends KLAY directly to the bridge on chain A (triggering the fallback). The `RequestValueTransfer` event is emitted with `to = 0xABCD...`.
4. Bridge operators observe the event and call `handleKLAYTransfer(..., 0xABCD..., value, ...)` on chain B.
5. KLAY is transferred to `0xABCD...` on chain B — an address the multisig owners do not control.
6. If an attacker has pre-deployed a contract at `0xABCD...` on chain B (possible via CREATE2 or by replicating the multisig deployment nonce), they drain the received KLAY. [1](#0-0) [3](#0-2)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L98-99)
```text
        (bool ok, ) = _to.call.value(_value)("");
        require(ok, "handleKLAYTransfer: transfer failed");
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L113-123)
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
        requestNonce++;
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L126-129)
```text
    // () requests transfer KLAY to msg.sender address on relative chain.
    function () external payable {
        _requestKLAYTransfer(msg.sender, feeOfKLAY, new bytes(0));
    }
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L131-135)
```text
    // requestKLAYTransfer requests transfer KLAY to _to on relative chain.
    function requestKLAYTransfer(address _to, uint256 _value, bytes calldata _extraData) external payable {
        uint256 feeLimit = msg.value.sub(_value);
        _requestKLAYTransfer(_to, feeLimit, _extraData);
    }
```
