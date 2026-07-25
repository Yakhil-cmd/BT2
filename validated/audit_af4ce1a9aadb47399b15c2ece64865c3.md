### Title
Missing Zero-Address Validation on `_to` in Bridge Transfer Functions Causes Permanent Loss of Bridged KAIA — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`, `BridgeTransferERC20.sol`, `BridgeTransferERC721.sol`)

### Summary

The Kaia service-chain bridge's public transfer-request entry points (`requestKLAYTransfer`, `requestERC20Transfer`, `requestERC721Transfer`, `onERC20Received`, `onERC721Received`) accept a caller-supplied `_to` address without validating that it is non-zero. When `_to = address(0)` is supplied, the source-chain side of the bridge executes normally (locking or burning assets and incrementing `requestNonce`), while the destination-chain `handleKLAYTransfer` call succeeds and irrecoverably sends KAIA to the zero address. For ERC-20 in mint-burn mode the source-side burn is permanent and the destination-side `mint(address(0), …)` always reverts, leaving the bridge nonce unresolvable.

### Finding Description

`requestKLAYTransfer` and its internal helper `_requestKLAYTransfer` accept an arbitrary `address _to` with no zero-address guard:

```solidity
// BridgeTransferKLAY.sol – lines 103-124
function _requestKLAYTransfer(address _to, uint256 _feeLimit, bytes memory _extraData)
    internal unlockedKLAY nonReentrant
{
    require(isRunning, "stopped bridge");
    require(msg.value > _feeLimit, "insufficient amount");
    // ← no require(_to != address(0))
    uint256 fee = _payKLAYFeeAndRefundChange(_feeLimit);
    emit RequestValueTransfer(TokenType.KLAY, msg.sender, _to, address(0),
        msg.value.sub(_feeLimit), requestNonce, fee, _extraData);
    requestNonce++;
}
``` [1](#0-0) 

The bridge operator on the counterpart chain faithfully relays the emitted event and calls `handleKLAYTransfer` with the zero address. That function also has no guard and executes a low-level call that succeeds against `address(0)`:

```solidity
// BridgeTransferKLAY.sol – line 98
(bool ok, ) = _to.call.value(_value)("");
require(ok, "handleKLAYTransfer: transfer failed");
``` [2](#0-1) 

In the EVM, a `.call{value: v}("")` to `address(0)` returns `ok = true` and the KAIA is permanently destroyed. The nonce is consumed and `lowerHandleNonce` advances normally, so the bridge itself does not stall — the loss is silent and unrecoverable.

The same missing check exists in `requestERC20Transfer` / `_requestERC20Transfer` and `requestERC721Transfer` / `_requestERC721Transfer`: [3](#0-2) [4](#0-3) 

For ERC-20 in **mint-burn mode** the source-side `ERC20Burnable.burn(_value)` executes before the event is emitted, permanently destroying the tokens. On the destination side `ERC20Mintable.mint(address(0), _value)` reverts (OpenZeppelin enforces the zero-address guard), so the entire `handleERC20Transfer` transaction reverts — including the `_updateHandleNonce` write — leaving `handleNoncesToBlockNums[nonce] == 0` forever. Because `_updateHandleNonce` advances `lowerHandleNonce` only while `handleNoncesToBlockNums[i] > 0`, the stuck nonce prevents `lowerHandleNonce` from advancing past it, degrading the bridge recovery mechanism for all subsequent transfers. [5](#0-4) [6](#0-5) 

### Impact Explanation

**KAIA path (highest severity):** Any user who calls `requestKLAYTransfer(address(0), value, extraData)` with sufficient `msg.value` will have their KAIA locked in the source bridge and then irrecoverably sent to `address(0)` on the destination chain. The call succeeds, the nonce is consumed, and no recovery is possible. This is an unauthorized, permanent burn of bridged KAIA.

**ERC-20 mint-burn path:** Tokens are burned on the source chain before the event is emitted. The destination-side handle always reverts, so the tokens are permanently destroyed and the bridge nonce for that request is never marked handled, degrading `lowerHandleNonce` accounting.

### Likelihood Explanation

Any unprivileged user can trigger this by passing `address(0)` as `_to`. While accidental misuse is the most common scenario, a malicious actor could deliberately burn their own bridged KAIA or grief the ERC-20 bridge's nonce accounting. No special role or collusion is required.

### Recommendation

Add a zero-address guard at the top of every public and internal bridge transfer entry point:

```solidity
require(_to != address(0), "zero recipient address");
```

This should be added to `_requestKLAYTransfer`, `requestKLAYTransfer`, `_requestERC20Transfer`, `requestERC20Transfer`, `onERC20Received`, `_requestERC721Transfer`, `requestERC721Transfer`, and `onERC721Received`.

### Proof of Concept

```
// Source chain
bridge.requestKLAYTransfer{value: 1.5 ether}(
    address(0),   // _to = zero address — no revert
    1 ether,
    ""
);
// → RequestValueTransfer emitted with to=0x000…000, requestNonce incremented
// → 1 ether locked in source bridge

// Destination chain (bridge operator relays event)
bridge.handleKLAYTransfer(
    txHash, from, payable(address(0)), 1 ether, nonce, blockNum, ""
);
// → _updateHandleNonce executes, lowerHandleNonce advances
// → address(0).call{value: 1 ether}("") returns ok=true
// → 1 ether permanently destroyed at address(0)
// → require(ok) passes — no revert, no recovery
```

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L98-99)
```text
        (bool ok, ) = _to.call.value(_value)("");
        require(ok, "handleKLAYTransfer: transfer failed");
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L103-124)
```text
    function _requestKLAYTransfer(address _to, uint256 _feeLimit,  bytes memory _extraData)
        internal
        unlockedKLAY
        nonReentrant
    {
        require(isRunning, "stopped bridge");
        require(msg.value > _feeLimit, "insufficient amount");

        uint256 fee = _payKLAYFeeAndRefundChange(_feeLimit);

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
    }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L68-72)
```text
        if (modeMintBurn) {
            require(ERC20Mintable(_tokenAddress).mint(_to, _value), "handleERC20Transfer: mint failed");
        } else {
            IERC20(_tokenAddress).safeTransfer(_to, _value);
        }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L76-108)
```text
    function _requestERC20Transfer(
        address _tokenAddress,
        address _from,
        address _to,
        uint256 _value,
        uint256 _feeLimit,
        bytes memory _extraData
    )
        internal
        onlyRegisteredToken(_tokenAddress)
        onlyUnlockedToken(_tokenAddress)
    {
        require(isRunning, "stopped bridge");
        require(_value > 0, "zero ERC20 token amount");

        uint256 fee = _payERC20FeeAndRefundChange(_from, _tokenAddress, _feeLimit);

        if (modeMintBurn) {
            ERC20Burnable(_tokenAddress).burn(_value);
        }

        emit RequestValueTransfer(
            TokenType.ERC20,
            _from,
            _to,
            _tokenAddress,
            _value,
            requestNonce,
            fee,
            _extraData
        );
        requestNonce++;
    }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L74-106)
```text
    function _requestERC721Transfer(
        address _tokenAddress,
        address _from,
        address _to,
        uint256 _tokenId,
        bytes memory _extraData
    )
        internal
        onlyRegisteredToken(_tokenAddress)
        onlyUnlockedToken(_tokenAddress)
    {
        require(isRunning, "stopped bridge");
        (bool success, bytes memory uri) = _tokenAddress.call(abi.encodePacked(ERC721Metadata(_tokenAddress).tokenURI.selector, abi.encode(_tokenId)));
        if (!success) {
            uri = "";
        }
        if (modeMintBurn) {
            ERC721Burnable(_tokenAddress).burn(_tokenId);
        }
        emit RequestValueTransferEncoded(
            TokenType.ERC721,
            _from,
            _to,
            _tokenAddress,
            _tokenId,
            requestNonce,
            0,
            _extraData,
            2,
            abi.encode(string(uri))
        );
        requestNonce++;
    }
```

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L139-156)
```text
    function _updateHandleNonce(uint64 _requestedNonce) internal {
        if (_requestedNonce > upperHandleNonce) {
            upperHandleNonce = _requestedNonce;
        }

        uint64 limit = lowerHandleNonce + 200;
        if (limit > upperHandleNonce) {
            limit = upperHandleNonce;
        }

        uint64 i;
        for (i = lowerHandleNonce; i <= limit && handleNoncesToBlockNums[i] > 0; i++) {
            recoveryBlockNumber = handleNoncesToBlockNums[i];
            delete handleNoncesToBlockNums[i];
            delete closedValueTransferVotes[i];
        }
        lowerHandleNonce = i;
    }
```
