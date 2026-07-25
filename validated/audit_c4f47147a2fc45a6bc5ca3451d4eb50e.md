### Title
Missing `isRunning` Guard in Bridge Handle Functions Allows Asset Transfers When Bridge Is Stopped — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`, `BridgeTransferERC20.sol`, `BridgeTransferERC721.sol`)

---

### Summary

The Kaia service-chain bridge contracts expose `handleKLAYTransfer`, `handleERC20Transfer`, and `handleERC721Transfer` as operator-callable functions that transfer KLAY and bridged tokens to recipients. All three functions are missing the `require(isRunning, "stopped bridge")` guard that is present in every corresponding `_request*Transfer` function. When the bridge owner invokes `start(false)` / `setRunningStatus(false)` to halt the bridge (e.g., during an emergency), the request path is correctly blocked, but the handle path remains fully open. Any operator meeting the vote threshold can still execute arbitrary value transfers out of the bridge contract.

---

### Finding Description

`BridgeTransfer.sol` declares `bool public isRunning = true` and exposes `setRunningStatus` / `start` for the owner to halt all bridge activity. [1](#0-0) 

Every `_request*Transfer` internal function enforces this flag:

- `_requestKLAYTransfer`: `require(isRunning, "stopped bridge")` [2](#0-1) 
- `_requestERC20Transfer`: `require(isRunning, "stopped bridge")` [3](#0-2) 
- `_requestERC721Transfer`: `require(isRunning, "stopped bridge")` [4](#0-3) 

However, the three public handle functions that actually disburse assets carry **no** `isRunning` check:

- `handleKLAYTransfer` — only `onlyOperators` + `nonReentrant` [5](#0-4) 
- `handleERC20Transfer` — only `onlyOperators` [6](#0-5) 
- `handleERC721Transfer` — only `onlyOperators` [7](#0-6) 

---

### Impact Explanation

When `isRunning = false`, the owner's intent is to freeze all bridge asset movement. The request side is correctly frozen. But operators can still call `handleKLAYTransfer` with arbitrary `(_requestTxHash, _from, _to, _value, _requestedNonce, _requestedBlockNumber)` parameters. The only on-chain checks are nonce ordering (`_lowerHandleNonceCheck`) and operator vote threshold (`_voteValueTransfer`). If the vote threshold is 1 (or enough operators cooperate), KLAY held in the bridge contract is transferred to an arbitrary `_to` address via `_to.call.value(_value)("")`. Similarly, `handleERC20Transfer` mints or transfers ERC20 tokens, and `handleERC721Transfer` mints or transfers ERC721 tokens, all while the bridge is supposed to be stopped.

Corrupted value: KLAY balance of the bridge contract and bridged ERC20/ERC721 token balances are drained to attacker-controlled addresses despite `isRunning = false`. [8](#0-7) [9](#0-8) [10](#0-9) 

---

### Likelihood Explanation

The trigger requires a registered bridge operator (or a set of operators meeting the configured threshold). Operators are semi-trusted: they are registered by the owner but are distinct accounts. The scenario is realistic whenever the owner stops the bridge in response to a security incident — precisely the moment when preventing further asset movement is most critical. The default operator threshold can be as low as 1, making a single compromised or malicious operator sufficient. [11](#0-10) 

---

### Recommendation

Add `require(isRunning, "stopped bridge")` at the top of each handle function, mirroring the pattern already used in the request functions:

```solidity
// BridgeTransferKLAY.sol – handleKLAYTransfer
function handleKLAYTransfer(...) public onlyOperators nonReentrant {
+   require(isRunning, "stopped bridge");
    _lowerHandleNonceCheck(_requestedNonce);
    ...
}

// BridgeTransferERC20.sol – handleERC20Transfer
function handleERC20Transfer(...) public onlyOperators {
+   require(isRunning, "stopped bridge");
    _lowerHandleNonceCheck(_requestedNonce);
    ...
}

// BridgeTransferERC721.sol – handleERC721Transfer
function handleERC721Transfer(...) public onlyOperators {
+   require(isRunning, "stopped bridge");
    _lowerHandleNonceCheck(_requestedNonce);
    ...
}
```

Alternatively, introduce a shared `onlyRunning` modifier in `BridgeTransfer.sol` and apply it uniformly to all six transfer entry points.

---

### Proof of Concept

1. Owner deploys bridge; `isRunning` defaults to `true`.
2. Owner calls `start(false)` to halt the bridge during an incident.
3. `requestKLAYTransfer` now reverts with `"stopped bridge"` — request path is frozen.
4. Operator calls `handleKLAYTransfer(txHash, attacker, victim, 1 ether, nonce, blockNum, "")` — **succeeds** because no `isRunning` check exists.
5. `_to.call.value(1 ether)("")` executes, draining 1 KLAY from the bridge to `victim` (or any attacker-controlled address) despite the bridge being stopped.
6. The same applies to `handleERC20Transfer` (mints/transfers ERC20) and `handleERC721Transfer` (mints/transfers ERC721). [12](#0-11) [6](#0-5) [7](#0-6)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L28-57)
```text
    bool public isRunning = true;

    uint64 public requestNonce; // the number of value transfer request that this contract received.
    uint64 public lowerHandleNonce; // a minimum nonce of a value transfer request that will be handled.
    uint64 public upperHandleNonce; // a maximum nonce of the counterpart bridge's value transfer request that is handled.
    uint64 public recoveryBlockNumber = 1; // the block number that recovery start to filter log from.
    mapping(uint64 => uint64) public handleNoncesToBlockNums;  // <request nonce> => <request blockNum>

    event RunningStatusChanged(bool _status);

    using SafeMath for uint256;

    enum TokenType {
        KLAY,
        ERC20,
        ERC721
    }

    constructor(bool _modeMintBurn) BridgeFee(address(0)) internal {
        modeMintBurn = _modeMintBurn;
    }

    // setRunningStatus can allow or disallow the value transfer request.
    function setRunningStatus(bool _status)
        public
        onlyOwner
    {
        isRunning = _status;
        emit RunningStatusChanged(_status);
    }
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L62-100)
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
        _lowerHandleNonceCheck(_requestedNonce);

        if (!_voteValueTransfer(_requestedNonce)) {
            return;
        }

        _setHandledRequestTxHash(_requestTxHash);

        handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber;
        _updateHandleNonce(_requestedNonce);

        emit HandleValueTransfer(
            _requestTxHash,
            TokenType.KLAY,
            _from,
            _to,
            address(0),
            _value,
            _requestedNonce,
            lowerHandleNonce,
            _extraData
        );

        (bool ok, ) = _to.call.value(_value)("");
        require(ok, "handleKLAYTransfer: transfer failed");
    }
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L108-108)
```text
        require(isRunning, "stopped bridge");
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L32-73)
```text
    function handleERC20Transfer(
        bytes32 _requestTxHash,
        address _from,
        address _to,
        address _tokenAddress,
        uint256 _value,
        uint64 _requestedNonce,
        uint64 _requestedBlockNumber,
        bytes memory _extraData
    )
        public
        onlyOperators
    {
        _lowerHandleNonceCheck(_requestedNonce);

        if (!_voteValueTransfer(_requestedNonce)) {
            return;
        }

        _setHandledRequestTxHash(_requestTxHash);

        handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber;
        _updateHandleNonce(_requestedNonce);

        emit HandleValueTransfer(
            _requestTxHash,
            TokenType.ERC20,
            _from,
            _to,
            _tokenAddress,
            _value,
            _requestedNonce,
            lowerHandleNonce,
            _extraData
        );

        if (modeMintBurn) {
            require(ERC20Mintable(_tokenAddress).mint(_to, _value), "handleERC20Transfer: mint failed");
        } else {
            IERC20(_tokenAddress).safeTransfer(_to, _value);
        }
    }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L88-88)
```text
        require(isRunning, "stopped bridge");
```

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L29-71)
```text
    function handleERC721Transfer(
        bytes32 _requestTxHash,
        address _from,
        address _to,
        address _tokenAddress,
        uint256 _tokenId,
        uint64 _requestedNonce,
        uint64 _requestedBlockNumber,
        string memory _tokenURI,
        bytes memory _extraData
    )
        public
        onlyOperators
    {
        _lowerHandleNonceCheck(_requestedNonce);

        if (!_voteValueTransfer(_requestedNonce)) {
            return;
        }

        _setHandledRequestTxHash(_requestTxHash);

        handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber;
        _updateHandleNonce(_requestedNonce);

        emit HandleValueTransfer(
            _requestTxHash,
            TokenType.ERC721,
            _from,
            _to,
            _tokenAddress,
            _tokenId,
            _requestedNonce,
            lowerHandleNonce,
            _extraData
        );

        if (modeMintBurn) {
            require(ERC721MetadataMintable(_tokenAddress).mintWithTokenURI(_to, _tokenId, _tokenURI), "mint failed");
        } else {
            IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);
        }
    }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L85-85)
```text
        require(isRunning, "stopped bridge");
```
