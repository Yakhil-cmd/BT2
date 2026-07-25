### Title
Bridge `handle*Transfer` Functions Missing `isRunning` Guard Allows Asset Drain When Bridge Is Stopped — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`, `BridgeTransferERC20.sol`, `BridgeTransferERC721.sol`)

---

### Summary

The Kaia service-chain bridge's `handleKLAYTransfer`, `handleERC20Transfer`, and `handleERC721Transfer` functions are missing the `isRunning` check that all corresponding `request*Transfer` functions enforce. When the bridge owner stops the bridge (`isRunning = false`) as an emergency measure, operators can still call the handle functions to transfer KLAY, ERC20, or ERC721 tokens out of the bridge contract.

---

### Finding Description

`BridgeTransfer.isRunning` is the bridge's emergency-stop flag. The owner sets it to `false` via `setRunningStatus(false)` / `start(false)` to halt all bridge activity during exploits, upgrades, or active bugs.

Every **request** path enforces this guard:

- `_requestKLAYTransfer` — `require(isRunning, "stopped bridge");`
- `_requestERC20Transfer` — `require(isRunning, "stopped bridge");`
- `_requestERC721Transfer` — `require(isRunning, "stopped bridge");`

But every **handle** path omits it entirely:

- `handleKLAYTransfer` — `onlyOperators`, `nonReentrant`, **no `isRunning` check**
- `handleERC20Transfer` — `onlyOperators`, **no `isRunning` check**
- `handleERC721Transfer` — `onlyOperators`, **no `isRunning` check**

The handle functions transfer real assets: `handleKLAYTransfer` calls `_to.call.value(_value)("")`; `handleERC20Transfer` calls `IERC20.safeTransfer` or `ERC20Mintable.mint`; `handleERC721Transfer` calls `IERC721.transferFrom` or `ERC721MetadataMintable.mintWithTokenURI`.

The default `operatorThresholds[ValueTransfer]` is **1**, meaning a single operator can unilaterally execute a handle call without any co-signer. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) 

---

### Impact Explanation

When the bridge owner stops the bridge in response to a security incident, the `isRunning = false` state is supposed to freeze all asset movement. Because the handle functions bypass this flag, a compromised or malicious operator can:

1. Call `handleKLAYTransfer` with an attacker-controlled `_to` and any `_value` up to the bridge's KLAY balance — directly draining native KLAY.
2. Call `handleERC20Transfer` in mint-burn mode to mint arbitrary ERC20 tokens to any address, or in lock-unlock mode to drain the bridge's ERC20 reserves.
3. Call `handleERC721Transfer` to mint or transfer NFTs held by the bridge.

The corrupted value is the bridge's KLAY balance / ERC20 balance / NFT holdings — all protected assets that the emergency stop is designed to freeze.

---

### Likelihood Explanation

- The default operator threshold is 1, so no collusion is required.
- Operators are semi-trusted: they are registered by the owner but hold independent keys that can be compromised.
- The exact scenario the `isRunning` flag is designed to guard against — a security incident requiring an emergency stop — is also the scenario where a compromised operator key is most dangerous.
- The owner cannot atomically stop the bridge and deregister all operators in a single transaction; there is a window during which the bridge is stopped but operators remain registered.

---

### Recommendation

Add an `isRunning` guard to all three handle functions, mirroring the pattern already used in the request functions:

```solidity
// BridgeTransferKLAY.sol
function handleKLAYTransfer(...) public onlyOperators nonReentrant {
+   require(isRunning, "stopped bridge");
    _lowerHandleNonceCheck(_requestedNonce);
    ...
}

// BridgeTransferERC20.sol
function handleERC20Transfer(...) public onlyOperators {
+   require(isRunning, "stopped bridge");
    _lowerHandleNonceCheck(_requestedNonce);
    ...
}

// BridgeTransferERC721.sol
function handleERC721Transfer(...) public onlyOperators {
+   require(isRunning, "stopped bridge");
    _lowerHandleNonceCheck(_requestedNonce);
    ...
}
``` [8](#0-7) 

---

### Proof of Concept

```
Setup:
  - Deploy Bridge(false) with operator = Alice (threshold = 1, default)
  - Fund bridge with 10 KLAY
  - Owner calls start(false)  →  isRunning = false

Attack:
  - Alice (operator, key compromised) calls:
      handleKLAYTransfer(
          txHash = <any fresh bytes32>,
          _from  = <any address>,
          _to    = attacker,
          _value = 10 ether,
          _requestedNonce = lowerHandleNonce,   // satisfies _lowerHandleNonceCheck
          _requestedBlockNumber = block.number,
          _extraData = ""
      )

Result:
  - _voteValueTransfer passes (threshold = 1, Alice is the sole voter)
  - _to.call.value(10 ether)("") succeeds
  - Bridge KLAY balance: 0
  - isRunning was false throughout — the emergency stop had zero effect on the handle path
``` [9](#0-8) [10](#0-9) [11](#0-10)

### Citations

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

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L102-109)
```text
    // _requestKLAYTransfer requests transfer KLAY to _to on relative chain.
    function _requestKLAYTransfer(address _to, uint256 _feeLimit,  bytes memory _extraData)
        internal
        unlockedKLAY
        nonReentrant
    {
        require(isRunning, "stopped bridge");
        require(msg.value > _feeLimit, "insufficient amount");
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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L84-89)
```text
        internal
        onlyRegisteredToken(_tokenAddress)
        onlyUnlockedToken(_tokenAddress)
    {
        require(isRunning, "stopped bridge");
        require(_value > 0, "zero ERC20 token amount");
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

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L74-86)
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
```

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L54-57)
```text
    constructor() internal {
        for (uint8 i = 0; i < uint8(VoteType.Max); i++) {
            operatorThresholds[uint8(i)] = 1;
        }
```

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L102-116)
```text
    // _voteValueTransfer votes value transfer transaction with the operator.
    function _voteValueTransfer(uint64 _requestNonce)
        internal
        returns(bool)
    {
        require(!closedValueTransferVotes[_requestNonce], "closed vote");

        bytes32 voteKey = keccak256(msg.data);
        if (_voteCommon(VoteType.ValueTransfer, _requestNonce, voteKey)) {
            closedValueTransferVotes[_requestNonce] = true;
            return true;
        }

        return false;
    }
```

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L26-34)
```text
contract BridgeTransfer is BridgeHandledRequests, BridgeFee, BridgeOperator {
    bool public modeMintBurn = false;
    bool public isRunning = true;

    uint64 public requestNonce; // the number of value transfer request that this contract received.
    uint64 public lowerHandleNonce; // a minimum nonce of a value transfer request that will be handled.
    uint64 public upperHandleNonce; // a maximum nonce of the counterpart bridge's value transfer request that is handled.
    uint64 public recoveryBlockNumber = 1; // the block number that recovery start to filter log from.
    mapping(uint64 => uint64) public handleNoncesToBlockNums;  // <request nonce> => <request blockNum>
```

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L50-57)
```text
    // setRunningStatus can allow or disallow the value transfer request.
    function setRunningStatus(bool _status)
        public
        onlyOwner
    {
        isRunning = _status;
        emit RunningStatusChanged(_status);
    }
```
