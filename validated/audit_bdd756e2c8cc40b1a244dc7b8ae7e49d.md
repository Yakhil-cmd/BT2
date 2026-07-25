### Title
Bridge `isRunning` Stop Flag Not Enforced in Handle Functions, Allowing Asset Transfers When Bridge Is Stopped — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`, `BridgeTransferERC20.sol`, `BridgeTransferERC721.sol`)

---

### Summary

The `isRunning` flag in the Kaia service-chain bridge contracts is intended to halt all bridge operations when the owner calls `setRunningStatus(false)`. The outbound request functions correctly enforce this guard, but the inbound handle functions — which actually move KAIA, ERC20, and ERC721 tokens out of the bridge — do not check `isRunning` at all. Any registered bridge operator can therefore continue draining bridged assets even while the bridge is in a stopped state.

---

### Finding Description

`BridgeTransfer.sol` declares `isRunning` and exposes `setRunningStatus(bool)` (owner-only) as an emergency circuit-breaker. [1](#0-0) 

The three request-side functions correctly enforce the guard:

- `_requestKLAYTransfer()` — `require(isRunning, "stopped bridge")` at line 108
- `_requestERC20Transfer()` — `require(isRunning, "stopped bridge")` at line 88
- `_requestERC721Transfer()` — `require(isRunning, "stopped bridge")` at line 85 [2](#0-1) [3](#0-2) [4](#0-3) 

The three handle-side functions that actually transfer assets contain **no `isRunning` check**:

**`handleKLAYTransfer`** — transfers native KAIA to `_to` via `.call.value(_value)("")`: [5](#0-4) 

**`handleERC20Transfer`** — mints or `safeTransfer`s ERC20 tokens to `_to`: [6](#0-5) 

**`handleERC721Transfer`** — mints or `transferFrom`s ERC721 tokens to `_to`: [7](#0-6) 

The only access control on the handle functions is `onlyOperators`. Operators are semi-trusted accounts registered by the bridge owner; they are not the owner themselves.

---

### Impact Explanation

When the bridge owner stops the bridge (`isRunning = false`) to contain a security incident — for example, a compromised counterpart chain or a discovered exploit — any registered operator can still call `handleKLAYTransfer`, `handleERC20Transfer`, or `handleERC721Transfer` with arbitrary parameters and successfully transfer KAIA or bridged tokens out of the bridge contract. The emergency stop provides no protection against the handle path.

Corrupted value: the KAIA balance of the bridge contract and the ERC20/ERC721 balances held in custody are transferred to attacker-controlled addresses despite `isRunning == false`.

---

### Likelihood Explanation

The trigger requires a registered bridge operator — a semi-trusted role, not an arbitrary user. However:
- Operators are not the owner; they are a separate, potentially larger set of accounts.
- A compromised operator key, a malicious operator, or a social-engineering attack on an operator is a realistic scenario, especially during the same incident that prompted the owner to stop the bridge.
- The call requires no special on-chain state beyond operator registration and sufficient bridge liquidity, both of which are normal operating conditions.

---

### Recommendation

Add `require(isRunning, "stopped bridge")` at the top of each handle function, mirroring the guard already present in the request functions:

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
```

Alternatively, extract the guard into a shared modifier in `BridgeTransfer` and apply it to all six public entry points.

---

### Proof of Concept

1. Owner calls `bridge.setRunningStatus(false)` — bridge is now stopped; `isRunning == false`.
2. Operator calls `bridge.handleKLAYTransfer(txHash, from, attackerAddr, 1000 ether, nonce, blockNum, "0x")`.
3. The call passes `onlyOperators`, skips the absent `isRunning` check, passes `_lowerHandleNonceCheck`, votes through `_voteValueTransfer`, and executes `attackerAddr.call.value(1000 ether)("")`.
4. 1000 KAIA is transferred to `attackerAddr` while the bridge is in a stopped state.
5. The same pattern applies to `handleERC20Transfer` (minting or transferring ERC20) and `handleERC721Transfer` (minting or transferring ERC721).

The invariant broken is: **`isRunning == false` must prevent all asset movements out of the bridge**. The request path enforces this; the handle path does not. [8](#0-7) [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L103-109)
```text
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

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L73-86)
```text
    // _requestERC721Transfer requests transfer ERC721 to _to on relative chain.
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
