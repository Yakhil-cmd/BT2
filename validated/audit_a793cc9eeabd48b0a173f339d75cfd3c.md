### Title
Bridge `handle*Transfer` Functions Bypass `isRunning` and Token-Lock Guards, Enabling Asset Drain When Bridge Is Stopped — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`, `BridgeTransferERC20.sol`, `BridgeTransferERC721.sol`)

---

### Summary

The Kaia service-chain bridge exposes three operator-callable "handle" functions (`handleKLAYTransfer`, `handleERC20Transfer`, `handleERC721Transfer`) that move assets out of the bridge contract. The corresponding "request" functions that move assets *into* the bridge all enforce `isRunning` and per-asset lock guards. The handle functions enforce neither. When the bridge owner invokes the emergency stop (`isRunning = false`) or locks a specific asset (`isLockedKLAY = true` / `lockedTokens[token] = true`), operators — including automated relayers with a default threshold of 1 — can still call the handle functions and drain KLAY, ERC20, and ERC721 tokens from the bridge.

---

### Finding Description

`BridgeTransfer.sol` declares the `isRunning` flag and `setRunningStatus` to halt the bridge in emergencies. [1](#0-0) 

`BridgeTransferKLAY.sol` declares `isLockedKLAY` and enforces it only on the request path via the `unlockedKLAY` modifier and an explicit `isRunning` check: [2](#0-1) 

`BridgeTransferERC20.sol` similarly enforces `onlyUnlockedToken` and `isRunning` only on the request path: [3](#0-2) 

`BridgeTransferERC721.sol` does the same: [4](#0-3) 

However, all three handle functions — which actually push assets out of the bridge — carry **no such checks**:

`handleKLAYTransfer` (no `isRunning`, no `unlockedKLAY`): [5](#0-4) 

`handleERC20Transfer` (no `isRunning`, no `onlyUnlockedToken`): [6](#0-5) 

`handleERC721Transfer` (no `isRunning`, no `onlyUnlockedToken`): [7](#0-6) 

The `onlyOperators` modifier is the sole gate on all three functions: [8](#0-7) 

The default operator threshold is 1, meaning a single operator can unilaterally execute any handle call: [9](#0-8) 

---

### Impact Explanation

When the bridge owner calls `setRunningStatus(false)` or `lockKLAY()` / `lockToken(token)` as an emergency response (e.g., a counterpart-chain exploit generating fraudulent cross-chain requests), the protective flags are silently ignored by the handle path. Any registered operator — including an automated relayer bot that is unaware of the emergency stop — can continue calling `handleKLAYTransfer`, `handleERC20Transfer`, or `handleERC721Transfer` to transfer KLAY, ERC20 tokens (or mint them in `modeMintBurn` mode), and ERC721 tokens (or mint them) out of the bridge to attacker-controlled addresses. The bridge's entire KLAY balance and all locked ERC20/ERC721 reserves are at risk.

---

### Likelihood Explanation

Bridge operators are typically automated relayers that listen for `RequestValueTransfer` events on the counterpart chain and immediately call the corresponding handle function. They do not poll `isRunning` or lock state before submitting. With the default threshold of 1, a single such relayer is sufficient to execute the transfer. The owner's emergency stop therefore provides no real protection against ongoing handle-side asset outflows.

---

### Recommendation

Add `isRunning` and the relevant lock guard to each handle function. For `handleKLAYTransfer`, add:

```solidity
require(isRunning, "stopped bridge");
require(!isLockedKLAY, "locked");
```

For `handleERC20Transfer` and `handleERC721Transfer`, add:

```solidity
require(isRunning, "stopped bridge");
require(!lockedTokens[_tokenAddress], "locked token");
```

If the intent is to allow handle transfers to complete even after a stop (to drain pending cross-chain requests safely), this asymmetry must be explicitly documented and the lock/stop semantics must be clearly separated into "no new requests" vs. "no outbound transfers."

---

### Proof of Concept

1. Deploy the bridge with one operator (threshold = 1, default).
2. Fund the bridge with 100 KLAY.
3. Owner calls `setRunningStatus(false)` — bridge is stopped.
4. Owner calls `lockKLAY()` — KLAY is locked.
5. Operator calls:
   ```solidity
   bridge.handleKLAYTransfer(
       txhash, attacker, attacker, 100 ether, 0, blockNum, ""
   );
   ```
6. The call succeeds: neither `isRunning` nor `isLockedKLAY` is checked. The bridge's entire KLAY balance is transferred to `attacker`.

The same sequence applies to `handleERC20Transfer` (drains or mints ERC20) and `handleERC721Transfer` (drains or mints ERC721), bypassing `lockedTokens` in both cases.

### Citations

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L27-57)
```text
    bool public modeMintBurn = false;
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

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L81-85)
```text
        internal
        onlyRegisteredToken(_tokenAddress)
        onlyUnlockedToken(_tokenAddress)
    {
        require(isRunning, "stopped bridge");
```

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L54-61)
```text
    constructor() internal {
        for (uint8 i = 0; i < uint8(VoteType.Max); i++) {
            operatorThresholds[uint8(i)] = 1;
        }

        operators[msg.sender] = true;
        operatorList.push(msg.sender);
    }
```

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L63-67)
```text
    modifier onlyOperators()
    {
        require(operators[msg.sender], "msg.sender is not an operator");
        _;
    }
```
