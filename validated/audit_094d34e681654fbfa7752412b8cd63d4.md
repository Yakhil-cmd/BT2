### Title
`handle*Transfer` Functions Bypass `isRunning` Guard When Bridge Is Stopped — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`, `BridgeTransferERC20.sol`, `BridgeTransferERC721.sol`)

---

### Summary

The bridge's `isRunning` flag is intended to halt all asset movements during emergencies. The outbound request functions correctly enforce this guard, but the inbound handle functions (`handleKLAYTransfer`, `handleERC20Transfer`, `handleERC721Transfer`) do not check `isRunning`, allowing operators to push KLAY and token transfers out of the bridge even when the owner has stopped it.

---

### Finding Description

`BridgeTransfer.sol` declares `bool public isRunning = true` and exposes `setRunningStatus(false)` / `start(false)` for the owner to halt the bridge. [1](#0-0) 

Every **request** path (user → bridge) enforces this guard:

- `_requestKLAYTransfer`: `require(isRunning, "stopped bridge")` [2](#0-1) 
- `_requestERC20Transfer`: `require(isRunning, "stopped bridge")` [3](#0-2) 
- `_requestERC721Transfer`: `require(isRunning, "stopped bridge")` [4](#0-3) 

Every **handle** path (operator → recipient) is **missing** the guard entirely:

- `handleKLAYTransfer` — only `onlyOperators` + `nonReentrant`, no `isRunning` check: [5](#0-4) 
- `handleERC20Transfer` — only `onlyOperators`, no `isRunning` check: [6](#0-5) 
- `handleERC721Transfer` — only `onlyOperators`, no `isRunning` check: [7](#0-6) 

The nonce guard `_lowerHandleNonceCheck` only verifies `lowerHandleNonce <= _requestedNonce`; it does not verify that the nonce corresponds to a real pending cross-chain request. [8](#0-7) 

The vote key is `keccak256(msg.data)`, so with the default threshold of 1 (set in `BridgeOperator` constructor), a single operator can unilaterally execute any `handle*Transfer` call with arbitrary parameters. [9](#0-8) 

---

### Impact Explanation

When the bridge owner calls `start(false)` to stop the bridge — typically in response to a security incident, exploit, or upgrade — the `isRunning = false` state is supposed to freeze all asset movements. Because the handle functions bypass this flag, a compromised or malicious operator (or any operator when threshold = 1) can still call `handleKLAYTransfer` to drain the bridge's KLAY balance, `handleERC20Transfer` to drain ERC-20 tokens (via `safeTransfer` or `mint`), and `handleERC721Transfer` to transfer or mint ERC-721 tokens — all while the bridge is nominally stopped. This directly violates the invariant that `isRunning = false` halts all bridge-managed asset transfers.

---

### Likelihood Explanation

Requires two conditions: (1) the bridge is in a stopped state, and (2) at least one operator acts (maliciously or under compromise). With the default threshold of 1, condition (2) requires only a single operator. The scenario is realistic precisely in the situations where the owner would stop the bridge — i.e., when an operator key may already be at risk.

---

### Recommendation

Add an `isRunning` check to all three handle functions, mirroring the pattern used on the request side:

```diff
 function handleKLAYTransfer(...)
     public
     onlyOperators
     nonReentrant
 {
+    require(isRunning, "stopped bridge");
     _lowerHandleNonceCheck(_requestedNonce);
     ...
 }

 function handleERC20Transfer(...)
     public
     onlyOperators
 {
+    require(isRunning, "stopped bridge");
     _lowerHandleNonceCheck(_requestedNonce);
     ...
 }

 function handleERC721Transfer(...)
     public
     onlyOperators
 {
+    require(isRunning, "stopped bridge");
     _lowerHandleNonceCheck(_requestedNonce);
     ...
 }
```

Alternatively, extract the check into a shared modifier in `BridgeTransfer` and apply it to all six transfer entry points uniformly.

---

### Proof of Concept

1. Owner deploys bridge; default `isRunning = true`, default operator threshold = 1, deployer is operator.
2. Bridge accumulates KLAY (e.g., via `chargeWithoutEvent()`).
3. Owner detects an incident and calls `start(false)` → `isRunning = false`.
4. Attacker (compromised operator, or the deployer acting maliciously) calls:
   ```solidity
   handleKLAYTransfer(
       bytes32(0),          // arbitrary requestTxHash
       address(0),          // arbitrary _from
       payable(attacker),   // _to = attacker
       bridgeBalance,       // _value = full balance
       lowerHandleNonce,    // valid nonce (>= lowerHandleNonce)
       1,                   // arbitrary block number
       ""
   );
   ```
5. `_lowerHandleNonceCheck` passes (nonce is valid). `_voteValueTransfer` passes (threshold = 1, single vote suffices). No `isRunning` check exists. The bridge sends `bridgeBalance` KLAY to the attacker.
6. The bridge is drained despite `isRunning = false`.

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

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L158-160)
```text
    function _lowerHandleNonceCheck(uint64 _requestedNonce) internal {
        require(lowerHandleNonce <= _requestedNonce, "removed vote");
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

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L103-108)
```text
    function _requestKLAYTransfer(address _to, uint256 _feeLimit,  bytes memory _extraData)
        internal
        unlockedKLAY
        nonReentrant
    {
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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L76-88)
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

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L74-85)
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
