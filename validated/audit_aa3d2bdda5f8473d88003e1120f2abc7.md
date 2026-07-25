### Title
`handleKLAYTransfer()`, `handleERC20Transfer()`, and `handleERC721Transfer()` Callable When Bridge Assets Are Locked — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`, `BridgeTransferERC20.sol`, `BridgeTransferERC721.sol`)

### Summary

The Kaia service-chain bridge implements per-asset lock guards (`unlockedKLAY`, `onlyUnlockedToken`) to let the owner emergency-stop outbound transfers. These guards are applied to the user-facing *request* path but are entirely absent from the operator-facing *handle* path. As a result, bridge operators can drain KLAY and registered ERC-20/ERC-721 tokens from the bridge contract even after the owner has activated the lock.

### Finding Description

`BridgeTransferKLAY.sol` defines two modifiers and a lock flag:

```solidity
bool public isLockedKLAY;

modifier lockedKLAY   { require( isLockedKLAY, "unlocked"); _; }
modifier unlockedKLAY { require(!isLockedKLAY, "locked");   _; }
```

The internal request function correctly enforces the lock:

```solidity
// _requestKLAYTransfer — line 103-124
function _requestKLAYTransfer(...) internal unlockedKLAY nonReentrant {
    require(isRunning, "stopped bridge");
    ...
}
```

But the handle function that actually sends KLAY to the recipient does **not** carry the `unlockedKLAY` modifier:

```solidity
// handleKLAYTransfer — line 62-100
function handleKLAYTransfer(...) public onlyOperators nonReentrant {
    ...
    (bool ok, ) = _to.call.value(_value)("");   // KLAY leaves the bridge here
    require(ok, "handleKLAYTransfer: transfer failed");
}
```

The same asymmetry exists in `BridgeTransferERC20.sol`:

- `_requestERC20Transfer` carries `onlyUnlockedToken(_tokenAddress)` (line 86)
- `handleERC20Transfer` carries only `onlyOperators` — `onlyUnlockedToken` is absent (line 43)

And in `BridgeTransferERC721.sol`:

- `_requestERC721Transfer` carries `onlyUnlockedToken(_tokenAddress)` (line 83)
- `handleERC721Transfer` carries only `onlyOperators` — `onlyUnlockedToken` is absent (line 41)

The lock functions themselves are owner-only:

```solidity
// BridgeTokens.sol line 95-104
function lockToken(address _token) external onlyOwner onlyRegisteredToken onlyUnlockedToken {
    lockedTokens[_token] = true;
    emit TokenLocked(_token);
}
```

So the owner can lock assets, but operators — who are a distinct, semi-trusted role registered by the owner — can still call the handle functions and move assets out of the bridge.

### Impact Explanation

When the owner calls `lockKLAY()` or `lockToken()` (e.g., in response to a detected exploit or bridge misconfiguration), the intent is to halt all asset movement. The request path is correctly blocked. However, any registered operator can immediately call `handleKLAYTransfer` / `handleERC20Transfer` / `handleERC721Transfer` with arbitrary parameters and transfer the full KLAY balance or any ERC-20/ERC-721 token held by the bridge to an arbitrary address. The `_voteValueTransfer` threshold can be as low as 1 (the default), meaning a single operator suffices. The corrupted value is the entire KLAY/token balance of the bridge contract, transferred to an attacker-controlled address while the owner's emergency lock is active.

### Likelihood Explanation

The default operator threshold is 1 (`operatorThresholds[uint8(i)] = 1` in `BridgeOperator` constructor). The deployer is automatically an operator. Any registered operator — a role that is semi-trusted but distinct from the owner — can exploit this without any additional privilege escalation. The attack is executable in a single transaction immediately after the owner activates the lock.

### Recommendation

Add the lock guard to each handle function:

```solidity
// BridgeTransferKLAY.sol
function handleKLAYTransfer(...) public onlyOperators unlockedKLAY nonReentrant { ... }

// BridgeTransferERC20.sol
function handleERC20Transfer(...) public onlyOperators onlyUnlockedToken(_tokenAddress) { ... }

// BridgeTransferERC721.sol
function handleERC721Transfer(...) public onlyOperators onlyUnlockedToken(_tokenAddress) { ... }
```

### Proof of Concept

1. Owner deploys bridge, registers operator `OP`, sets threshold to 1.
2. Bridge accumulates 1000 KLAY via `chargeWithoutEvent`.
3. Owner detects anomaly and calls `lockKLAY()` → `isLockedKLAY = true`.
4. `OP` calls `handleKLAYTransfer(fakeTxHash, OP, ATTACKER, 1000e18, 0, 1, "")`.
5. `_lowerHandleNonceCheck(0)` passes (lowerHandleNonce == 0).
6. `_voteValueTransfer(0)` returns `true` (threshold == 1, single vote).
7. `_to.call.value(1000e18)("")` executes — 1000 KLAY sent to `ATTACKER`.
8. Lock is active, yet the full bridge balance is drained.

---

**Affected files:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8)

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

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L103-106)
```text
    function _requestKLAYTransfer(address _to, uint256 _feeLimit,  bytes memory _extraData)
        internal
        unlockedKLAY
        nonReentrant
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L32-44)
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
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L84-87)
```text
        internal
        onlyRegisteredToken(_tokenAddress)
        onlyUnlockedToken(_tokenAddress)
    {
```

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L29-42)
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
```

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L81-84)
```text
        internal
        onlyRegisteredToken(_tokenAddress)
        onlyUnlockedToken(_tokenAddress)
    {
```

**File:** contracts/service_chain/bridge/BridgeTokens.sol (L42-50)
```text
    modifier onlyLockedToken(address _token) {
        require(lockedTokens[_token], "unlocked token");
        _;
    }

    modifier onlyUnlockedToken(address _token) {
        require(!lockedTokens[_token], "locked token");
        _;
    }
```

**File:** contracts/service_chain/bridge/BridgeTokens.sol (L95-104)
```text
    function lockToken(address _token)
        external
        onlyOwner
        onlyRegisteredToken(_token)
        onlyUnlockedToken(_token)
    {
        lockedTokens[_token] = true;

        emit TokenLocked(_token);
    }
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
