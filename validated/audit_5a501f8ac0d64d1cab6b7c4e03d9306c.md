### Title
`handleKLAYTransfer` (and `handleERC20Transfer` / `handleERC721Transfer`) Bypass `isLockedKLAY` / `isRunning` Emergency Stop, Allowing Asset Drain While Bridge Is Halted — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`, `BridgeTransferERC20.sol`, `BridgeTransferERC721.sol`)

---

### Summary

The Kaia service-chain bridge exposes three `handle*Transfer` functions that operators call to release assets on the destination side. All three functions are missing the `isRunning` / `isLockedKLAY` / `onlyUnlockedToken` guards that protect the corresponding `request*Transfer` entry-points. When the bridge owner invokes the emergency stop (`setRunningStatus(false)`) or the per-asset lock (`lockKLAY()` / `lockToken()`), users are blocked from initiating new cross-chain transfers, but operators can still call `handleKLAYTransfer`, `handleERC20Transfer`, and `handleERC721Transfer` to drain KLAY and bridged tokens from the contract.

---

### Finding Description

`BridgeTransfer.sol` declares two protected-state flags:

- `isRunning` (line 28) — toggled by the owner via `setRunningStatus(false)` to halt the bridge.
- `isLockedKLAY` in `BridgeTransferKLAY.sol` (line 24) — toggled by `lockKLAY()` to prevent KLAY transfers.
- `lockedTokens[token]` in `BridgeTokens.sol` (line 25) — toggled by `lockToken()` to prevent per-token transfers. [1](#0-0) [2](#0-1) [3](#0-2) 

The **request** path correctly enforces these guards:

- `_requestKLAYTransfer` carries `unlockedKLAY` and `require(isRunning, "stopped bridge")`.
- `_requestERC20Transfer` carries `onlyUnlockedToken(_tokenAddress)` and `require(isRunning, "stopped bridge")`.
- `_requestERC721Transfer` carries `onlyUnlockedToken(_tokenAddress)` and `require(isRunning, "stopped bridge")`. [4](#0-3) [5](#0-4) 

The **handle** path has **no such guards**:

```solidity
// BridgeTransferKLAY.sol L62-100
function handleKLAYTransfer(...)
    public
    onlyOperators   // ← only guard
    nonReentrant
{
    ...
    (bool ok, ) = _to.call.value(_value)("");   // sends KLAY unconditionally
    require(ok, "handleKLAYTransfer: transfer failed");
}
```

```solidity
// BridgeTransferERC20.sol L32-73
function handleERC20Transfer(...)
    public
    onlyOperators   // ← only guard
{
    ...
    IERC20(_tokenAddress).safeTransfer(_to, _value);  // sends tokens unconditionally
}
``` [6](#0-5) [7](#0-6) [8](#0-7) 

---

### Impact Explanation

When the owner calls `lockKLAY()` or `setRunningStatus(false)` — typically in response to a security incident such as a suspected operator-key compromise — the intent is to freeze all asset movement through the bridge. Because `handleKLAYTransfer` / `handleERC20Transfer` / `handleERC721Transfer` ignore both flags, any operator (including a compromised one) can continue to call these functions and transfer KLAY or bridged ERC-20/ERC-721 tokens out of the bridge contract to arbitrary `_to` addresses. The corrupted value is the bridge's entire KLAY balance and all held token balances. [9](#0-8) [10](#0-9) 

---

### Likelihood Explanation

The trigger requires operator-level access, which is semi-trusted. However, the lock/stop mechanism exists precisely to protect against scenarios where operators are compromised. The owner's emergency action is rendered ineffective against any operator who retains their key. The `onlyOperators` modifier is the only barrier, and it is the very role the emergency stop is designed to neutralize. [11](#0-10) 

---

### Recommendation

Add the appropriate state guards to all three `handle*Transfer` functions:

- `handleKLAYTransfer`: add `require(isRunning, "stopped bridge")` and `require(!isLockedKLAY, "locked")`.
- `handleERC20Transfer`: add `require(isRunning, "stopped bridge")` and `require(!lockedTokens[_tokenAddress], "locked token")`.
- `handleERC721Transfer`: add `require(isRunning, "stopped bridge")` and `require(!lockedTokens[_tokenAddress], "locked token")`.

Alternatively, introduce a shared `whenRunning` modifier in `BridgeTransfer` and apply it uniformly to all public transfer entry-points, both request and handle sides.

---

### Proof of Concept

1. Owner deploys the bridge and registers an operator.
2. A security incident is detected; owner calls `lockKLAY()` (sets `isLockedKLAY = true`) and `setRunningStatus(false)` (sets `isRunning = false`).
3. Users attempting `requestKLAYTransfer` are correctly reverted with `"locked"` / `"stopped bridge"`.
4. The operator (or attacker who has obtained the operator key) calls:
   ```solidity
   bridge.handleKLAYTransfer(
       fakeRequestTxHash,
       victimAddress,
       attackerAddress,   // _to
       bridgeKLAYBalance, // _value — full bridge balance
       nextNonce,
       blockNumber,
       ""
   );
   ```
5. `handleKLAYTransfer` passes `onlyOperators`, skips all lock/running checks, and executes `_to.call.value(_value)("")`, transferring the entire KLAY balance to the attacker.
6. The same attack applies to `handleERC20Transfer` and `handleERC721Transfer` for bridged tokens. [12](#0-11) [13](#0-12) [14](#0-13)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L27-28)
```text
    bool public modeMintBurn = false;
    bool public isRunning = true;
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

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L24-24)
```text
    bool public isLockedKLAY;
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L39-47)
```text
    // lockKLAY can to prevent request KLAY transferring.
    function lockKLAY()
        external
        onlyOwner
        unlockedKLAY
    {
        isLockedKLAY = true;

        emit KLAYLocked();
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

**File:** contracts/service_chain/bridge/BridgeTokens.sol (L25-25)
```text
    mapping(address => bool) public lockedTokens;
```

**File:** contracts/service_chain/bridge/BridgeTokens.sol (L94-104)
```text
    // lockToken can lock the token to prevent request token transferring.
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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L84-88)
```text
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
