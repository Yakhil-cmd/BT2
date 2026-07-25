### Title
Bridge `chargeWithoutEvent()` Bypasses `isRunning` and `isLockedKLAY` Stop Mechanisms, and `handleKLAYTransfer`/`handleERC20Transfer`/`handleERC721Transfer` Bypass `isRunning` — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`, `BridgeTransferERC20.sol`, `BridgeTransferERC721.sol`)

---

### Summary

The Kaia service-chain bridge implements two stop mechanisms: `isRunning` (global bridge stop) and `isLockedKLAY` / `lockedTokens` (per-asset lock). However, `chargeWithoutEvent()` — callable by any address with no access control — has no guard for either flag. Additionally, `handleKLAYTransfer()`, `handleERC20Transfer()`, and `handleERC721Transfer()` — the operator-callable outbound settlement functions — have no `isRunning` check. This means that when the bridge owner stops the bridge for emergency reasons, asset-moving state changes can still occur, making correct recovery difficult or impossible.

---

### Finding Description

**`BridgeTransfer.sol`** declares `isRunning = true` as the global stop flag: [1](#0-0) 

The request-side functions correctly enforce both guards. `_requestKLAYTransfer()` applies `unlockedKLAY` modifier and `require(isRunning, "stopped bridge")`: [2](#0-1) 

`_requestERC20Transfer()` and `_requestERC721Transfer()` similarly check `isRunning`: [3](#0-2) [4](#0-3) 

**Gap 1 — `chargeWithoutEvent()` has zero guards:**

```solidity
function chargeWithoutEvent() external payable {}
``` [5](#0-4) 

This function is `external payable` with no `isRunning`, no `isLockedKLAY`, and no `onlyOwner` / `onlyOperators` modifier. Any address can call it and deposit KLAY into the bridge contract regardless of the bridge's stopped or locked state.

**Gap 2 — `handleKLAYTransfer()`, `handleERC20Transfer()`, `handleERC721Transfer()` have no `isRunning` check:**

`handleKLAYTransfer()` is `public onlyOperators nonReentrant` but never checks `isRunning` or `isLockedKLAY`: [6](#0-5) 

`handleERC20Transfer()` is `public onlyOperators` with no `isRunning` check: [7](#0-6) 

`handleERC721Transfer()` is `public onlyOperators` with no `isRunning` check: [8](#0-7) 

These functions transfer KLAY, ERC20 tokens, or ERC721 tokens **out** of the bridge to `_to`, update `handleNoncesToBlockNums`, advance `lowerHandleNonce`, and emit `HandleValueTransfer` — all critical state mutations — without ever consulting `isRunning`.

---

### Impact Explanation

**`chargeWithoutEvent()` (unprivileged):** Any user can deposit KLAY into the bridge contract even when `isRunning = false` and `isLockedKLAY = true`. This changes the bridge's KLAY balance during a paused state, corrupting the accounting baseline that the bridge owner relies on for safe recovery. The deposited KLAY also increases the pool available for subsequent `handleKLAYTransfer` calls once the bridge is restarted, potentially enabling more outbound transfers than intended.

**`handleXXXTransfer()` (operator-level):** When `isRunning = false`, bridge operators can still call these functions to settle pending cross-chain requests, transferring KAIA and bridged ERC20/ERC721 assets out of the bridge. The `lowerHandleNonce`, `upperHandleNonce`, `handleNoncesToBlockNums`, and `recoveryBlockNumber` state variables are all mutated during a stopped state, making it impossible to cleanly restart the bridge from a known-good state. [9](#0-8) 

---

### Likelihood Explanation

- **`chargeWithoutEvent()`**: Reachable by any address with no preconditions. Likelihood is high whenever the bridge is stopped.
- **`handleXXXTransfer()`**: Reachable by registered bridge operators. Operators are semi-trusted relayers; a compromised or misbehaving operator can call these functions during an emergency stop.

---

### Recommendation

1. Add `require(isRunning, "stopped bridge")` and `require(!isLockedKLAY, "locked")` to `chargeWithoutEvent()`, or restrict it to `onlyOwner`.
2. Add `require(isRunning, "stopped bridge")` to `handleKLAYTransfer()`, `handleERC20Transfer()`, and `handleERC721Transfer()` so that the bridge stop flag applies symmetrically to both inbound and outbound settlement paths.
3. Audit all `external`/`public` functions in the bridge inheritance chain (`BridgeTransfer`, `BridgeTransferKLAY`, `BridgeTransferERC20`, `BridgeTransferERC721`, `BridgeFee`, `BridgeOperator`) to confirm that every state-mutating entry point is guarded by the appropriate stop flags.

---

### Proof of Concept

```
1. Owner calls bridge.setRunningStatus(false)  → isRunning = false
2. Owner calls bridge.lockKLAY()               → isLockedKLAY = true
   (Bridge is fully stopped and KLAY locked)

3. Attacker calls bridge.chargeWithoutEvent{value: 100 ether}()
   → Succeeds. Bridge KLAY balance increases by 100 ETH.
   → No revert. isRunning and isLockedKLAY are never checked.

4. Operator calls bridge.handleKLAYTransfer(txHash, from, to, 50 ether, nonce, blockNum, "")
   → Succeeds. 50 KLAY transferred to `to`.
   → lowerHandleNonce, handleNoncesToBlockNums, recoveryBlockNumber mutated.
   → isRunning is never checked.

Result: Bridge state (nonces, balances, recovery pointer) is corrupted during
the emergency stop window, making safe restart impossible.
``` [5](#0-4) [10](#0-9) [11](#0-10) [12](#0-11)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L28-28)
```text
    bool public isRunning = true;
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

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L137-139)
```text
    // chargeWithoutEvent sends KLAY to this contract without event for increasing
    // the withdrawal limit.
    function chargeWithoutEvent() external payable {}
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

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L81-85)
```text
        internal
        onlyRegisteredToken(_tokenAddress)
        onlyUnlockedToken(_tokenAddress)
    {
        require(isRunning, "stopped bridge");
```
