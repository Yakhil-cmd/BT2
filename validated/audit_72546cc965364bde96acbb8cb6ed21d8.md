### Title
Missing Self-Address Validation in `requestKLAYTransfer`/`handleKLAYTransfer` Causes Permanent KLAY Lock — (File: `contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

---

### Summary

Neither `requestKLAYTransfer` nor `handleKLAYTransfer` in `BridgeTransferKLAY` validates that the `_to` recipient is not the bridge contract itself. When a user passes the destination bridge's address as `_to`, the KLAY is permanently locked in the source bridge: every operator attempt to execute `handleKLAYTransfer` on the destination chain reverts because the low-level KLAY send triggers the bridge's own payable fallback, which re-enters `_requestKLAYTransfer` and is blocked by the shared `nonReentrant` guard.

---

### Finding Description

`requestKLAYTransfer` is a public, unprivileged entry point that accepts any `_to` address:

```solidity
function requestKLAYTransfer(address _to, uint256 _value, bytes calldata _extraData) external payable {
    uint256 feeLimit = msg.value.sub(_value);
    _requestKLAYTransfer(_to, feeLimit, _extraData);
}
``` [1](#0-0) 

`_requestKLAYTransfer` contains no check that `_to != address(this)` (or the counterpart bridge address):

```solidity
function _requestKLAYTransfer(address _to, uint256 _feeLimit, bytes memory _extraData)
    internal
    unlockedKLAY
    nonReentrant
{
    require(isRunning, "stopped bridge");
    require(msg.value > _feeLimit, "insufficient amount");
    ...
    emit RequestValueTransfer(..., _to, ...);
    requestNonce++;
}
``` [2](#0-1) 

On the destination chain, `handleKLAYTransfer` delivers KLAY via a low-level call:

```solidity
(bool ok, ) = _to.call.value(_value)("");
require(ok, "handleKLAYTransfer: transfer failed");
``` [3](#0-2) 

The bridge's payable fallback immediately calls `_requestKLAYTransfer`, which carries `nonReentrant`:

```solidity
function () external payable {
    _requestKLAYTransfer(msg.sender, feeOfKLAY, new bytes(0));
}
``` [4](#0-3) 

`handleKLAYTransfer` itself also holds `nonReentrant`:

```solidity
function handleKLAYTransfer(...) public onlyOperators nonReentrant {
``` [5](#0-4) 

Because both functions share the same `ReentrancyGuard` lock (imported only into `BridgeTransferKLAY`), the fallback's call to `_requestKLAYTransfer` reverts. The revert propagates back through the low-level `call`, setting `ok = false`, which causes `require(ok, ...)` to revert the entire `handleKLAYTransfer` transaction — including all nonce and state updates. [6](#0-5) 

The same structural gap exists in `BridgeTransferERC20`: `requestERC20Transfer` and `handleERC20Transfer` accept any `_to` without a self-address check. In lock/unlock mode, `safeTransfer(_to, _value)` with `_to == address(this)` silently succeeds, depositing tokens back into the bridge's own balance and permanently orphaning the user's locked tokens on the source chain. [7](#0-6) 

---

### Impact Explanation

**KLAY path (hard revert / permanent lock):**
- The user's KLAY is deducted from their balance and held in the source bridge.
- Every operator call to `handleKLAYTransfer` on the destination chain reverts unconditionally.
- The request nonce is never marked handled; the KLAY can never be recovered.
- Affected asset: native KAIA locked in the service-chain bridge contract.

**ERC20 path (silent accounting corruption):**
- In lock/unlock mode: tokens are transferred to the bridge itself, inflating its apparent liquidity while the user's source-chain tokens are permanently locked.
- In mint/burn mode: tokens are minted to the bridge address, inflating the circulating supply on the destination chain with no corresponding user benefit.
- Affected asset: bridged ERC20 tokens.

---

### Likelihood Explanation

`requestKLAYTransfer` is a public, unprivileged function callable by any account. The destination bridge address is publicly known (registered on-chain and observable from bridge configuration). A user — whether malicious or simply mistaken — can pass the destination bridge address as `_to`. No special role, key, or majority-validator cooperation is required. The condition is reachable in normal production operation.

---

### Recommendation

Add a self-address guard at the earliest validation point in both the request and handle paths:

```solidity
// In _requestKLAYTransfer / requestERC20Transfer / onERC20Received:
require(_to != address(this), "Bridge: recipient cannot be the bridge itself");

// In handleKLAYTransfer / handleERC20Transfer:
require(_to != address(this), "Bridge: recipient cannot be the bridge itself");
```

The check on the request side prevents the malformed event from ever being emitted. The check on the handle side provides defense-in-depth for any event that reaches the destination chain with `_to == address(this)`.

---

### Proof of Concept

1. **Setup**: Source bridge `SB` on service chain; destination bridge `DB` on main chain. Both are `BridgeTransferKLAY` instances.

2. **Attacker action** (unprivileged): Call on the source chain:
   ```solidity
   SB.requestKLAYTransfer{value: 1 ether}(
       address(DB),   // _to = destination bridge address
       1 ether - fee,
       ""
   );
   ```
   Source bridge emits `RequestValueTransfer(..., _to=DB, ..., value=1 ether-fee, nonce=N, ...)` and locks the KLAY.

3. **Operator response**: Operators observe the event and call on the destination chain:
   ```solidity
   DB.handleKLAYTransfer(txHash, attacker, address(DB), 1 ether-fee, N, blockNum, "");
   ```

4. **Execution trace inside `handleKLAYTransfer`**:
   - Nonce check passes, votes pass, `_setHandledRequestTxHash` and `_updateHandleNonce` execute.
   - `(bool ok,) = address(DB).call{value: 1 ether-fee}("")` — sends KLAY to `DB` itself.
   - `DB`'s fallback fires: `_requestKLAYTransfer(msg.sender, feeOfKLAY, "")`.
   - `_requestKLAYTransfer` tries to acquire `nonReentrant` lock — **reverts** because `handleKLAYTransfer` holds it.
   - `ok = false` → `require(ok, "handleKLAYTransfer: transfer failed")` **reverts the entire transaction**.
   - All state changes (nonce update, tx hash record) are rolled back.

5. **Result**: Every subsequent operator attempt produces the same revert. The KLAY is permanently locked in `SB` with no recovery path. [8](#0-7) [9](#0-8) [10](#0-9)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L20-23)
```text
import "../../libs/openzeppelin-contracts-v2/contracts/utils/ReentrancyGuard.sol";


contract BridgeTransferKLAY is BridgeTransfer, ReentrancyGuard {
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L62-99)
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

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L127-129)
```text
    function () external payable {
        _requestKLAYTransfer(msg.sender, feeOfKLAY, new bytes(0));
    }
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L132-135)
```text
    function requestKLAYTransfer(address _to, uint256 _value, bytes calldata _extraData) external payable {
        uint256 feeLimit = msg.value.sub(_value);
        _requestKLAYTransfer(_to, feeLimit, _extraData);
    }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L32-72)
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
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L123-135)
```text
    // requestERC20Transfer requests transfer ERC20 to _to on relative chain.
    function requestERC20Transfer(
        address _tokenAddress,
        address _to,
        uint256 _value,
        uint256 _feeLimit,
        bytes memory _extraData
    )
        public
    {
        IERC20(_tokenAddress).safeTransferFrom(msg.sender, address(this), _value.add(_feeLimit));
        _requestERC20Transfer(_tokenAddress, msg.sender, _to, _value, _feeLimit, _extraData);
    }
```
