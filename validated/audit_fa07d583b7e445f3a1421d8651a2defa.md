### Title
Re-entrancy via Registered Token Callback Allows Fraudulent Bridge Requests with Corrupted `requestNonce` — (`contracts/service_chain/bridge/BridgeTransferERC721.sol`, `BridgeTransferERC20.sol`)

---

### Summary

`BridgeTransferERC721._requestERC721Transfer` and `BridgeTransferERC20._requestERC20Transfer` make external calls to registered token contracts **before** incrementing `requestNonce`, with no `nonReentrant` guard. A registered token whose `tokenURI` (ERC721) or `transfer` hook (ERC20) re-enters the bridge via `onERC721Received` / `onERC20Received` can inject additional `RequestValueTransfer*` events sharing or consuming nonces that were never backed by actual deposits. The counterpart bridge operators process every such event and mint or transfer bridged assets on the other chain, creating unbacked tokens.

---

### Finding Description

`BridgeTransferKLAY` explicitly imports `ReentrancyGuard` and marks both `_requestKLAYTransfer` and `handleKLAYTransfer` as `nonReentrant`. [1](#0-0) [2](#0-1) 

The developer even left an explicit comment in `BridgeFee.sol` acknowledging that `_payKLAYFeeAndRefundChange` requires its caller to be `nonReentrant`: [3](#0-2) 

Neither `BridgeTransferERC721` nor `BridgeTransferERC20` imports `ReentrancyGuard`, and none of their entry points (`requestERC721Transfer`, `onERC721Received`, `requestERC20Transfer`, `onERC20Received`) carry `nonReentrant`.

**ERC721 path — external call before nonce increment:**

Inside `_requestERC721Transfer`, after the `onlyRegisteredToken` check passes, a low-level call is made to the registered token to fetch its URI. This call does **not** revert on failure, so any re-entrancy it triggers continues silently: [4](#0-3) 

`requestNonce` is only incremented at line 105, **after** the external call at line 86.

`onERC721Received` has no access control beyond the `onlyRegisteredToken` check inside `_requestERC721Transfer`, which passes because `msg.sender` is the registered token: [5](#0-4) 

**ERC20 path — external call before nonce increment:**

`_requestERC20Transfer` calls `_payERC20FeeAndRefundChange` before `requestNonce++`. That function calls `IERC20(_token).safeTransfer(feeReceiver, fee)` and `IERC20(_token).safeTransfer(from, feeRefund)` — both external calls to the registered token — before the nonce is committed: [6](#0-5) [7](#0-6) 

`onERC20Received` similarly has no guard beyond `onlyRegisteredToken`: [8](#0-7) 

---

### Impact Explanation

During re-entrancy the inner call to `_requestERC721Transfer` / `_requestERC20Transfer` reads the **pre-increment** value of `requestNonce`, emits a `RequestValueTransferEncoded` / `RequestValueTransfer` event with that nonce, and increments it. The outer call then emits a second event with the next nonce value and increments again. The result is **two valid-looking bridge request events** for a single actual token deposit (or even zero deposit, if `onERC721Received` is called without a preceding `transferFrom`).

The counterpart bridge's Go-side handler (`handleRequestValueTransferEvent`) processes every such event and submits `HandleERC721Transfer` / `HandleERC20Transfer` transactions: [9](#0-8) 

Each processed nonce causes the counterpart bridge to mint or transfer tokens to the attacker's chosen `_to` address. The bridge's asset accounting is permanently corrupted: more tokens exist on the counterpart chain than were deposited on the source chain.

The corrupted values are:
- `requestNonce` — advanced by 2 (or more) per single deposit
- `RequestValueTransferEncoded` / `RequestValueTransfer` events — one or more are unbacked by real deposits
- Counterpart chain token balances — inflated by unauthorized mints/transfers

---

### Likelihood Explanation

The trigger requires a **registered** ERC721 or ERC20 token. Token registration is `onlyOwner`. However, the token's internal behavior after registration is not controlled by the bridge owner. Realistic scenarios:

1. A legitimate ERC721 token whose `tokenURI` delegates to an upgradeable on-chain metadata contract — if the metadata contract owner is different from the bridge owner, they can make it re-enter the bridge.
2. An ERC20 token with transfer hooks (ERC777-style or custom callback patterns) where the hook recipient is attacker-controlled.
3. A token that is legitimate at registration time but whose ownership is later transferred to an attacker.

The `onERC721Received` and `onERC20Received` entry points are fully public with no caller whitelist, so once re-entrancy is triggered from within the registered token's callback, the bridge cannot distinguish it from a legitimate 1-step deposit.

---

### Recommendation

1. Add `ReentrancyGuard` to `BridgeTransferERC20` and `BridgeTransferERC721` (as already done for `BridgeTransferKLAY`).
2. Apply `nonReentrant` to `requestERC20Transfer`, `onERC20Received`, `requestERC721Transfer`, and `onERC721Received`.
3. Alternatively, follow the checks-effects-interactions pattern: increment `requestNonce` **before** any external call to the token contract.

---

### Proof of Concept

**Setup:** Deploy `Bridge` with `modeMintBurn = false`. Register `MaliciousNFT` (controlled by attacker). Attacker holds `tokenId = 1` and `tokenId = 2`.

**`MaliciousNFT.tokenURI(uint256 tokenId)`** implementation:
```solidity
function tokenURI(uint256 tokenId) public view returns (string memory) {
    if (!reentered) {
        reentered = true;
        // Re-enter bridge via 1-step deposit path — no actual transferFrom needed
        IBridge(bridge).onERC721Received(attacker, 2, victim, "");
    }
    return "uri";
}
```

**Attack sequence:**
1. Attacker approves bridge for `tokenId = 1`.
2. Attacker calls `bridge.requestERC721Transfer(maliciousNFT, victim, 1, "")`.
3. Bridge calls `IERC721(maliciousNFT).transferFrom(attacker, bridge, 1)` — `tokenId 1` deposited.
4. Bridge calls `_requestERC721Transfer(maliciousNFT, attacker, victim, 1, "")`.
5. `onlyRegisteredToken` passes. `requestNonce = 0`.
6. Bridge calls `maliciousNFT.call(tokenURI selector, 1)`.
7. `tokenURI` calls `bridge.onERC721Received(attacker, 2, victim, "")`.
8. Bridge calls `_requestERC721Transfer(maliciousNFT, attacker, victim, 2, "")`.
9. `onlyRegisteredToken` passes (`msg.sender = maliciousNFT`). `requestNonce = 0` (not yet incremented).
10. Inner call emits `RequestValueTransferEncoded(ERC721, attacker, victim, maliciousNFT, tokenId=2, nonce=0, ...)`.
11. `requestNonce++` → `requestNonce = 1`. Returns.
12. Outer call emits `RequestValueTransferEncoded(ERC721, attacker, victim, maliciousNFT, tokenId=1, nonce=1, ...)`.
13. `requestNonce++` → `requestNonce = 2`.

**Result:** Two bridge request events (nonces 0 and 1) for `tokenId 2` and `tokenId 1`. Only `tokenId 1` was actually deposited. The counterpart bridge operators call `handleERC721Transfer` for both nonces, minting `tokenId 2` to `victim` on the counterpart chain with no backing deposit. The attacker obtains a free bridged NFT. [10](#0-9) [5](#0-4) [2](#0-1)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L20-23)
```text
import "../../libs/openzeppelin-contracts-v2/contracts/utils/ReentrancyGuard.sol";


contract BridgeTransferKLAY is BridgeTransfer, ReentrancyGuard {
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L103-107)
```text
    function _requestKLAYTransfer(address _to, uint256 _feeLimit,  bytes memory _extraData)
        internal
        unlockedKLAY
        nonReentrant
    {
```

**File:** contracts/service_chain/bridge/BridgeFee.sol (L41-43)
```text
    // Caller of this function must be nonReentrant.
    // - BridgeTransferKLAY._requestKLAYTransfer() is nonReentrant
    function _payKLAYFeeAndRefundChange(uint256 _feeLimit) internal returns(uint256) {
```

**File:** contracts/service_chain/bridge/BridgeFee.sol (L68-88)
```text
    function _payERC20FeeAndRefundChange(address from, address _token, uint256 _feeLimit) internal returns(uint256) {
        uint256 fee = feeOfERC20[_token];

        if (feeReceiver != address(0) && fee > 0) {
            require(_feeLimit >= fee, "insufficient feeLimit");

            IERC20(_token).safeTransfer(feeReceiver, fee);

            uint256 feeRefund = _feeLimit.sub(fee);
            if (feeRefund > 0) {
                IERC20(_token).safeTransfer(from, feeRefund);
            }

            return fee;
        }

        if (_feeLimit > 0) {
            IERC20(_token).safeTransfer(from, _feeLimit);
        }
        return 0;
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

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L109-118)
```text
    function onERC721Received(
        address _from,
        uint256 _tokenId,
        address _to,
        bytes memory _extraData
    )
        public
    {
        _requestERC721Transfer(msg.sender, _from, _to, _tokenId, _extraData);
    }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L91-107)
```text
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
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L111-121)
```text
    function onERC20Received(
        address _from,
        address _to,
        uint256 _value,
        uint256 _feeLimit,
        bytes memory _extraData
    )
        public
    {
        _requestERC20Transfer(msg.sender, _from, _to, _value, _feeLimit, _extraData);
    }
```

**File:** node/sc/bridge_manager.go (L331-354)
```go
	switch tokenType {
	case KAIA:
		handleTx, err = bi.bridge.HandleKLAYTransfer(auth, txHash, from, to, valueOrTokenId, requestNonce, blkNumber, extraData)
		if err != nil {
			return err
		}
		handleValueTransferLog(bi.onChildChain, handleVTmethods[KAIA], handleTx.Hash().String(), requestNonce, from, to, valueOrTokenId)
	case ERC20:
		handleTx, err = bi.bridge.HandleERC20Transfer(auth, txHash, from, to, ctpartTokenAddr, valueOrTokenId, requestNonce, blkNumber, extraData)
		if err != nil {
			return err
		}
		handleValueTransferLog(bi.onChildChain, handleVTmethods[ERC20], handleTx.Hash().String(), requestNonce, from, to, valueOrTokenId)
	case ERC721:
		uri := GetURI(ev)
		handleTx, err = bi.bridge.HandleERC721Transfer(auth, txHash, from, to, ctpartTokenAddr, valueOrTokenId, requestNonce, blkNumber, uri, extraData)
		if err != nil {
			return err
		}
		handleValueTransferLog(bi.onChildChain, handleVTmethods[ERC721], handleTx.Hash().String(), requestNonce, from, to, valueOrTokenId)
	default:
		logger.Error("Got Unknown Token Type ReceivedEvent", "bridge", contractAddr, "nonce", requestNonce, "from", from)
		return nil
	}
```
