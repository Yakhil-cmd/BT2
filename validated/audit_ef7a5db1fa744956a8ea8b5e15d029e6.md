### Title
Missing `nonReentrant` Guard on ERC20/ERC721 Bridge Transfer Functions Enables Double-Minting of Bridged Assets — (`contracts/service_chain/bridge/BridgeTransferERC20.sol`, `BridgeTransferERC721.sol`)

---

### Summary

`BridgeTransferKLAY` protects both its handle and request functions with `nonReentrant`, and `BridgeFee.sol` explicitly documents that `_payKLAYFeeAndRefundChange` requires its caller to be `nonReentrant`. The analogous ERC20 and ERC721 bridge functions — `handleERC20Transfer`, `requestERC20Transfer`, `handleERC721Transfer`, and `requestERC721Transfer` — carry no such guard. A registered ERC-20-compatible token that issues a callback to the bridge during a transfer (e.g., an ERC-777 token or a token implementing the Kaia 1-step deposit callback) can re-enter `requestERC20Transfer` or trigger `onERC20Received` a second time within the same call, causing two `RequestValueTransfer` events to be emitted for a single token deposit. Bridge operators on the counterpart chain process both events and mint or release double the bridged assets.

---

### Finding Description

**Inconsistency in reentrancy protection:**

`BridgeTransferKLAY` inherits `ReentrancyGuard` and marks both `handleKLAYTransfer` and `_requestKLAYTransfer` as `nonReentrant`. [1](#0-0) [2](#0-1) [3](#0-2) 

`BridgeFee.sol` explicitly documents this requirement: [4](#0-3) 

`BridgeTransferERC20` and `BridgeTransferERC721` do **not** inherit `ReentrancyGuard` and apply no `nonReentrant` modifier to any of their public/external functions: [5](#0-4) [6](#0-5) 

**Vulnerable call sequence in `requestERC20Transfer`:**

```solidity
function requestERC20Transfer(...) public {
    IERC20(_tokenAddress).safeTransferFrom(msg.sender, address(this), _value.add(_feeLimit)); // ← external call
    _requestERC20Transfer(_tokenAddress, msg.sender, _to, _value, _feeLimit, _extraData);
}
``` [7](#0-6) 

`_requestERC20Transfer` then calls `_payERC20FeeAndRefundChange`, which makes further external `safeTransfer` calls, and only increments `requestNonce` **after** all external calls complete: [8](#0-7) [9](#0-8) 

The bridge also exposes `onERC20Received`, callable by any registered token, which directly invokes `_requestERC20Transfer`: [10](#0-9) 

**Vulnerable call sequence in `_requestERC721Transfer`:**

An unguarded external call to `_tokenAddress.call(...)` is made before `requestNonce` is incremented: [11](#0-10) 

---

### Impact Explanation

A registered token that calls `onERC20Received` on the bridge during a `safeTransferFrom` (e.g., a token implementing the Kaia 1-step deposit callback in its `transferFrom` logic) causes the following:

1. Attacker calls `requestERC20Transfer(token, to, value, 0, data)`.
2. Bridge calls `token.safeTransferFrom(attacker, bridge, value)` — tokens are deposited once.
3. Token calls `bridge.onERC20Received(attacker, to, value, 0, data)` as a transfer callback.
4. `_requestERC20Transfer` runs: emits `RequestValueTransfer` with `requestNonce = N`; increments to `N+1`.
5. Control returns to `requestERC20Transfer`; `_requestERC20Transfer` runs again: emits `RequestValueTransfer` with `requestNonce = N+1`; increments to `N+2`.

Two valid `RequestValueTransfer` events with consecutive nonces are emitted for a single deposit. Bridge operators on the counterpart chain call `handleERC20Transfer` (or `handleKLAYTransfer`) for both nonces, minting or releasing `2 × value` tokens while the bridge only received `value` tokens. The attacker gains `value` bridged tokens at no cost.

The same structural flaw applies to `handleERC20Transfer`: state is committed before the external `safeTransfer`/`mint` call, but without a mutex, a callback from `_to` can invoke other unguarded bridge entry points within the same transaction. [12](#0-11) 

---

### Likelihood Explanation

- Requires a registered ERC-20-compatible token that issues a callback to the bridge during transfer. Token registration is owner-controlled, but legitimate ERC-777 tokens and tokens implementing the Kaia 1-step deposit interface are natural candidates.
- The 1-step deposit path (`onERC20Received`) is an explicitly supported and documented feature of the bridge, making the callback pattern expected and realistic.
- No special privileges are required for the attacker beyond holding tokens and having them approved.
- The inconsistency is self-documented: `BridgeFee.sol` acknowledges the reentrancy risk for KLAY but provides no equivalent protection for ERC20.

---

### Recommendation

1. Have `BridgeTransferERC20` and `BridgeTransferERC721` inherit `ReentrancyGuard` and apply `nonReentrant` to `handleERC20Transfer`, `requestERC20Transfer`, `onERC20Received`, `handleERC721Transfer`, `requestERC721Transfer`, and `onERC721Received` — mirroring the protection already applied in `BridgeTransferKLAY`.
2. In `_requestERC20Transfer` and `_requestERC721Transfer`, increment `requestNonce` **before** any external call (checks-effects-interactions pattern).
3. Add the same comment to `_payERC20FeeAndRefundChange` that exists on `_payKLAYFeeAndRefundChange`: callers must be `nonReentrant`.

---

### Proof of Concept

```
Attacker deploys MaliciousToken (registered ERC-20 on bridge, implements 1-step callback):
  transferFrom(from, bridge, amount) {
      // standard transfer logic
      bridge.onERC20Received(from, attackerTo, amount, 0, data);  // callback
  }

Attack:
  1. attacker.approve(bridge, value)
  2. bridge.requestERC20Transfer(MaliciousToken, attackerTo, value, 0, data)
     → MaliciousToken.safeTransferFrom(attacker, bridge, value)
       → bridge.onERC20Received(attacker, attackerTo, value, 0, data)
         → _requestERC20Transfer: emit RequestValueTransfer(nonce=N); requestNonce=N+1
       ← returns
     ← safeTransferFrom returns
     → _requestERC20Transfer: emit RequestValueTransfer(nonce=N+1); requestNonce=N+2
  3. Bridge operators see nonces N and N+1, both valid, both processed.
  4. Counterpart chain mints 2×value tokens to attackerTo.
  5. Net gain: value tokens for zero additional cost.
```

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L23-23)
```text
contract BridgeTransferKLAY is BridgeTransfer, ReentrancyGuard {
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L62-73)
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
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L102-106)
```text
    // _requestKLAYTransfer requests transfer KLAY to _to on relative chain.
    function _requestKLAYTransfer(address _to, uint256 _feeLimit,  bytes memory _extraData)
        internal
        unlockedKLAY
        nonReentrant
```

**File:** contracts/service_chain/bridge/BridgeFee.sol (L41-42)
```text
    // Caller of this function must be nonReentrant.
    // - BridgeTransferKLAY._requestKLAYTransfer() is nonReentrant
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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L28-44)
```text
contract BridgeTransferERC20 is BridgeTokens, IERC20BridgeReceiver, BridgeTransfer {
    using SafeERC20 for IERC20;

    // handleERC20Transfer sends the token by the request.
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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L68-72)
```text
        if (modeMintBurn) {
            require(ERC20Mintable(_tokenAddress).mint(_to, _value), "handleERC20Transfer: mint failed");
        } else {
            IERC20(_tokenAddress).safeTransfer(_to, _value);
        }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L91-108)
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
    }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L110-121)
```text
    // onERC20Received function of ERC20 token for 1-step deposits to the Bridge.
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

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L27-41)
```text
contract BridgeTransferERC721 is BridgeTokens, IERC721BridgeReceiver, BridgeTransfer {
    // handleERC721Transfer sends the ERC721 by the request.
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
```

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L84-106)
```text
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
