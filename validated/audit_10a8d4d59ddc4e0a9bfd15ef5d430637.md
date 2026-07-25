### Title
Missing Reentrancy Guard on ERC20/ERC721 Bridge Request Functions Allows Duplicate Cross-Chain Transfer Requests — (`contracts/service_chain/bridge/BridgeTransferERC20.sol`, `contracts/service_chain/bridge/BridgeTransferERC721.sol`)

---

### Summary

`requestERC20Transfer` and `requestERC721Transfer` make external calls to the token contract **before** incrementing `requestNonce`. The public `onERC20Received` / `onERC721Received` callbacks have no access control and no reentrancy guard. A registered ERC20/ERC721 token whose `transferFrom` (or `tokenURI`) implementation calls back into the bridge can cause two `RequestValueTransfer` events to be emitted with consecutive nonces for a single on-chain deposit. The counterpart bridge processes both events and releases 2× the value, draining bridged assets.

---

### Finding Description

`BridgeTransferKLAY._requestKLAYTransfer` and `handleKLAYTransfer` are both decorated with `nonReentrant`. The ERC20 and ERC721 equivalents are not.

**`requestERC20Transfer` (BridgeTransferERC20.sol line 124–135):**

```solidity
function requestERC20Transfer(...) public {
    IERC20(_tokenAddress).safeTransferFrom(msg.sender, address(this), _value.add(_feeLimit)); // ← external call
    _requestERC20Transfer(_tokenAddress, msg.sender, _to, _value, _feeLimit, _extraData);     // ← requestNonce++ happens here
}
```

Inside `_requestERC20Transfer` (lines 76–108), additional external calls occur before `requestNonce++`:

```solidity
uint256 fee = _payERC20FeeAndRefundChange(_from, _tokenAddress, _feeLimit); // ← safeTransfer to feeReceiver / from
if (modeMintBurn) { ERC20Burnable(_tokenAddress).burn(_value); }            // ← external call
emit RequestValueTransfer(..., requestNonce, ...);
requestNonce++;   // ← state update last
```

`onERC20Received` is `public` with no guard:

```solidity
function onERC20Received(address _from, address _to, uint256 _value, uint256 _feeLimit, bytes memory _extraData) public {
    _requestERC20Transfer(msg.sender, _from, _to, _value, _feeLimit, _extraData);
}
```

**Attack path (fee = 0, non-mintBurn mode, `requestNonce = N`):**

1. Attacker calls `requestERC20Transfer(maliciousToken, to, value, 0, data)`.
2. Bridge calls `maliciousToken.transferFrom(attacker, bridge, value)`.
3. `maliciousToken.transferFrom` updates balances (bridge now holds `value` tokens), then calls back `bridge.onERC20Received(attacker, to, value, 0, data)`.
4. Bridge re-enters `_requestERC20Transfer`; emits `RequestValueTransfer` with nonce **N**; `requestNonce` → N+1.
5. `transferFrom` returns; bridge calls `_requestERC20Transfer` again; emits `RequestValueTransfer` with nonce **N+1**; `requestNonce` → N+2.
6. Counterpart bridge operators handle both events, releasing `2 × value` tokens to `to`.

The same pattern applies to `requestERC721Transfer` / `_requestERC721Transfer` / `onERC721Received`.

---

### Impact Explanation

The counterpart bridge's `handleERC20Transfer` / `handleERC721Transfer` treats each nonce as an independent, valid transfer request. Both nonces (N and N+1) pass `_lowerHandleNonceCheck`, `_voteValueTransfer`, and `_updateHandleNonce`. The bridge releases `2 × value` bridged tokens while only `value` tokens were deposited on the source side. This is an **unauthorized transfer of bridged assets** from the counterpart bridge's reserve.

---

### Likelihood Explanation

The trigger requires a registered ERC20/ERC721 token whose `transferFrom` (or `tokenURI` / `burn`) implementation calls back into `onERC20Received` / `onERC721Received`. Token registration is owner-controlled, so the attacker must either:

- Convince the owner to register a malicious token, or
- Exploit a legitimate token that has unexpected callback behavior (e.g., ERC-777 hooks, fee-on-transfer with receiver callbacks, or a token that mirrors the `ERC20ServiceChain.requestValueTransfer` pattern inside `transferFrom`).

The inconsistency is telling: KLAY request and handle functions carry `nonReentrant`; ERC20/ERC721 request functions do not, despite making multiple external calls to the same token contract before updating shared state.

---

### Recommendation

1. Add `nonReentrant` to `requestERC20Transfer`, `requestERC721Transfer`, `onERC20Received`, and `onERC721Received`.
2. Follow the Checks-Effects-Interactions pattern: increment `requestNonce` **before** any external call in `_requestERC20Transfer` and `_requestERC721Transfer`.
3. Restrict `onERC20Received` / `onERC721Received` to `onlyRegisteredToken` (already enforced inside `_requestERC20Transfer`, but the outer function should also gate on `msg.sender`).

---

### Proof of Concept

```solidity
// MaliciousERC20: registered on the bridge by owner
contract MaliciousERC20 is ERC20 {
    address public bridge;
    constructor(address _bridge) { bridge = _bridge; }

    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        // 1. Update balances normally
        _transfer(from, to, amount);
        // 2. Re-enter bridge before requestNonce is incremented
        IERC20BridgeReceiver(bridge).onERC20Received(
            from, targetAddress, amount, 0, ""
        );
        return true;
    }
}

// Attack:
// 1. Deploy MaliciousERC20, get it registered on the bridge.
// 2. Call bridge.requestERC20Transfer(maliciousToken, victim, value, 0, "").
// 3. Two RequestValueTransfer events emitted (nonces N, N+1).
// 4. Counterpart bridge operators handle both → 2×value released.
```

**Affected files:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L76-108)
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
        require(_value > 0, "zero ERC20 token amount");

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

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L73-106)
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

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L108-118)
```text
    // onERC721Received function of ERC721 token for 1-step deposits to the Bridge
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

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L120-131)
```text
    // requestERC721Transfer requests transfer ERC721 to _to on relative chain.
    function requestERC721Transfer(
        address _tokenAddress,
        address _to,
        uint256 _tokenId,
        bytes memory _extraData
    )
        public
    {
        IERC721(_tokenAddress).transferFrom(msg.sender, address(this), _tokenId);
        _requestERC721Transfer(_tokenAddress, msg.sender, _to, _tokenId, _extraData);
    }
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L102-107)
```text
    // _requestKLAYTransfer requests transfer KLAY to _to on relative chain.
    function _requestKLAYTransfer(address _to, uint256 _feeLimit,  bytes memory _extraData)
        internal
        unlockedKLAY
        nonReentrant
    {
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
