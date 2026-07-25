### Title
Unauthenticated `onERC20Received`/`onERC721Received` Allows Fake Bridge Transfer Requests Without Token Deposit — (File: `contracts/service_chain/bridge/BridgeTransferERC20.sol`, `contracts/service_chain/bridge/BridgeTransferERC721.sol`)

---

### Summary

The bridge contracts expose two public entry points for initiating a cross-chain value transfer. The "2-step" path (`requestERC20Transfer` / `requestERC721Transfer`) first pulls tokens from the caller into the bridge, then emits the request event. The "1-step" callback path (`onERC20Received` / `onERC721Received`) is designed to be invoked by the token contract after a transfer, but it is `public` with no caller authentication beyond `onlyRegisteredToken(msg.sender)`. Any account that controls a registered token contract address can call these callbacks directly—without depositing any tokens—causing the bridge to emit a `RequestValueTransfer` event. Bridge operators will then execute the corresponding `handleERC20Transfer` / `handleERC721Transfer` on the counterpart chain, draining the counterpart bridge's reserves or minting new tokens, with no corresponding deposit on the source chain.

---

### Finding Description

**Two entry points, one missing guard.**

In `BridgeTransferERC20.sol`:

```
requestERC20Transfer (public)
  → IERC20.safeTransferFrom(msg.sender, bridge, value+feeLimit)   ← tokens actually deposited
  → _requestERC20Transfer(tokenAddress, msg.sender, ...)           ← event emitted

onERC20Received (public)
  → _requestERC20Transfer(msg.sender, _from, ...)                  ← event emitted, NO deposit
``` [1](#0-0) [2](#0-1) 

The internal `_requestERC20Transfer` carries `onlyRegisteredToken(_tokenAddress)` and `onlyUnlockedToken(_tokenAddress)` modifiers, but these only verify that `msg.sender` is a registered, unlocked token address. They do **not** verify that any tokens were actually transferred into the bridge before the event fires. [3](#0-2) 

The identical structural gap exists in `BridgeTransferERC721.sol`:

```
requestERC721Transfer (public)
  → IERC721.transferFrom(msg.sender, bridge, tokenId)   ← token deposited
  → _requestERC721Transfer(tokenAddress, msg.sender, ...)

onERC721Received (public)
  → _requestERC721Transfer(msg.sender, _from, ...)       ← NO deposit
``` [4](#0-3) 

**Analog to ERC721F.** Just as `safeTransferFrom` in ERC721F bypassed the overridden `transferFrom`'s access list by calling `_safeTransfer` directly, `onERC20Received`/`onERC721Received` in Kaia's bridge bypass the token-deposit invariant enforced by `requestERC20Transfer`/`requestERC721Transfer`. Both cases share the same root cause: a second public entry point reaches the same state-changing internal function without passing through the guarded path.

**Fee guard analysis.** `_requestERC20Transfer` calls `_payERC20FeeAndRefundChange` before emitting the event. When the configured fee is 0 and `_feeLimit = 0`, this call performs no token movement and succeeds unconditionally. An attacker who controls the token contract can also make the token's `transfer`/`burn` calls return success regardless of actual balances, removing even this partial barrier. [5](#0-4) 

For ERC721 in `modeMintBurn = false` mode, `_requestERC721Transfer` performs no token movement at all before emitting the event—only a `tokenURI` call (which can be made to succeed trivially) and an optional `burn` (skipped in lock/unlock mode). [6](#0-5) 

---

### Impact Explanation

An attacker controlling a registered token contract can:

1. Call `bridge.onERC20Received(victim, recipient, amount, 0, "")` from the malicious token contract (fee = 0, feeLimit = 0).
2. `onlyRegisteredToken(msg.sender)` passes; `_requestERC20Transfer` runs; `RequestValueTransfer` is emitted with `requestNonce++`.
3. Bridge operators observe the event and call `handleERC20Transfer` on the counterpart bridge.
4. **`modeMintBurn = false` (lock/unlock):** `IERC20(_tokenAddress).safeTransfer(_to, _value)` drains real tokens from the counterpart bridge to the attacker-chosen recipient—no tokens were ever deposited on the source chain.
5. **`modeMintBurn = true` (mint/burn):** `ERC20Mintable(_tokenAddress).mint(_to, _value)` mints new tokens on the counterpart chain; the attacker-controlled source token

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L75-108)
```text
    // _requestERC20Transfer requests transfer ERC20 to _to on relative chain.
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

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L108-131)
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
