### Title
Missing Caller Validation in `onERC20Received` and `onERC721Received` Allows Unauthorized Cross-Chain Asset Drain — (`contracts/service_chain/bridge/BridgeTransferERC20.sol`, `contracts/service_chain/bridge/BridgeTransferERC721.sol`)

---

### Summary

`BridgeTransferERC20::onERC20Received` and `BridgeTransferERC721::onERC721Received` are `public` functions with no validation that the caller is the actual registered token contract. Any address that is registered as a token can call these functions directly — without depositing any tokens into the bridge — and emit a `RequestValueTransfer` event. Bridge operators on the counterpart chain will then execute a real asset transfer (release or mint), draining the counterpart bridge's reserves or causing unauthorized minting.

---

### Finding Description

`onERC20Received` is the 1-step deposit entry point: the token contract is supposed to transfer tokens to the bridge and then call this function. The bridge uses `msg.sender` as the token address and passes it directly to `_requestERC20Transfer`:

```solidity
// BridgeTransferERC20.sol line 111-121
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

`_requestERC20Transfer` applies `onlyRegisteredToken(_tokenAddress)` — meaning `msg.sender` must be a registered token — but it never verifies that tokens were actually transferred to the bridge before the call. The function then emits `RequestValueTransfer` unconditionally:

```solidity
// BridgeTransferERC20.sol line 76-108
function _requestERC20Transfer(...) internal onlyRegisteredToken(_tokenAddress) onlyUnlockedToken(_tokenAddress) {
    require(isRunning, "stopped bridge");
    require(_value > 0, "zero ERC20 token amount");
    uint256 fee = _payERC20FeeAndRefundChange(_from, _tokenAddress, _feeLimit);
    if (modeMintBurn) {
        ERC20Burnable(_tokenAddress).burn(_value);
    }
    emit RequestValueTransfer(...);
    requestNonce++;
}
```

The identical pattern exists in `BridgeTransferERC721::onERC721Received`:

```solidity
// BridgeTransferERC721.sol line 109-118
function onERC721Received(address _from, uint256 _tokenId, address _to, bytes memory _extraData) public {
    _requestERC721Transfer(msg.sender, _from, _to, _tokenId, _extraData);
}
```

`BridgeTokens::registerToken` is `onlyOwner`, so only the bridge owner can register tokens. However, the token contract itself (once registered) is a distinct, semi-trusted entity — it may be controlled by a token issuer who is not the bridge owner. That token contract can call `onERC20Received` directly without performing any actual token transfer.

---

### Impact Explanation

**Exact corrupted value:** The counterpart bridge's token reserves (lock-and-release mode) or its minting authority (mint-and-burn mode) are consumed without any corresponding deposit on the source chain.

**Lock-and-release mode (`modeMintBurn = false`):**
- `_payERC20FeeAndRefundChange` with `_feeLimit = 0` and zero fee returns 0 with no token movement.
- No burn is attempted.
- `RequestValueTransfer` is emitted with attacker-controlled `_from`, `_to`, `_value`.
- Bridge operators call `handleERC20Transfer` on the counterpart bridge, which executes `IERC20(_tokenAddress).safeTransfer(_to, _value)`, draining the counterpart bridge's token reserves.

**Mint-and-burn mode (`modeMintBurn = true`):**
- `ERC20Burnable(_tokenAddress).burn(_value)` is called on the attacker-controlled token contract. A malicious token contract can implement `burn` as a no-op.
- `RequestValueTransfer` is emitted.
- Bridge operators call `handleERC20Transfer` on the counterpart bridge, which calls `ERC20Mintable(_tokenAddress).mint(_to, _value)`, minting arbitrary tokens to the attacker with no upper bound.

---

### Likelihood Explanation

The trigger requires the attacker to call `onERC20Received` from a registered token contract address. Token registration is `onlyOwner`, but the token contract itself is a separate entity. In service-chain deployments, token contracts are often deployed and controlled by token issuers who are distinct from the bridge operator. A malicious or compromised token issuer can exploit this directly. No other privileged access is needed beyond holding a registered token contract.

---

### Recommendation

Add a check inside `onERC20Received` and `onERC721Received` that verifies the caller is the registered token contract AND that the bridge's token balance increased by at least `_value` in the same call (or use a reentrancy-safe balance-before/after check). At minimum, restrict the caller to the registered token:

```solidity
function onERC20Received(
    address _from,
    address _to,
    uint256 _value,
    uint256 _feeLimit,
    bytes memory _extraData
) public onlyRegisteredToken(msg.sender) {
    // Verify tokens were actually deposited
    // e.g., check balance increased by _value + _feeLimit
    _requestERC20Transfer(msg.sender, _from, _to, _value, _feeLimit, _extraData);
}
```

A balance-delta check (record balance before, assert balance after ≥ balance before + `_value + _feeLimit`) is the robust fix, analogous to the `msg.sender != address(token)` guard in the referenced Streamr report.

---

### Proof of Concept

```solidity
// Attacker controls MaliciousToken, which is registered on the bridge.
// MaliciousToken.burn() is a no-op.
// Attack (modeMintBurn = true):

contract MaliciousToken is IERC20, ERC20Mintable {
    function burn(uint256) public { /* no-op */ }

    function attack(address bridge, address victim, address counterpartReceiver) external {
        // Call onERC20Received directly — no tokens transferred to bridge
        IBridge(bridge).onERC20Received(
            victim,           // _from: blame the victim
            counterpartReceiver, // _to: attacker's address on counterpart chain
            1_000_000 ether,  // _value: arbitrary large amount
            0,                // _feeLimit: zero to avoid balance check in _payERC20FeeAndRefundChange
            ""
        );
        // RequestValueTransfer event emitted with value=1_000_000 ether
        // Bridge operators execute handleERC20Transfer on counterpart chain
        // Counterpart bridge mints 1_000_000 ether tokens to counterpartReceiver
    }
}
```

**Exact state change:** `requestNonce` increments on the source bridge; on the counterpart bridge, `handleERC20Transfer` mints (or transfers) `_value` tokens to `counterpartReceiver` — a net unauthorized asset creation with zero deposit on the source chain.

**Affected files:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** contracts/service_chain/bridge/BridgeTokens.sol (L32-35)
```text
    modifier onlyRegisteredToken(address _token) {
        require(registeredTokens[_token] != address(0), "not allowed token");
        _;
    }
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
