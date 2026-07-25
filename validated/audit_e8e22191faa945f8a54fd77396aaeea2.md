### Title
Deflationary/Fee-on-Transfer Token Accounting Discrepancy in `requestERC20Transfer` Overcredits Bridge Counterpart — (`contracts/service_chain/bridge/BridgeTransferERC20.sol`)

### Summary

`BridgeTransferERC20.requestERC20Transfer` pulls `_value + _feeLimit` from the caller via `safeTransferFrom`, then unconditionally emits `RequestValueTransfer` with the caller-supplied `_value`. For fee-on-transfer (deflationary) tokens, the bridge receives fewer tokens than `_value + _feeLimit`, yet the event records the full `_value`. The counterpart bridge reads this event and releases `_value` tokens to the recipient, draining reserves that were never fully deposited.

### Finding Description

In `requestERC20Transfer` (lock mode):

```solidity
// BridgeTransferERC20.sol L133-134
IERC20(_tokenAddress).safeTransferFrom(msg.sender, address(this), _value.add(_feeLimit));
_requestERC20Transfer(_tokenAddress, msg.sender, _to, _value, _feeLimit, _extraData);
```

`safeTransferFrom` is called with `_value + _feeLimit`, but for a deflationary token the bridge actually receives `(_value + _feeLimit) × (1 − r)` where `r` is the token's internal transfer fee rate. The function then calls `_requestERC20Transfer`, which:

1. Calls `_payERC20FeeAndRefundChange` — attempts to send `fee` to `feeReceiver` and `feeLimit − fee` back to the user from the bridge's balance (which is already short by `r × (_value + _feeLimit)`).
2. Emits `RequestValueTransfer` with the original `_value`:

```solidity
// BridgeTransferERC20.sol L97-106
emit RequestValueTransfer(
    TokenType.ERC20,
    _from,
    _to,
    _tokenAddress,
    _value,          // ← caller-supplied, not actual received amount
    requestNonce,
    fee,
    _extraData
);
```

The counterpart bridge's operator calls `handleERC20Transfer` with this `_value`, which in lock mode executes:

```solidity
// BridgeTransferERC20.sol L71
IERC20(_tokenAddress).safeTransfer(_to, _value);
```

releasing the full `_value` to the recipient even though the source bridge only ever held `_value × (1 − r)` (approximately, after fee/refund accounting).

The same flaw exists in the 1-step path `onERC20Received` (line 120): the token contract calls `onERC20Received` with a `_value` it claims to have transferred; if deflationary, the bridge receives less but the event still records `_value`.

There is no balance-before/balance-after check anywhere in this path. The `onlyRegisteredToken` modifier in `BridgeTokens.sol` only verifies the token is registered — it does not enforce any non-deflationary property:

```solidity
// BridgeTokens.sol L32-35
modifier onlyRegisteredToken(address _token) {
    require(registeredTokens[_token] != address(0), "not allowed token");
    _;
}
```

### Impact Explanation

In lock mode, each `requestERC20Transfer` call with a deflationary token leaves the source bridge holding fewer tokens than the amount committed in the `RequestValueTransfer` event. The counterpart bridge releases the full committed amount. Over repeated transfers, the source bridge's token reserves are progressively undercollateralized. A user (or attacker) who deposits a deflationary token and receives full-value vouchers on the counterpart chain can withdraw more tokens than were ever locked, effectively stealing from other depositors — identical to the Gravity bridge finding.

### Likelihood Explanation

The trigger is any registered deflationary ERC20 token. Token registration is owner-controlled, but the contract imposes no technical barrier against registering such tokens. Any user can call `requestERC20Transfer` permissionlessly once a deflationary token is registered. The 1-step path (`onERC20Received`) is callable by the token contract itself, requiring no additional approval step.

### Recommendation

Measure the actual received amount using a balance snapshot before and after `safeTransferFrom`, and use the delta as the canonical value passed to `_requestERC20Transfer` and emitted in `RequestValueTransfer`:

```solidity
function requestERC20Transfer(
    address _tokenAddress,
    address _to,
    uint256 _value,
    uint256 _feeLimit,
    bytes memory _extraData
) public {
    uint256 balanceBefore = IERC20(_tokenAddress).balanceOf(address(this));
    IERC20(_tokenAddress).safeTransferFrom(msg.sender, address(this), _value.add(_feeLimit));
    uint256 actualReceived = IERC20(_tokenAddress).balanceOf(address(this)).sub(balanceBefore);
    // derive actual _value from actualReceived minus feeLimit portion
    _requestERC20Transfer(_tokenAddress, msg.sender, _to, actualReceived.sub(_feeLimit), _feeLimit, _extraData);
}
```

Apply the same pattern to `onERC20Received`.

### Proof of Concept

1. Owner registers a deflationary ERC20 token `T` (2% transfer fee) on both source and counterpart bridges.
2. Alice calls `requestERC20Transfer(T, Bob, 1000, 0, "")` on the source bridge.
3. `safeTransferFrom` pulls 1000 T from Alice; due to the 2% fee, the bridge receives 980 T.
4. `_requestERC20Transfer` emits `RequestValueTransfer` with `_value = 1000`.
5. Bridge operator observes the event and calls `handleERC20Transfer(..., 1000, ...)` on the counterpart bridge.
6. Counterpart bridge executes `safeTransfer(Bob, 1000)`, releasing 1000 T to Bob.
7. Source bridge holds 980 T but has committed 1000 T — a 20 T deficit per transfer.
8. Repeated deposits by multiple users progressively drain the source bridge's reserves until it cannot honor legitimate withdrawals.

---

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L68-72)
```text
        if (modeMintBurn) {
            require(ERC20Mintable(_tokenAddress).mint(_to, _value), "handleERC20Transfer: mint failed");
        } else {
            IERC20(_tokenAddress).safeTransfer(_to, _value);
        }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L97-107)
```text
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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L124-135)
```text
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

**File:** contracts/service_chain/bridge/BridgeTokens.sol (L32-35)
```text
    modifier onlyRegisteredToken(address _token) {
        require(registeredTokens[_token] != address(0), "not allowed token");
        _;
    }
```
