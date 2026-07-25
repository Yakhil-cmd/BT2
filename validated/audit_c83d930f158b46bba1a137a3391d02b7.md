### Title
Bridge ERC20 Deposit Does Not Verify Actual Received Amount for Fee-on-Transfer Tokens — (`contracts/service_chain/bridge/BridgeTransferERC20.sol`)

### Summary

`BridgeTransferERC20.requestERC20Transfer` and the `onERC20Received` 1-step path both record the caller-supplied `_value` as the bridged amount without measuring the bridge's actual token balance change. For fee-on-transfer (deflationary) ERC20 tokens, the bridge receives fewer tokens than `_value + _feeLimit` but emits a `RequestValueTransfer` event for the full `_value`, causing the counterpart bridge to release more tokens than were ever deposited.

### Finding Description

`requestERC20Transfer` (2-step path) calls `safeTransferFrom` for `_value + _feeLimit`: [1](#0-0) 

`SafeERC20.safeTransferFrom` only checks that the call did not revert and that the return value (if any) is not `false`. It does **not** verify the actual number of tokens credited to `address(this)`. For a fee-on-transfer token with a 1 % transfer tax, a deposit of `_value = 100, _feeLimit = 10` causes the bridge to receive only `108.9` tokens, yet the bridge records and emits `RequestValueTransfer` for the full `100`: [2](#0-1) 

The same gap exists in the 1-step path. `onERC20Received` is called by the token contract after it has already executed `transfer(bridge, _amount + _feeLimit)`. The bridge trusts the caller-supplied `_value` and `_feeLimit` without measuring the balance delta: [3](#0-2) 

`_payERC20FeeAndRefundChange` then pays the fee and any refund out of the bridge's balance using `safeTransfer`: [4](#0-3) 

These outflows succeed as long as the bridge has residual liquidity, masking the deficit until the bridge is drained.

On the counterpart chain, operators observe the `RequestValueTransfer` event carrying the full `_value` and call `handleERC20Transfer`, which releases the full `_value` to the recipient: [5](#0-4) 

### Impact Explanation

Each deposit of a fee-on-transfer token creates a shortfall equal to `(transfer_fee_rate) × (_value + _feeLimit)` tokens. The bridge on the source chain holds fewer tokens than it has committed to release on the counterpart chain. Repeated deposits accumulate the deficit until the bridge's liquidity pool is exhausted, at which point legitimate withdrawals on the counterpart chain fail or the bridge becomes permanently insolvent. This constitutes an unauthorized drain of system-managed bridged assets.

### Likelihood Explanation

The `onlyRegisteredToken` modifier requires the token to be registered by the bridge owner: [6](#0-5) 

A bridge owner who registers any fee-on-transfer ERC20 (a common token design) triggers the vulnerability. Any user who subsequently calls `requestERC20Transfer` or the 1-step `requestValueTransfer` on the token contract exploits it without any special privilege. The trigger is therefore reachable by ordinary users once a qualifying token is registered.

### Recommendation

Measure the actual balance delta around every inbound token transfer and use that delta — not the caller-supplied `_value` — as the canonical bridged amount:

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
    uint256 received = IERC20(_tokenAddress).balanceOf(address(this)).sub(balanceBefore);
    require(received == _value.add(_feeLimit), "fee-on-transfer token not supported");
    _requestERC20Transfer(_tokenAddress, msg.sender, _to, _value, _feeLimit, _extraData);
}
```

Alternatively, document explicitly that fee-on-transfer tokens are not supported and add a check in `registerToken` to reject them, or adjust `_value` to `received - _feeLimit` before emitting the event.

Apply the same fix to `onERC20Received` by comparing `balanceOf(address(this))` before and after the token's `transfer` call, or by requiring the token contract to pass the actual received amount.

### Proof of Concept

1. Bridge owner registers a fee-on-transfer ERC20 token `T` (1 % transfer tax) on both source and counterpart bridges.
2. Alice calls `bridge.requestERC20Transfer(T, bob, 100e18, 10e18, "")` on the source chain.
3. `safeTransferFrom` moves `110e18` from Alice; due to the 1 % tax, the bridge receives `108.9e18`.
4. `_payERC20FeeAndRefundChange` pays `fee = 5e18` to `feeReceiver` and refunds `5e18` to Alice; bridge now holds `98.9e18`.
5. `RequestValueTransfer` is emitted for `_value = 100e18`.
6. Operators on the counterpart chain call `handleERC20Transfer` for `100e18`; the counterpart bridge releases `100e18` to Bob.
7. Net: source bridge received `108.9e18`, paid out `10e18` (fee + refund) + `100e18` (counterpart release) = `110e18` worth of value — a deficit of `1.1e18` per transfer.
8. After ~90 such transfers the source bridge's liquidity is exhausted; all subsequent counterpart withdrawals revert.

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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L133-134)
```text
        IERC20(_tokenAddress).safeTransferFrom(msg.sender, address(this), _value.add(_feeLimit));
        _requestERC20Transfer(_tokenAddress, msg.sender, _to, _value, _feeLimit, _extraData);
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

**File:** contracts/service_chain/bridge/BridgeTokens.sol (L32-35)
```text
    modifier onlyRegisteredToken(address _token) {
        require(registeredTokens[_token] != address(0), "not allowed token");
        _;
    }
```
