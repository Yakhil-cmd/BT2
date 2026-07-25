### Title
Bridge ERC20 Transfer Incompatible with Fee-on-Transfer Tokens — Undercollateralization and Asset Loss - (`contracts/service_chain/bridge/BridgeTransferERC20.sol`)

---

### Summary

The Kaia service-chain bridge's `requestERC20Transfer` and `handleERC20Transfer` functions do not account for the token's own transfer fee when the registered ERC20 is a fee-on-transfer (FOT) token. The bridge records and relays the nominal `_value` to the counterpart chain, but actually holds fewer tokens than that amount, making the bridge undercollateralized and causing asset loss for users and the bridge's liquidity pool.

---

### Finding Description

**`requestERC20Transfer` — source-chain deposit path** [1](#0-0) 

```solidity
IERC20(_tokenAddress).safeTransferFrom(msg.sender, address(this), _value.add(_feeLimit));
_requestERC20Transfer(_tokenAddress, msg.sender, _to, _value, _feeLimit, _extraData);
```

With a FOT token, `safeTransferFrom` causes the token contract to deduct its own transfer fee, so the bridge receives only `(_value + _feeLimit) × (1 − feeRate)` — strictly less than `_value + _feeLimit`. The code then proceeds to call `_payERC20FeeAndRefundChange`, which attempts to transfer the bridge's configured `fee` to `feeReceiver` and refund the remainder to the caller: [2](#0-1) 

Each of those outbound `safeTransfer` calls also incurs the token's own fee, further draining the bridge's balance. After all transfers, the bridge holds far less than `_value` tokens, yet the `RequestValueTransfer` event emits the full nominal `_value`: [3](#0-2) 

The counterpart bridge's operators observe this event and call `handleERC20Transfer` with the same `_value`, minting or transferring the full amount to the recipient — more than what was actually locked on the source chain.

**`handleERC20Transfer` — destination-chain withdrawal path (non-mintBurn mode)** [4](#0-3) 

```solidity
if (modeMintBurn) {
    require(ERC20Mintable(_tokenAddress).mint(_to, _value), ...);
} else {
    IERC20(_tokenAddress).safeTransfer(_to, _value);   // FOT deduction here
}
```

In non-mintBurn mode, `safeTransfer(_to, _value)` causes the token to deduct its fee again, so the recipient receives `_value × (1 − feeRate)` instead of `_value`. The `HandleValueTransfer` event records `_value` as delivered, but the recipient is silently shortchanged. The bridge's reserve is also drained by the fee amount on every withdrawal.

---

### Impact Explanation

- **Undercollateralization (non-mintBurn mode):** Every `requestERC20Transfer` call locks fewer tokens than the `_value` relayed to the counterpart chain. Over time the bridge's ERC20 reserve is drained below the sum of outstanding cross-chain obligations, making later withdrawals fail or steal from other depositors.
- **Inflation (mintBurn mode):** The source chain burns `_value` tokens, but the bridge only received `(_value + _feeLimit) × (1 − feeRate)` from the user. The counterpart chain mints the full `_value`, creating net new supply relative to what was actually deposited — a direct unauthorized mint of bridged assets.
- **Double-fee on bridge's own fee payments:** `_payERC20FeeAndRefundChange` issues two additional `safeTransfer` calls (fee to `feeReceiver`, refund to caller), each incurring the token's own fee, compounding the reserve drain.

---

### Likelihood Explanation

Any user can call `requestERC20Transfer` with any registered FOT ERC20 token. No privilege is required. The bridge's `registerToken` function allows operators to register arbitrary ERC20 addresses, and FOT tokens are a well-known, widely deployed token pattern. The trigger is a standard user-facing bridge deposit transaction.

---

### Recommendation

1. **Measure actual received amount** using a before/after balance check in `requestERC20Transfer`:

```solidity
uint256 before = IERC20(_tokenAddress).balanceOf(address(this));
IERC20(_tokenAddress).safeTransferFrom(msg.sender, address(this), _value.add(_feeLimit));
uint256 actualReceived = IERC20(_tokenAddress).balanceOf(address(this)).sub(before);
require(actualReceived >= _value, "FOT: insufficient received");
// use actualReceived instead of _value for accounting
```

2. **Emit the actual locked amount** in `RequestValueTransfer`, not the nominal `_value`, so the counterpart chain only mints/transfers what was truly deposited.

3. **Apply the same before/after pattern** in `handleERC20Transfer` (non-mintBurn) and verify the recipient received the expected amount, or emit the actual delivered amount in `HandleValueTransfer`.

4. Consider explicitly **blocking FOT tokens** from being registered if full FOT support is not intended, similar to how Uniswap V2 separates `removeLiquidityETHSupportingFeeOnTransferTokens`.

---

### Proof of Concept

**Setup:** Register a FOT ERC20 token (1% transfer fee) in the bridge. Bridge is in non-mintBurn mode with 1000 tokens in reserve.

**Step 1 — Source chain deposit:**
- User calls `requestERC20Transfer(token, to, 100, 10)` (value=100, feeLimit=10, bridge fee=5).
- `safeTransferFrom(user, bridge, 110)` → bridge receives `110 × 0.99 = 108.9` tokens.
- `_payERC20FeeAndRefundChange`: `safeTransfer(feeReceiver, 5)` → feeReceiver gets `4.95`, bridge loses `5`. `safeTransfer(user, 5)` → user gets `4.95`, bridge loses `5`.
- Bridge net balance change: `+108.9 − 5 − 5 = +98.9` tokens (not +100).
- `RequestValueTransfer` emits `_value = 100`.

**Step 2 — Counterpart chain handle:**
- Operators call `handleERC20Transfer(..., _value=100, ...)`.
- `safeTransfer(recipient, 100)` → recipient gets `99` tokens (1% fee), bridge loses `100`.

**Result:** Source chain locked `98.9` tokens; destination chain paid out `100` tokens. Net deficit of `1.1` tokens per bridge round-trip, drawn from the bridge's shared reserve. Repeated calls drain the reserve, causing all subsequent withdrawals to revert or steal from other users' deposits.

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
