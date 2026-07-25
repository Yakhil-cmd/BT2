### Title
Bridge ERC20 Deposit Trusts Declared Amount Without Verifying Actual Received Balance — (`contracts/service_chain/bridge/BridgeTransferERC20.sol`)

---

### Summary

`BridgeTransferERC20.requestERC20Transfer` calls `safeTransferFrom` and immediately proceeds to emit a cross-chain `RequestValueTransfer` event for the caller-declared `_value`, without ever verifying that the bridge's token balance actually increased by that amount. This is the direct Kaia analog of M-13: the safety of the deposit is controlled by `safeTransferFrom()` success alone, not by a balance invariant check.

---

### Finding Description

`requestERC20Transfer` in `BridgeTransferERC20.sol` performs the following sequence:

```solidity
function requestERC20Transfer(
    address _tokenAddress,
    address _to,
    uint256 _value,
    uint256 _feeLimit,
    bytes memory _extraData
) public {
    IERC20(_tokenAddress).safeTransferFrom(msg.sender, address(this), _value.add(_feeLimit));
    _requestERC20Transfer(_tokenAddress, msg.sender, _to, _value, _feeLimit, _extraData);
}
``` [1](#0-0) 

`_requestERC20Transfer` then emits `RequestValueTransfer` for `_value`:

```solidity
emit RequestValueTransfer(
    TokenType.ERC20,
    _from, _to, _tokenAddress,
    _value,
    requestNonce,
    fee,
    _extraData
);
requestNonce++;
``` [2](#0-1) 

There is no balance snapshot before the `safeTransferFrom` call and no post-transfer balance check to confirm the bridge received exactly `_value + _feeLimit` tokens. The bridge unconditionally trusts the return value of `safeTransferFrom`.

The same pattern exists in the 1-step path via `onERC20Received`: the token contract calls `transfer(bridge, _amount + _feeLimit)` and then calls `onERC20Received` with the declared `_amount`. The bridge trusts the declared value without checking its own balance:

```solidity
function onERC20Received(
    address _from, address _to,
    uint256 _value, uint256 _feeLimit,
    bytes memory _extraData
) public {
    _requestERC20Transfer(msg.sender, _from, _to, _value, _feeLimit, _extraData);
}
``` [3](#0-2) 

The `ERC20ServiceChain.requestValueTransfer` shows the 1-step flow: it calls `transfer(bridge, _amount + _feeLimit)` and then calls `onERC20Received` with the declared amounts: [4](#0-3) 

The `SafeERC20.callOptionalReturn` used by the bridge only checks that the low-level call succeeded and the return value (if any) is `true`. It does not verify the actual token accounting: [5](#0-4) 

---

### Impact Explanation

When the `RequestValueTransfer` event is emitted, the off-chain bridge relayer (`BridgeInfo.handleRequestValueTransferEvent`) reads `_value` from the event and calls `handleERC20Transfer` on the counterpart bridge, which releases exactly `_value` tokens to the recipient: [6](#0-5) [7](#0-6) 

If a registered ERC20 token has fee-on-transfer mechanics (e.g., a 1% transfer tax), the bridge receives `(value + feeLimit) × 0.99` tokens but emits `RequestValueTransfer` for `value`. The counterpart bridge releases `value` tokens. The shortfall — `(value + feeLimit) × 0.01` — is a net loss from the counterpart bridge's liquidity reserves per transaction. Repeated over many deposits, the counterpart bridge's reserves are drained below the amount needed to service legitimate withdrawals.

The impact is **unauthorized transfer of bridged assets**: users on the destination chain receive tokens that were never fully backed by the source-chain deposit, constituting an unauthorized drain of the counterpart bridge's token reserves.

---

### Likelihood Explanation

The bridge's token registration (`registerToken`) has no on-chain enforcement that the registered token is non-fee-on-transfer. Any operator can register a token with transfer-fee mechanics. Many real-world tokens (e.g., USDT on some chains, reflection tokens, deflationary tokens) implement transfer fees. The trigger requires only a normal user call to `requestERC20Transfer` with such a token — no privileged access is needed beyond the token being registered.

---

### Recommendation

Record the bridge's token balance before the `safeTransferFrom` call and verify the actual increase matches the declared `_value + _feeLimit` after the call:

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
    require(received >= _value.add(_feeLimit), "insufficient tokens received");
    _requestERC20Transfer(_tokenAddress, msg.sender, _to, _value, _feeLimit, _extraData);
}
```

Apply the same pattern to `onERC20Received` (snapshot balance before the external token `transfer` call is not possible there, but the bridge can snapshot its own balance at entry and compare against `_value + _feeLimit`).

---

### Proof of Concept

1. Operator registers a fee-on-transfer ERC20 token (1% fee) with the bridge via `registerToken`.
2. User calls `requestERC20Transfer(feeToken, victim, 1000e18, 0, "")`.
3. Bridge calls `safeTransferFrom(user, bridge, 1000e18)`. Token deducts 1% fee; bridge receives `990e18`. `safeTransferFrom` returns success.
4. Bridge emits `RequestValueTransfer(..., value=1000e18, ...)`.
5. Relayer sees the event and calls `handleERC20Transfer(..., _value=1000e18, ...)` on the counterpart bridge.
6. Counterpart bridge calls `safeTransfer(user, 1000e18)`, releasing `1000e18` tokens.
7. Net loss from counterpart bridge: `10e18` tokens per transaction.
8. After 100 such transactions, the counterpart bridge has lost `1000e18` tokens from its reserves, making it unable to service legitimate withdrawals. [1](#0-0) [7](#0-6) [6](#0-5)

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

**File:** contracts/testing/sc_erc20/ERC20ServiceChain.sol (L44-47)
```text
    function requestValueTransfer(uint256 _amount, address _to, uint256 _feeLimit, bytes calldata _extraData) external {
        require(transfer(bridge, _amount.add(_feeLimit)), "requestValueTransfer: transfer failed");
        IERC20BridgeReceiver(bridge).onERC20Received(msg.sender, _to, _amount, _feeLimit, _extraData);
    }
```

**File:** contracts/libs/openzeppelin-contracts-v2/contracts/token/ERC20/SafeERC20.sol (L55-74)
```text
    function callOptionalReturn(IERC20 token, bytes memory data) private {
        // We need to perform a low level call here, to bypass Solidity's return data size checking mechanism, since
        // we're implementing it ourselves.

        // A Solidity high level call has three parts:
        //  1. The target address is checked to verify it contains contract code
        //  2. The call itself is made, and success asserted
        //  3. The return value is decoded, which in turn checks the size of the returned data.
        // solhint-disable-next-line max-line-length
        require(address(token).isContract(), "SafeERC20: call to non-contract");

        // solhint-disable-next-line avoid-low-level-calls
        (bool success, bytes memory returndata) = address(token).call(data);
        require(success, "SafeERC20: low-level call failed");

        if (returndata.length > 0) { // Return data is optional
            // solhint-disable-next-line max-line-length
            require(abi.decode(returndata, (bool)), "SafeERC20: ERC20 operation did not succeed");
        }
    }
```

**File:** node/sc/bridge_manager.go (L338-343)
```go
	case ERC20:
		handleTx, err = bi.bridge.HandleERC20Transfer(auth, txHash, from, to, ctpartTokenAddr, valueOrTokenId, requestNonce, blkNumber, extraData)
		if err != nil {
			return err
		}
		handleValueTransferLog(bi.onChildChain, handleVTmethods[ERC20], handleTx.Hash().String(), requestNonce, from, to, valueOrTokenId)
```
