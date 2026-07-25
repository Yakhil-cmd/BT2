### Title
Caller-Supplied `_from` in `onERC20Received` Allows Fee-Refund Theft from Bridge Depositors — (File: `contracts/service_chain/bridge/BridgeTransferERC20.sol`)

---

### Summary

`BridgeTransferERC20.onERC20Received` is a `public` function that accepts a fully caller-controlled `_from` address. That address is forwarded verbatim into `_requestERC20Transfer`, where it is used as the recipient of the ERC20 fee refund via `_payERC20FeeAndRefundChange(_from, _tokenAddress, _feeLimit)`. Any registered token contract can call `onERC20Received` with an arbitrary `_from`, redirecting the fee refund away from the legitimate depositor to any address the caller chooses.

---

### Finding Description

The 1-step bridge deposit flow is:

1. User calls `ERC20ServiceChain.requestValueTransfer(amount, to, feeLimit, extraData)`.
2. Token contract executes `transfer(bridge, amount + feeLimit)` — tokens land in the bridge.
3. Token contract calls `bridge.onERC20Received(msg.sender, to, amount, feeLimit, extraData)`.
4. Bridge internally calls `_requestERC20Transfer(msg.sender /*tokenAddr*/, _from, to, amount, feeLimit, extraData)`.
5. Bridge pays the fee to the fee receiver and refunds `feeLimit − fee` tokens to `_from`. [1](#0-0) 

The vulnerability is in step 3–5. `onERC20Received` is declared `public` with **no access-control modifier of its own**: [1](#0-0) 

The only guard is `onlyRegisteredToken(msg.sender)` buried inside `_requestERC20Transfer`: [2](#0-1) 

That guard checks the **token address** (`msg.sender`), not the `_from` argument. `_from` is passed through unchecked and used directly as the refund recipient: [3](#0-2) 

and as the `from` field in the cross-chain event: [4](#0-3) 

The same structural flaw exists in `onERC721Received` (no fee refund there, but `_from` is still caller-supplied and emitted in the cross-chain event): [5](#0-4) 

---

### Impact Explanation

**Fee-refund theft.** When a legitimate user deposits `amount + feeLimit` tokens through the 1-step path, the bridge owes them `feeLimit − fee` tokens as a refund. Because `_from` is caller-supplied, a registered token contract can substitute any address for `_from`, diverting that refund to an attacker-controlled address. The depositor's tokens (the `amount` portion) still cross the bridge correctly, but the fee-change refund — which can be a non-trivial amount if `feeLimit` is set generously — is stolen.

In the more severe variant: a malicious registered token contract calls `onERC20Received` **without** having transferred tokens to the bridge first. The bridge emits a `RequestValueTransfer` event that the counterpart-chain bridge operator will honour by calling `handleERC20Transfer`, which transfers real tokens from the counterpart bridge's reserve to `_to`. This drains the counterpart bridge's ERC20 reserve without any corresponding deposit on the source chain. [6](#0-5) 

---

### Likelihood Explanation

**Medium.** The trigger requires `msg.sender` to be a registered token contract (`onlyRegisteredToken` check). Registered tokens are semi-trusted entities added by the bridge owner. However:

- A registered token contract that itself has a permissionless external entry point (e.g., a public `requestValueTransfer` that lets the caller supply `_from`) can be weaponised by any unprivileged user.
- The reference implementation `ERC20ServiceChain.requestValueTransfer` correctly passes `msg.sender` as `_from`, but the bridge imposes no requirement that all registered tokens follow this pattern.
- The bridge's `onERC20Received` is callable by any registered token at any time, independent of whether a real deposit occurred. [7](#0-6) 

---

### Recommendation

```diff
// BridgeTransferERC20.sol
  function onERC20Received(
-     address _from,
      address _to,
      uint256 _value,
      uint256 _feeLimit,
      bytes memory _extraData
  )
      public
+     onlyRegisteredToken(msg.sender)   // explicit guard
  {
-     _requestERC20Transfer(msg.sender, _from, _to, _value, _feeLimit, _extraData);
+     // _from must be derived from the token contract's own accounting,
+     // not accepted as a caller-supplied parameter.
+     // For the 1-step flow the token contract should pass the real sender
+     // via a separate authenticated mechanism, or the bridge should record
+     // the depositor from the ERC20 Transfer event rather than trusting _from.
  }
```

At minimum, add `onlyRegisteredToken(msg.sender)` as an explicit modifier on `onERC20Received` so the guard is visible and auditable. For full remediation, remove the `_from` parameter and derive the depositor identity from on-chain evidence (e.g., the ERC20 `Transfer` event emitted in the same transaction) rather than accepting it as a caller-supplied argument.

---

### Proof of Concept

**Setup:** `MaliciousToken` is a registered ERC20 token on the source bridge. The counterpart bridge holds 1 000 `CounterpartToken` in lock mode.

```
// Attacker calls from MaliciousToken contract:
bridge.onERC20Received(
    attackerEOA,          // _from  — spoofed; no tokens transferred to bridge
    victimEOA,            // _to    — irrelevant for fee theft
    1,                    // _value — passes the > 0 check
    1000e18,              // _feeLimit — large; bridge has prior token balance
    ""
);
```

1. `onlyRegisteredToken(MaliciousToken)` passes — token is registered.
2. `_payERC20FeeAndRefundChange(attackerEOA, MaliciousToken, 1000e18)` executes: fee (e.g. 0) is paid; `1000e18 − fee` tokens are transferred from the bridge's `MaliciousToken` balance to `attackerEOA`.
3. `RequestValueTransfer` is emitted with `from = attackerEOA`, `to = victimEOA`, `value = 1`.
4. Counterpart bridge operator calls `handleERC20Transfer`, transferring 1 `CounterpartToken` from the counterpart bridge reserve to `victimEOA` — no corresponding deposit was ever made on the source chain. [1](#0-0) [8](#0-7) [9](#0-8)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L32-73)
```text
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
        _lowerHandleNonceCheck(_requestedNonce);

        if (!_voteValueTransfer(_requestedNonce)) {
            return;
        }

        _setHandledRequestTxHash(_requestTxHash);

        handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber;
        _updateHandleNonce(_requestedNonce);

        emit HandleValueTransfer(
            _requestTxHash,
            TokenType.ERC20,
            _from,
            _to,
            _tokenAddress,
            _value,
            _requestedNonce,
            lowerHandleNonce,
            _extraData
        );

        if (modeMintBurn) {
            require(ERC20Mintable(_tokenAddress).mint(_to, _value), "handleERC20Transfer: mint failed");
        } else {
            IERC20(_tokenAddress).safeTransfer(_to, _value);
        }
    }
```

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

**File:** contracts/testing/sc_erc20/ERC20ServiceChain.sol (L44-47)
```text
    function requestValueTransfer(uint256 _amount, address _to, uint256 _feeLimit, bytes calldata _extraData) external {
        require(transfer(bridge, _amount.add(_feeLimit)), "requestValueTransfer: transfer failed");
        IERC20BridgeReceiver(bridge).onERC20Received(msg.sender, _to, _amount, _feeLimit, _extraData);
    }
```
