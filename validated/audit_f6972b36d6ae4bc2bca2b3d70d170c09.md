### Title
Bridge `handleERC20Transfer` and `handleKLAYTransfer` Use Push Pattern That Permanently Locks Bridged Assets When Recipient Is Blocked — (`contracts/service_chain/bridge/BridgeTransferERC20.sol`, `contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

---

### Summary

Both `handleERC20Transfer` and `handleKLAYTransfer` in the Kaia service-chain bridge use a **push pattern** to deliver assets to the recipient `_to`. If the push reverts — because `_to` is on a token blocklist (USDC/USDT) or is a contract that rejects KLAY — the entire transaction reverts, including all nonce-accounting state changes. The nonce is permanently unresolvable, and the bridged assets are permanently locked inside the bridge contract with no recovery path.

---

### Finding Description

`handleERC20Transfer` executes in this order:

1. `_lowerHandleNonceCheck(_requestedNonce)` — validates nonce window
2. `_voteValueTransfer(_requestedNonce)` — records vote, sets `closedValueTransferVotes[nonce] = true`
3. `_setHandledRequestTxHash(_requestTxHash)` — marks tx hash handled
4. `handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber` — records block
5. `_updateHandleNonce(_requestedNonce)` — advances `lowerHandleNonce`
6. Emits `HandleValueTransfer`
7. **`IERC20(_tokenAddress).safeTransfer(_to, _value)`** ← push transfer [1](#0-0) 

Because Solidity transactions are atomic, if step 7 reverts (e.g., `_to` is on USDC's blocklist), **all of steps 2–6 are also reverted**. The result:

- `closedValueTransferVotes[nonce]` returns to `false`
- `handleNoncesToBlockNums[nonce]` returns to `0`
- `lowerHandleNonce` is unchanged

Operators can retry indefinitely, but every attempt will revert identically. The nonce is permanently unhandleable.

`handleKLAYTransfer` has the identical structure, with the push at line 98–99:

```solidity
(bool ok, ) = _to.call.value(_value)("");
require(ok, "handleKLAYTransfer: transfer failed");
``` [2](#0-1) 

If `_to` is a contract without a payable fallback (or one that explicitly reverts), the `require` fires and the entire transaction reverts.

The nonce advancement logic in `_updateHandleNonce` advances `lowerHandleNonce` only when `handleNoncesToBlockNums[i] > 0` for consecutive nonces starting from `lowerHandleNonce`: [3](#0-2) 

Since the stuck nonce's `handleNoncesToBlockNums` entry is always reverted back to `0`, `lowerHandleNonce` never advances past it. There is no owner/operator function to skip a nonce or redirect a stuck transfer.

---

### Impact Explanation

**Impact: High.**

A user initiates a bridge transfer on the source chain, locking or burning their ERC20 tokens (or KLAY). The destination bridge receives the cross-chain request. If `_to` is on a token blocklist at the time operators attempt to handle it, the assets are permanently locked inside the bridge contract. There is no admin escape hatch, no nonce-skip function, and no pull-withdrawal mechanism. The user's funds are irrecoverably lost from their perspective. This constitutes an unauthorized permanent lock of bridged assets — a direct match to the allowed impact gate ("unauthorized … lock … affecting … bridged assets").

---

### Likelihood Explanation

**Likelihood: Low.**

Two conditions must coincide: (1) the bridged ERC20 token must implement an admin-controlled blocklist (USDC, USDT), and (2) the recipient address `_to` must be on that blocklist at the time operators execute the handle transaction. For KLAY, `_to` must be a non-payable contract. The scenario where a user's address is blocklisted between request and handle is realistic for USDC/USDT bridges. The KLAY variant is slightly more likely since any contract without a payable fallback triggers it.

---

### Recommendation

Replace the push pattern with a **pull-over-push** pattern in both `handleERC20Transfer` and `handleKLAYTransfer`:

1. On a successful vote, record the pending withdrawal: `pendingWithdrawals[_to][_tokenAddress] += _value` and advance the nonce.
2. Add a separate `withdraw(address _tokenAddress)` function that lets `_to` pull their own funds.

This decouples nonce accounting from asset delivery. A blocked recipient cannot prevent nonce advancement or lock other users' transfers.

Alternatively, add an owner-callable `recoverStuckTransfer(uint64 _nonce, address _newRecipient)` that can redirect a permanently-stuck nonce to a different address, at minimum preventing permanent asset loss.

---

### Proof of Concept

**ERC20 blocklist scenario:**

```
Setup:
- Bridge registered with USDC as a bridged token (modeMintBurn = false)
- Bridge holds 1000 USDC liquidity
- User on source chain calls requestERC20Transfer(USDC, _to=alice, 100)
  → source chain burns/locks 100 USDC, emits RequestValueTransfer(nonce=5)

Attack / Trigger:
- USDC admin adds alice to the USDC blocklist (alice is sanctioned)
- Bridge operators call handleERC20Transfer(txHash, from, alice, USDC, 100, 5, blockNum, "")

Execution trace in handleERC20Transfer:
  1. _lowerHandleNonceCheck(5) → passes (lowerHandleNonce=0 ≤ 5)
  2. _voteValueTransfer(5) → threshold reached, closedValueTransferVotes[5]=true, returns true
  3. _setHandledRequestTxHash(txHash) → handledRequestTx[txHash]=true
  4. handleNoncesToBlockNums[5] = blockNum
  5. _updateHandleNonce(5) → lowerHandleNonce advances
  6. emit HandleValueTransfer(...)
  7. IERC20(USDC).safeTransfer(alice, 100)
     → USDC transfer() checks blocklist → alice is blocked → REVERT

  Entire transaction reverts:
  - closedValueTransferVotes[5] = false  (reverted)
  - handleNoncesToBlockNums[5] = 0       (reverted)
  - lowerHandleNonce unchanged           (reverted)

Result:
- Operators retry → always revert
- 100 USDC permanently locked in bridge
- Alice's source-chain assets are already burned/locked
- No recovery function exists
```

**KLAY non-payable contract scenario:**

```
- _to = address of a contract with no payable fallback
- handleKLAYTransfer reaches line 98:
    (bool ok, ) = _to.call.value(_value)("");
    require(ok, "handleKLAYTransfer: transfer failed");  // ← always reverts
- Same permanent lock outcome
``` [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L44-72)
```text
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
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L75-99)
```text
        _lowerHandleNonceCheck(_requestedNonce);

        if (!_voteValueTransfer(_requestedNonce)) {
            return;
        }

        _setHandledRequestTxHash(_requestTxHash);

        handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber;
        _updateHandleNonce(_requestedNonce);

        emit HandleValueTransfer(
            _requestTxHash,
            TokenType.KLAY,
            _from,
            _to,
            address(0),
            _value,
            _requestedNonce,
            lowerHandleNonce,
            _extraData
        );

        (bool ok, ) = _to.call.value(_value)("");
        require(ok, "handleKLAYTransfer: transfer failed");
```

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L138-160)
```text
    // _updateHandleNonce increases lower and upper handle nonce after the _requestedNonce is handled.
    function _updateHandleNonce(uint64 _requestedNonce) internal {
        if (_requestedNonce > upperHandleNonce) {
            upperHandleNonce = _requestedNonce;
        }

        uint64 limit = lowerHandleNonce + 200;
        if (limit > upperHandleNonce) {
            limit = upperHandleNonce;
        }

        uint64 i;
        for (i = lowerHandleNonce; i <= limit && handleNoncesToBlockNums[i] > 0; i++) {
            recoveryBlockNumber = handleNoncesToBlockNums[i];
            delete handleNoncesToBlockNums[i];
            delete closedValueTransferVotes[i];
        }
        lowerHandleNonce = i;
    }

    function _lowerHandleNonceCheck(uint64 _requestedNonce) internal {
        require(lowerHandleNonce <= _requestedNonce, "removed vote");
    }
```
