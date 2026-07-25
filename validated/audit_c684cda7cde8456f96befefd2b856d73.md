### Title
`handleKLAYTransfer` Must Never Revert but Does — Recipient Revert Permanently Locks Bridged KAIA and Freezes `lowerHandleNonce` - (File: `contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

---

### Summary

`BridgeTransferKLAY::handleKLAYTransfer` is the bridge's fulfillment function for cross-chain KAIA transfers. Like `AutoRedemption::fulfillRequest` in the reference report, it must never revert: a revert leaves critical nonce-tracking state unset, permanently locking bridged KAIA and freezing the `lowerHandleNonce` / `recoveryBlockNumber` invariants with no admin escape hatch.

---

### Finding Description

`handleKLAYTransfer` executes in this order:

```
1. _lowerHandleNonceCheck(_requestedNonce)          // guard
2. _voteValueTransfer(_requestedNonce)               // sets closedValueTransferVotes[N] = true
3. _setHandledRequestTxHash(_requestTxHash)          // marks request handled
4. handleNoncesToBlockNums[N] = _requestedBlockNumber // records block
5. _updateHandleNonce(N)                             // advances lowerHandleNonce / recoveryBlockNumber
6. emit HandleValueTransfer(...)
7. (bool ok, ) = _to.call.value(_value)("")          // external call to recipient
8. require(ok, "handleKLAYTransfer: transfer failed") // ← REVERTS EVERYTHING if ok == false
``` [1](#0-0) 

When `_to` is a contract whose fallback reverts (or has no payable fallback), `ok == false` and `require` at line 99 reverts the entire transaction. Because Solidity reverts are atomic, **all state mutations from steps 2–5 are also rolled back**:

- `closedValueTransferVotes[N]` → reverted to `false`
- `handledRequestTx[_requestTxHash]` → reverted to `false`
- `handleNoncesToBlockNums[N]` → reverted to `0`
- `lowerHandleNonce` → reverted (not advanced)
- `recoveryBlockNumber` → reverted (not advanced) [2](#0-1) 

Because `closedValueTransferVotes[N]` is reverted to `false`, operators can vote again. But since `_to` always reverts, every subsequent attempt produces the same outcome: threshold is met, state is updated, transfer fails, everything reverts. The loop is permanent.

`_updateHandleNonce` advances `lowerHandleNonce` only when `handleNoncesToBlockNums[i] > 0` for consecutive nonces starting at `lowerHandleNonce`:

```solidity
for (i = lowerHandleNonce; i <= limit && handleNoncesToBlockNums[i] > 0; i++) {
    recoveryBlockNumber = handleNoncesToBlockNums[i];
    ...
}
lowerHandleNonce = i;
``` [3](#0-2) 

Since `handleNoncesToBlockNums[N]` is never durably set, `lowerHandleNonce` is permanently frozen at `N` and `recoveryBlockNumber` is permanently frozen at the block of nonce `N-1`. There is no owner/admin function anywhere in the contract to skip a stuck nonce or recover locked KAIA. [4](#0-3) 

---

### Impact Explanation

1. **Bridged KAIA permanently locked.** The `_value` KAIA held by the bridge contract for nonce `N` can never be delivered or reclaimed. It is frozen in the bridge forever.
2. **`lowerHandleNonce` permanently frozen.** `recoveryBlockNumber` is stuck at the block before `N`. The off-chain recovery daemon (`vt_recovery.go`) will scan from that block on every recovery cycle indefinitely.
3. **No admin escape hatch.** Neither `BridgeTransferKLAY` nor any parent contract exposes a function to forcibly advance `lowerHandleNonce`, skip a nonce, or drain stuck KAIA.

This matches the allowed impact gate: *unauthorized lock of KAIA / bridged assets in system-managed funds* and *persistent corruption of bridge nonce state that breaks settlement*.

---

### Likelihood Explanation

The trigger is fully unprivileged. Any user on the parent chain can call `requestKLAYTransfer` specifying a `_to` address on the child chain that is a contract without a payable fallback (e.g., a multisig, a DAO treasury, a token contract, or a deliberately deployed reverting contract). The bridge operators will faithfully attempt to fulfill the request, hit the revert loop, and the KAIA will be locked. No special role or majority-validator collusion is required. [5](#0-4) 

---

### Recommendation

1. **Do not `require` the low-level call result.** Capture `ok` but do not revert on failure. The nonce must be marked handled regardless of delivery outcome:
   ```solidity
   (bool ok, ) = _to.call.value(_value)("");
   if (!ok) {
       // emit a FailedValueTransfer event; KAIA stays in bridge for admin recovery
   }
   // lowerHandleNonce advances either way
   ```
2. **Validate `_value > 0`** before the external call to avoid a zero-value revert edge case.
3. **Add an owner-controlled `recoverStuckNonce(uint64 nonce)`** function that can forcibly set `handleNoncesToBlockNums[nonce]` to a sentinel value and advance `lowerHandleNonce`, analogous to the admin `lastRequestId` reset recommended in the reference report.
4. **Apply the same fix to `handleERC20Transfer`**, where `safeTransfer` and `ERC20Mintable.mint` can also revert after nonce state is written. [6](#0-5) 

---

### Proof of Concept

```
Setup (child-chain bridge, threshold = 1):
  - Deploy a contract `Rejecter` with no payable fallback on the child chain.
  - Fund the child-chain bridge with 10 KAIA.

Step 1 (parent chain):
  - User calls requestKLAYTransfer(Rejecter, 1 KAIA, "0x")
    → emits RequestValueTransfer(nonce=0, to=Rejecter, value=1e18)

Step 2 (child chain, operator):
  - Operator calls handleKLAYTransfer(txHash, from, Rejecter, 1e18, 0, blockNum, "0x")
    → _voteValueTransfer(0) → threshold met → closedValueTransferVotes[0] = true
    → handleNoncesToBlockNums[0] = blockNum
    → _updateHandleNonce(0) → lowerHandleNonce = 1
    → emit HandleValueTransfer(...)
    → Rejecter.call{value: 1e18}("") → ok = false
    → require(false) → REVERT
    → ALL state rolled back: lowerHandleNonce = 0, handleNoncesToBlockNums[0] = 0,
      closedValueTransferVotes[0] = false

Step 3 (operator retries):
  - Same result every time. lowerHandleNonce stays 0 forever.
  - 1 KAIA is permanently locked in the bridge.
  - recoveryBlockNumber never advances past block 1.
``` [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L62-100)
```text
    function handleKLAYTransfer(
        bytes32 _requestTxHash,
        address _from,
        address payable _to,
        uint256 _value,
        uint64 _requestedNonce,
        uint64 _requestedBlockNumber,
        bytes memory _extraData
    )
        public
        onlyOperators
        nonReentrant
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
    }
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L132-134)
```text
    function requestKLAYTransfer(address _to, uint256 _value, bytes calldata _extraData) external payable {
        uint256 feeLimit = msg.value.sub(_value);
        _requestKLAYTransfer(_to, feeLimit, _extraData);
```

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L103-116)
```text
    function _voteValueTransfer(uint64 _requestNonce)
        internal
        returns(bool)
    {
        require(!closedValueTransferVotes[_requestNonce], "closed vote");

        bytes32 voteKey = keccak256(msg.data);
        if (_voteCommon(VoteType.ValueTransfer, _requestNonce, voteKey)) {
            closedValueTransferVotes[_requestNonce] = true;
            return true;
        }

        return false;
    }
```

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L30-34)
```text
    uint64 public requestNonce; // the number of value transfer request that this contract received.
    uint64 public lowerHandleNonce; // a minimum nonce of a value transfer request that will be handled.
    uint64 public upperHandleNonce; // a maximum nonce of the counterpart bridge's value transfer request that is handled.
    uint64 public recoveryBlockNumber = 1; // the block number that recovery start to filter log from.
    mapping(uint64 => uint64) public handleNoncesToBlockNums;  // <request nonce> => <request blockNum>
```

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L138-156)
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
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L68-72)
```text
        if (modeMintBurn) {
            require(ERC20Mintable(_tokenAddress).mint(_to, _value), "handleERC20Transfer: mint failed");
        } else {
            IERC20(_tokenAddress).safeTransfer(_to, _value);
        }
```
