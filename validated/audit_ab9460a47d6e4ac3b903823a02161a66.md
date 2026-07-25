### Title
Service-Chain Bridge Permanently Blocked by Unhandleable Value-Transfer Request - (File: node/sc/bridge_manager.go)

### Summary

`processingPendingRequestEvents` in `node/sc/bridge_manager.go` processes pending cross-chain value-transfer events sequentially. When `handleRequestValueTransferEvent` returns an error for a given nonce, the failing event is re-queued and processing halts for all higher nonces. Because `handleKLAYTransfer` on the destination bridge calls `_to.call.value(_value)("")` and hard-reverts if the call fails, an attacker who sets `_to` to a contract that always reverts can craft a request that permanently fails gas estimation. This permanently blocks every subsequent value transfer through the bridge pair, locking all bridged assets in the source contract.

### Finding Description

`processingPendingRequestEvents` iterates over ready events in nonce order:

```go
// node/sc/bridge_manager.go:248-258
for idx, ev := range ReadyEvent {
    if ev.GetRequestNonce() < bi.lowerHandleNonce || bi.handledEvent.Exist(ev.GetRequestNonce()) {
        continue
    }
    if err := bi.handleRequestValueTransferEvent(ev); err != nil {
        bi.AddRequestValueTransferEvents(ReadyEvent[idx:])   // re-queue from failing nonce
        logger.Error("Failed handle request value transfer event", ...)
        return                                               // stop all further processing
    }
}
``` [1](#0-0) 

When `handleRequestValueTransferEvent` fails, the failing event **and every event with a higher nonce** are re-queued. The function returns immediately, and the next ticker tick (every second) will attempt the same failing event again. There is no skip-and-continue path.

`handleRequestValueTransferEvent` calls the Go ABI binding for `HandleKLAYTransfer`, which performs `eth_estimateGas` before submitting the transaction:

```go
// node/sc/bridge_manager.go:332-336
case KAIA:
    handleTx, err = bi.bridge.HandleKLAYTransfer(auth, txHash, from, to,
        valueOrTokenId, requestNonce, blkNumber, extraData)
    if err != nil {
        return err
    }
``` [2](#0-1) 

On the destination bridge, `handleKLAYTransfer` does:

```solidity
// contracts/service_chain/bridge/BridgeTransferKLAY.sol:98-99
(bool ok, ) = _to.call.value(_value)("");
require(ok, "handleKLAYTransfer: transfer failed");
``` [3](#0-2) 

If `_to` is a contract that always reverts on receiving KAIA, `eth_estimateGas` will simulate the revert and return an error to the Go binding. This error propagates back through `handleRequestValueTransferEvent` → `processingPendingRequestEvents`, which re-queues the event and stops. The bridge is now stuck.

The source-side `requestKLAYTransfer` accepts any `_to` address without validation:

```solidity
// contracts/service_chain/bridge/BridgeTransferKLAY.sol:132-135
function requestKLAYTransfer(address _to, uint256 _value, bytes calldata _extraData)
    external payable
{
    uint256 feeLimit = msg.value.sub(_value);
    _requestKLAYTransfer(_to, feeLimit, _extraData);
}
``` [4](#0-3) 

The same pattern applies to ERC721 transfers: `handleERC721Transfer` calls `mintWithTokenURI` with an unbounded URI string fetched from the token contract. A token with a URI large enough to exceed the block gas limit will also cause permanent gas-estimation failure. [5](#0-4) 

The Value Transfer Recovery mechanism (`vt_recovery.go`) does not help: it only re-queues events whose nonce is ≥ `lowerHandleNonce`. Because `lowerHandleNonce` never advances past the permanently failing nonce, the recovery loop keeps re-injecting the same poisoned event. [6](#0-5) 

### Impact Explanation

All value transfers through the affected bridge pair with a request nonce greater than the attacker's poisoned nonce are permanently blocked. KAIA and tokens locked in the source bridge contract cannot be released to the destination chain. The `lowerHandleNonce` on the destination bridge contract never advances, so the VT Recovery mechanism continuously re-queues the same failing event. The bridge is effectively bricked until an operator manually intervenes (no in-protocol skip mechanism exists).

This matches the "Persistent corruption … that breaks … transfers" and "Bridge … privilege escalation that changes protected chain state or asset ownership" criteria in the Allowed Impact Gate.

### Likelihood Explanation

The attack requires only:
1. Deploying a contract on the destination chain that reverts on receiving KAIA (trivial, ~10 lines of Solidity).
2. Calling `requestKLAYTransfer` on the source bridge with `_to` set to that contract and paying the minimum fee.

No privileged access is required. Any unprivileged user can execute this with a small amount of KAIA.

### Recommendation

1. **Skip-and-store, do not block.** In `processingPendingRequestEvents`, when `handleRequestValueTransferEvent` returns an error, log the failure and continue to the next event rather than re-queuing and returning. Store the failed nonce in a persistent "failed transfers" map so operators can inspect and manually retry or skip it.

2. **Validate `_to` on the source bridge.** In `_requestKLAYTransfer`, reject transfers where `_to` is a contract address (or at minimum emit a warning). Alternatively, use a pull-payment pattern on the destination side so that a reverting recipient does not cause the bridge operator's transaction to fail.

3. **Cap URI length.** In `_requestERC721Transfer`, enforce a maximum length on the fetched `tokenURI` before encoding it into the event, preventing oversized payloads from causing gas-estimation failures on the destination side.

### Proof of Concept

```
// 1. Deploy on destination chain:
contract Reverter {
    receive() external payable { revert("always revert"); }
}

// 2. On source chain, call:
sourceBridge.requestKLAYTransfer{value: 1 ether + fee}(
    address(reverterOnDestination),
    1 ether,
    ""
);
// This emits RequestValueTransfer with nonce N.

// 3. SubBridge operator attempts:
//    destinationBridge.HandleKLAYTransfer(..., reverterOnDestination, 1 ether, N, ...)
//    eth_estimateGas reverts → Go binding returns error
//    processingPendingRequestEvents re-queues nonce N and returns.

// 4. All subsequent requests with nonce > N are now permanently blocked.
//    VT Recovery re-queues nonce N on every interval, perpetuating the block.
```

The root cause is at `node/sc/bridge_manager.go:254-257` (the `return` on error without skipping) and `contracts/service_chain/bridge/BridgeTransferKLAY.sol:98-99` (the hard-revert on failed KAIA transfer to `_to`). [7](#0-6) [3](#0-2)

### Citations

**File:** node/sc/bridge_manager.go (L240-259)
```go
func (bi *BridgeInfo) processingPendingRequestEvents() {
	ReadyEvent := bi.GetReadyRequestValueTransferEvents()
	if ReadyEvent == nil {
		return
	}

	logger.Trace("Get ready request value transfer event", "len(readyEvent)", len(ReadyEvent), "len(pendingEvent)", bi.pendingRequestEvent.Len())

	for idx, ev := range ReadyEvent {
		if ev.GetRequestNonce() < bi.lowerHandleNonce || bi.handledEvent.Exist(ev.GetRequestNonce()) {
			logger.Trace("handled requests can be ignored", "RequestNonce", ev.GetRequestNonce(), "lowerHandleNonce", bi.lowerHandleNonce)
			continue
		}

		if err := bi.handleRequestValueTransferEvent(ev); err != nil {
			bi.AddRequestValueTransferEvents(ReadyEvent[idx:])
			logger.Error("Failed handle request value transfer event", "err", err, "len(RePutEvent)", len(ReadyEvent[idx:]))
			return
		}
	}
```

**File:** node/sc/bridge_manager.go (L332-336)
```go
	case KAIA:
		handleTx, err = bi.bridge.HandleKLAYTransfer(auth, txHash, from, to, valueOrTokenId, requestNonce, blkNumber, extraData)
		if err != nil {
			return err
		}
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L98-99)
```text
        (bool ok, ) = _to.call.value(_value)("");
        require(ok, "handleKLAYTransfer: transfer failed");
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L132-135)
```text
    function requestKLAYTransfer(address _to, uint256 _value, bytes calldata _extraData) external payable {
        uint256 feeLimit = msg.value.sub(_value);
        _requestKLAYTransfer(_to, feeLimit, _extraData);
    }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L66-70)
```text
        if (modeMintBurn) {
            require(ERC721MetadataMintable(_tokenAddress).mintWithTokenURI(_to, _tokenId, _tokenURI), "mint failed");
        } else {
            IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);
        }
```

**File:** node/sc/vt_recovery.go (L307-320)
```go
		for reqVTevIt.Next() {
			logger.Trace("pending nonce in the RequestValueTransfer event", "requestNonce", reqVTevIt.Event.RequestNonce)
			if reqVTevIt.Event.RequestNonce >= hint.handleNonce {
				// Check if the event is already handled in target bridge contract
				if isHandledEvent(to, RequestValueTransferEvent{reqVTevIt.Event}) {
					continue
				}
				logger.Trace("filtered pending nonce", "requestNonce", reqVTevIt.Event.RequestNonce, "handledNonce", hint.handleNonce)
				pendingEvents = append(pendingEvents, RequestValueTransferEvent{reqVTevIt.Event})
				if len(pendingEvents) >= maxPendingTxs {
					reqVTevIt.Close()
					break pendingTxLoop
				}
			}
```
