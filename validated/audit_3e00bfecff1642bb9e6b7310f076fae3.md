### Title
EVM Callback Revert in `onPacketResult` Permanently Blocks IBC Acknowledgement/Timeout Processing - (`x/cronos/keeper/keeper.go`)

### Summary

`onPacketResult` in `x/cronos/keeper/keeper.go` calls an EVM contract's `onPacketResultCallback` and propagates any EVM revert as a hard error. Because `IBCOnAcknowledgementPacketCallback` and `IBCOnTimeoutPacketCallback` both delegate to `onPacketResult` without swallowing the error, a contract whose `onPacketResultCallback` consistently reverts will permanently prevent the IBC acknowledgement or timeout from being committed, locking escrowed funds indefinitely.

### Finding Description

`onPacketResult` is the shared implementation for both `IBCOnAcknowledgementPacketCallback` and `IBCOnTimeoutPacketCallback`:

```go
// x/cronos/keeper/keeper.go
func (k Keeper) onPacketResult(...) error {
    ...
    _, res, err := k.CallEVM(ctx, &senderAddr, data, big.NewInt(0), gasLimit)
    if err != nil {
        return err                                                    // propagated
    }
    if res.Failed() {
        return fmt.Errorf("IBC callback EVM execution reverted: %s", res.VmError)  // propagated
    }
    return nil
}
``` [1](#0-0) 

Both callback entry points return this error directly to the IBC callback middleware:

```go
func (k Keeper) IBCOnAcknowledgementPacketCallback(...) error {
    ...
    return k.onPacketResult(ctx, packet, res.Success(), relayer, contractAddress, packetSenderAddress)
}

func (k Keeper) IBCOnTimeoutPacketCallback(...) error {
    return k.onPacketResult(ctx, packet, false, relayer, contractAddress, packetSenderAddress)
}
``` [2](#0-1) 

When the IBC callback middleware receives a non-nil error from these methods, it causes the entire `MsgAcknowledgement` or `MsgTimeout` transaction to fail. The IBC core does not commit the acknowledgement/timeout receipt, so the relayer retries — but every retry hits the same reverting EVM contract, making the packet permanently unresolvable.

Failure modes that cause a persistent revert (no admin action can fix them without a contract upgrade):
- The EVM contract's `onPacketResultCallback` has a logic bug that always reverts for a given `(channel, sequence)` pair.
- The contract was self-destructed after the packet was sent (no code at the address → EVM call fails).
- The `MaxCallbackGas` parameter is set too low for the contract's logic, causing an out-of-gas revert on every attempt. [3](#0-2) 

Contrast this with the refund paths in `IBCConversionModule`, which explicitly swallow conversion errors to avoid blocking IBC flows:

```go
// Intentional: log and continue so the IBC refund is not blocked.
im.cronoskeeper.Logger(ctx).Error("failed to convert refund vouchers on acknowledgement", ...)
``` [4](#0-3) 

The callback path has no equivalent protection.

### Impact Explanation

**High — Permanent inability for honest users to process valid IBC ack/timeout flows.**

When `MsgAcknowledgement` or `MsgTimeout` can never be committed:
- ICS-20 escrowed tokens on the source chain are permanently locked (the escrow is only released when the ack/timeout is committed).
- The IBC packet sequence for that channel advances only after the ack is committed; depending on the channel ordering, this can also stall subsequent ordered-channel packets.
- No unprivileged user can unblock this — it requires either a contract upgrade (if the contract is upgradeable) or a governance parameter change to `MaxCallbackGas`.

### Likelihood Explanation

Any unprivileged user who:
1. Deploys a CRC20/ICA-callback contract that implements `onPacketResultCallback` with a revertible code path, **or**
2. Uses the ICA precompile to send a packet from a contract that is later self-destructed,

can trigger this condition without any malicious intent. Normal contract bugs (e.g., an assertion that fails for a specific sequence number) are sufficient.

### Recommendation

Mirror the "log and continue" pattern already used in the refund paths of `IBCConversionModule`. In `onPacketResult`, catch EVM revert errors, emit a Cosmos event or log, and return `nil` so the IBC ack/timeout is always committed:

```go
if err != nil || res.Failed() {
    k.Logger(ctx).Error("IBC callback EVM execution failed",
        "contract", contractAddress,
        "channel", packet.SourceChannel,
        "sequence", packet.Sequence,
        "error", err,
    )
    return nil  // do not block ack/timeout commitment
}
```

Alternatively, adopt the ibc-go callback middleware's built-in "allow failure" flag so that callback errors are downgraded to events rather than transaction failures.

### Proof of Concept

1. Deploy a Solidity contract `C` on Cronos that implements `onPacketResultCallback` and unconditionally reverts:
   ```solidity
   function onPacketResultCallback(string calldata, uint64, bool) external payable returns (bool) {
       revert("always fail");
   }
   ```
2. From `C`, call the ICA precompile to submit an IBC packet (e.g., an ICS-20 transfer). The packet is sent with `C`'s address as both sender and callback contract.
3. The counterparty chain processes the packet and sends back an acknowledgement.
4. The relayer submits `MsgAcknowledgement` on Cronos. The IBC callback middleware calls `IBCOnAcknowledgementPacketCallback` → `onPacketResult` → `CallEVM` → `C.onPacketResultCallback` → revert.
5. `onPacketResult` returns `fmt.Errorf("IBC callback EVM execution reverted: ...")`.
6. The `MsgAcknowledgement` transaction fails; the ack receipt is never written.
7. Every subsequent relay attempt repeats steps 4–6. The escrowed tokens are permanently locked. [5](#0-4) [2](#0-1)

### Citations

**File:** x/cronos/keeper/keeper.go (L406-436)
```go
func (k Keeper) onPacketResult(
	ctx sdk.Context,
	packet channeltypes.Packet,
	acknowledgement bool,
	relayer sdk.AccAddress,
	contractAddress,
	packetSenderAddress string,
) error {
	sender, err := sdk.AccAddressFromBech32(packetSenderAddress)
	if err != nil {
		return fmt.Errorf("invalid bech32 address: %s, err: %w", packetSenderAddress, err)
	}
	senderAddr := common.BytesToAddress(sender)
	contractAddr := common.HexToAddress(contractAddress)
	if senderAddr != contractAddr {
		return fmt.Errorf("sender is not authenticated: expected %s, got %s", senderAddr, contractAddr)
	}
	data, err := cronosprecompiles.OnPacketResultCallback(packet.SourceChannel, packet.Sequence, acknowledgement)
	if err != nil {
		return err
	}
	gasLimit := k.GetParams(ctx).MaxCallbackGas
	_, res, err := k.CallEVM(ctx, &senderAddr, data, big.NewInt(0), gasLimit)
	if err != nil {
		return err
	}
	if res.Failed() {
		return fmt.Errorf("IBC callback EVM execution reverted: %s", res.VmError)
	}
	return nil
}
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

**File:** x/cronos/middleware/conversion_middleware.go (L180-188)
```go
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
