### Title
Missing `ConvertTokens` Decoder Registration Permanently Prevents `FungibleTokenPacket` EVM Log Emission — (`x/cronos/events/events.go`)

---

### Summary

`ConvertTokens` is fully implemented in `decoders.go` but is never registered in `RelayerValueDecoders`. The `FungibleTokenPacket` ABI event declares `tokens` as its sole non-indexed argument. Every call to `RelayerConvertEvent` for a `fungible_token_packet` SDK event will deterministically fail with `"no decoder for tokens"`, permanently suppressing the EVM log.

---

### Finding Description

**Step 1 — ABI event descriptor construction**

`NewEventDescriptors` iterates over all ABI events and calls `getArguments(event.Inputs, false)` to collect non-indexed argument names. For `FungibleTokenPacket`:

```solidity
event FungibleTokenPacket(
    address indexed receiver,
    address indexed sender,
    Cosmos.Token[] tokens          // ← sole non-indexed arg
);
```

`toUnderScore("Tokens")` → `"tokens"`, so `EventDescriptor.nonIndexed = ["tokens"]`. [1](#0-0) [2](#0-1) 

**Step 2 — `makeFilter` requires a decoder for every non-indexed argument**

```go
decode, ok := valueDecoders.GetDecoder(name)   // name = "tokens"
if !ok {
    return nil, fmt.Errorf("no decoder for %s", name)
}
```

`GetDecoder` checks the map for `"tokens"`, then falls back to `""`. Neither key exists in `RelayerValueDecoders`. [3](#0-2) [4](#0-3) 

**Step 3 — `ConvertTokens` exists but is not registered**

`decoders.go` contains a complete, correct implementation:

```go
func ConvertTokens(attributeValue string, _ bool) ([]any, error) {
    var tokens []transfertypes.Token
    err := json.Unmarshal([]byte(attributeValue), &tokens)
    ...
}
```

But `RelayerValueDecoders` in `events.go` has no entry for `"tokens"` (or `transfertypes.AttributeKeyTokens`): [5](#0-4) [6](#0-5) 

**Step 4 — Error propagation path**

`RelayerConvertEvent` → `desc.ConvertEvent` → `makeFilter(nonIndexed)` → `"no decoder for tokens"` error returned to the precompile `exec` call in `relayer.go`: [7](#0-6) [8](#0-7) [9](#0-8) 

---

### Impact Explanation

Every `fungible_token_packet` SDK event processed through `RelayerConvertEvent` will fail. This means:

1. The `FungibleTokenPacket` EVM log (topic `0x8681afe37c8f6aabb2f095898d12d4d1c65f110716e0ed752c7662fc83bbbfaf`) is **never emitted** for any IBC transfer processed via the relayer precompile.
2. If the error propagates out of `exec`, the precompile `RecvPacket` call reverts, permanently blocking IBC packet delivery via the precompile path.
3. All downstream EVM contracts that filter on `FungibleTokenPacket` receive no events.

This is **High: Corruption of EVM receipt/log processing** — the `FungibleTokenPacket` log is permanently absent from all receipts, and the precompile path for `RecvPacket` may be rendered non-functional.

The claim of "consensus divergence" in the question is **not accurate**: all nodes fail identically, so there is no state divergence between validators. The impact is a permanent, deterministic missing-log / precompile-revert condition, not a consensus split.

---

### Likelihood Explanation

This is triggered by any IBC transfer that causes the transfer module to emit a `fungible_token_packet` SDK event and the relayer precompile to process it. No special privileges are required — any relayer submitting a `RecvPacket` via the precompile hits this path. The bug is unconditional: there is no code path through which `"tokens"` could be resolved from `RelayerValueDecoders`.

---

### Recommendation

Register `ConvertTokens` in `RelayerValueDecoders` under the correct key. In ibc-go v11, the attribute key for multi-token packets is `transfertypes.AttributeKeyTokens`. Add:

```go
// in x/cronos/events/events.go, RelayerValueDecoders
transfertypes.AttributeKeyTokens: ConvertTokens,
```

Also verify whether the `receiver`/`sender` indexed arguments for `FungibleTokenPacket` are correctly sourced from the SDK event attributes (they may differ from the `receiver`/`sender` keys used by bank events). [6](#0-5) 

---

### Proof of Concept

```go
func TestFungibleTokenPacketMissingDecoder(t *testing.T) {
    // Build a synthetic fungible_token_packet SDK event as ibc-go v11 emits it
    tokensJSON := `[{"denom":{"base":"uatom","trace":[]},"amount":"1000"}]`
    event := sdk.NewEvent(
        "fungible_token_packet",
        sdk.NewAttribute("receiver", "0xdeadbeef..."),
        sdk.NewAttribute("sender",   "cosmos1..."),
        sdk.NewAttribute("tokens",   tokensJSON),
    )

    log, err := events.RelayerConvertEvent(event)
    // EXPECT: err != nil, log == nil
    // ACTUAL: err = "no decoder for tokens"
    require.Error(t, err)
    require.Nil(t, log)
}
```

The test will pass (confirming the bug) without any fix. After adding `transfertypes.AttributeKeyTokens: ConvertTokens` to `RelayerValueDecoders`, the test should produce a valid `*ethtypes.Log` with no error.

### Citations

**File:** x/cronos/events/bindings/src/Relayer.sol (L60-64)
```text
    event FungibleTokenPacket(
        address indexed receiver,
        address indexed sender,
        Cosmos.Token[] tokens
    );
```

**File:** x/cronos/events/event.go (L23-35)
```go
func NewEventDescriptors(a abi.ABI) map[string]*EventDescriptor {
	descriptors := make(map[string]*EventDescriptor, len(a.Events))
	for _, event := range a.Events {
		event_type := toUnderScore(event.Name)
		descriptors[event_type] = &EventDescriptor{
			id:         event.ID,
			indexed:    getArguments(event.Inputs, true),
			nonIndexed: getArguments(event.Inputs, false),
			packValues: event.Inputs.NonIndexed().PackValues,
		}
	}
	return descriptors
}
```

**File:** x/cronos/events/event.go (L44-52)
```go
	for _, name := range attrNames {
		value, ok := attrs[name]
		if !ok {
			return nil, fmt.Errorf("attribute %s not found", name)
		}
		decode, ok := valueDecoders.GetDecoder(name)
		if !ok {
			return nil, fmt.Errorf("no decoder for %s", name)
		}
```

**File:** x/cronos/events/event.go (L88-91)
```go
	attrVals, err := makeFilter(valueDecoders, attrs, desc.nonIndexed, false)
	if err != nil {
		return nil, err
	}
```

**File:** x/cronos/events/decoders.go (L26-32)
```go
func (d ValueDecoders) GetDecoder(name string) (ValueDecoder, bool) {
	decoder, ok := d[name]
	if !ok {
		decoder, ok = d[""]
	}
	return decoder, ok
}
```

**File:** x/cronos/events/decoders.go (L88-99)
```go
func ConvertTokens(attributeValue string, _ bool) ([]any, error) {
	var tokens []transfertypes.Token
	err := json.Unmarshal([]byte(attributeValue), &tokens)
	if err != nil {
		return []any{}, err
	}
	evmTokens, err := sdkTokensToEvmTokens(tokens)
	if err != nil {
		return []any{}, err
	}
	return []any{evmTokens}, nil
}
```

**File:** x/cronos/events/events.go (L19-39)
```go
	RelayerValueDecoders = ValueDecoders{
		channeltypes.AttributeKeyDataHex:             ConvertPacketData,
		sdk.AttributeKeyAmount:                       ConvertAmount,
		banktypes.AttributeKeyRecipient:              ConvertAccAddressFromBech32,
		banktypes.AttributeKeySpender:                ConvertAccAddressFromBech32,
		banktypes.AttributeKeyReceiver:               ConvertAccAddressFromBech32,
		banktypes.AttributeKeySender:                 ConvertAccAddressFromBech32,
		banktypes.AttributeKeyMinter:                 ConvertAccAddressFromBech32,
		banktypes.AttributeKeyBurner:                 ConvertAccAddressFromBech32,
		channeltypes.AttributeKeySequence:            ConvertUint64,
		channeltypes.AttributeKeySrcPort:             ReturnStringAsIs,
		cronoseventstypes.AttributeKeySrcPortInfo:    ReturnStringAsIs,
		channeltypes.AttributeKeySrcChannel:          ReturnStringAsIs,
		cronoseventstypes.AttributeKeySrcChannelInfo: ReturnStringAsIs,
		channeltypes.AttributeKeyDstPort:             ReturnStringAsIs,
		channeltypes.AttributeKeyDstChannel:          ReturnStringAsIs,
		channeltypes.AttributeKeyConnectionID:        ReturnStringAsIs,
		transfertypes.AttributeKeyDenom:              ReturnStringAsIs,
		transfertypes.AttributeKeyRefundReceiver:     ConvertAccAddressFromBech32,
		transfertypes.AttributeKeyRefundTokens:       ReturnStringAsIs,
	}
```

**File:** x/cronos/events/events.go (L60-70)
```go
func RelayerConvertEvent(event sdk.Event) (*ethtypes.Log, error) {
	desc, ok := RelayerEvents[event.Type]
	if !ok {
		return nil, nil
	}
	replaceAttrs := map[string]string{
		cronoseventstypes.AttributeKeySrcPortInfo:    channeltypes.AttributeKeySrcPort,
		cronoseventstypes.AttributeKeySrcChannelInfo: channeltypes.AttributeKeySrcChannel,
	}
	return desc.ConvertEvent(event.Attributes, RelayerValueDecoders, replaceAttrs)
}
```

**File:** x/cronos/keeper/precompiles/relayer.go (L219-228)
```go
	converter := cronosevents.RelayerConvertEvent
	input := args[0].([]byte)
	e := &Executor{
		cdc:       bc.cdc,
		stateDB:   stateDB,
		caller:    contract.Caller(),
		contract:  precompileAddr,
		input:     input,
		converter: converter,
	}
```
