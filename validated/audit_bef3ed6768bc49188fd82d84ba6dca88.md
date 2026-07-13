### Title
`registerPayee` and `registerCounterpartyPayee` Missing from Relayer Precompile Dispatch — (`File: x/cronos/keeper/precompiles/relayer.go`)

### Summary

The `RelayerContract.Run()` method in the Cronos relayer precompile dispatches calls via a `switch` on `method.Name`. Three methods declared in the ABI (`submitMisbehaviour`, `registerPayee`, `registerCounterpartyPayee`) have no corresponding `case` in the switch, causing every call to them to permanently fail with `"unknown method"`.

### Finding Description

The `IRelayerFunctions` Solidity interface exposes 20 methods, including `registerPayee` and `registerCounterpartyPayee`: [1](#0-0) 

Both methods are declared as named constants in the Go implementation: [2](#0-1) 

Gas costs are assigned for them in `init()`: [3](#0-2) 

However, the `Run()` dispatch switch handles only 16 methods and has no `case` for `RegisterPayee`, `RegisterCounterpartyPayee`, or `SubmitMisbehaviour`. Any call to these methods falls through to: [4](#0-3) 

The full switch covers `CreateClient` through `TimeoutOnClose` but never `RegisterPayee` or `RegisterCounterpartyPayee`: [5](#0-4) 

This is structurally identical to the external bug: a function is present in the routing interface (ABI / diamond cut) but absent from the actual dispatch table (`Run()` switch / `FacetCut` selectors), making it permanently unreachable.

### Impact Explanation

Any EVM contract or unprivileged user calling `registerPayee` or `registerCounterpartyPayee` on the relayer precompile at address `0x0000000000000000000000000000000000000065` will always receive an error. This permanently prevents the use of these precompile functions for IBC fee middleware registration. Relayers that rely on the EVM precompile path (e.g., smart-contract-based relayers like `TestRelayer`) cannot register payee addresses, permanently blocking their ability to receive IBC incentivized fees through this interface. [6](#0-5) 

**Impact class:** High — permanent inability for honest users to process valid precompile calls (`registerPayee`, `registerCounterpartyPayee`).

### Likelihood Explanation

Any unprivileged caller can trigger this. No special permissions, leaked keys, or admin compromise are required. The methods are publicly advertised in the ABI and have gas costs assigned, so callers have every reason to expect them to work. The failure is silent at the ABI level (the method resolves correctly, gas is charged, but execution always errors).

### Recommendation

Add `case` branches for `RegisterPayee`, `RegisterCounterpartyPayee`, and `SubmitMisbehaviour` in `RelayerContract.Run()`, wiring them to the appropriate IBC fee keeper and light-client keeper methods, analogous to how the other methods are handled.

```go
case RegisterPayee:
    // wire to ibcFeeKeeper.RegisterPayee
case RegisterCounterpartyPayee:
    // wire to ibcFeeKeeper.RegisterCounterpartyPayee
case SubmitMisbehaviour:
    res, err = exec(e, bc.ibcKeeper.SubmitMisbehaviour)
```

### Proof of Concept

1. Deploy any contract that calls `registerPayee(portID, channelID, payeeAddr)` on the precompile at `0x65`.
2. The ABI lookup succeeds (`irelayerABI.MethodById` returns the method), gas is computed via `RequiredGas`, but `Run()` hits `default` and returns `"unknown method: registerPayee"`.
3. The transaction reverts. The payee is never registered. The same applies to `registerCounterpartyPayee`.

This can be confirmed by inspecting `TestRelayer.callRegisterPayee` — it calls `relayer.registerPayee(...)` and `require(result, "call failed")`, which will always revert against the current precompile implementation. [7](#0-6)

### Citations

**File:** x/cronos/events/bindings/src/RelayerFunctions.sol (L23-24)
```text
    function registerPayee(string calldata portID, string calldata channelID, address payeeAddr) external payable returns (bool);
    function registerCounterpartyPayee(string calldata portID, string calldata channelID, string calldata counterpartyPayeeAddr) external payable returns (bool);
```

**File:** x/cronos/keeper/precompiles/relayer.go (L50-51)
```go
	RegisterPayee                   = "registerPayee"
	RegisterCounterpartyPayee       = "registerCounterpartyPayee"
```

**File:** x/cronos/keeper/precompiles/relayer.go (L95-98)
```go
		case RegisterPayee:
			relayerGasRequiredByMethod[methodID] = 38000
		case RegisterCounterpartyPayee:
			relayerGasRequiredByMethod[methodID] = 37000
```

**File:** x/cronos/keeper/precompiles/relayer.go (L229-266)
```go
	switch method.Name {
	case CreateClient:
		res, err = exec(e, bc.ibcKeeper.CreateClient)
	case UpdateClient:
		res, err = exec(e, bc.ibcKeeper.UpdateClient)
	case UpgradeClient:
		res, err = exec(e, bc.ibcKeeper.UpgradeClient)
	case ConnectionOpenInit:
		res, err = exec(e, bc.ibcKeeper.ConnectionOpenInit)
	case ConnectionOpenTry:
		res, err = exec(e, bc.ibcKeeper.ConnectionOpenTry)
	case ConnectionOpenAck:
		res, err = exec(e, bc.ibcKeeper.ConnectionOpenAck)
	case ConnectionOpenConfirm:
		res, err = exec(e, bc.ibcKeeper.ConnectionOpenConfirm)
	case ChannelOpenInit:
		res, err = exec(e, bc.ibcKeeper.ChannelOpenInit)
	case ChannelOpenTry:
		res, err = exec(e, bc.ibcKeeper.ChannelOpenTry)
	case ChannelOpenAck:
		res, err = exec(e, bc.ibcKeeper.ChannelOpenAck)
	case ChannelOpenConfirm:
		res, err = exec(e, bc.ibcKeeper.ChannelOpenConfirm)
	case ChannelCloseInit:
		res, err = exec(e, bc.ibcKeeper.ChannelCloseInit)
	case ChannelCloseConfirm:
		res, err = exec(e, bc.ibcKeeper.ChannelCloseConfirm)
	case RecvPacket:
		res, err = exec(e, bc.ibcKeeper.RecvPacket)
	case Acknowledgement:
		res, err = exec(e, bc.ibcKeeper.Acknowledgement)
	case Timeout:
		res, err = exec(e, bc.ibcKeeper.Timeout)
	case TimeoutOnClose:
		res, err = exec(e, bc.ibcKeeper.TimeoutOnClose)
	default:
		return nil, fmt.Errorf("unknown method: %s", method.Name)
	}
```

**File:** integration_tests/contracts/contracts/TestRelayer.sol (L19-31)
```text
    function callRegisterPayee(string calldata portID, string calldata channelID, address payeeAddr) public returns (bool) {
        require(payee == address(0) || payee == msg.sender, "register fail");
        bool result = relayer.registerPayee(portID, channelID, payeeAddr);
        require(result, "call failed");
        payee = msg.sender;
    }

    function callRegisterCounterpartyPayee(string calldata portID, string calldata channelID, string calldata counterpartyPayeeAddr) public returns (bool) {
        require(counterpartyPayee == address(0) || counterpartyPayee == msg.sender, "register fail");
        bool result = relayer.registerCounterpartyPayee(portID, channelID, counterpartyPayeeAddr);
        require(result, "call failed");
        counterpartyPayee = msg.sender;
    }
```
