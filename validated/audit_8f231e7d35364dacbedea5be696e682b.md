The code evidence is clear. Let me verify the complete picture before rendering a verdict.

### Title
BlockList KV State Silently Dropped on Genesis Export/Re-initialization — (`x/cronos/genesis.go`)

### Summary

`ExportGenesis` in the cronos module never serializes the `KeyPrefixBlockList` KV store entry. Any genesis export — at any height, not only `height=-1` — produces a genesis file that is missing the blocklist blob. When nodes re-initialize from that genesis, `InitGenesis` restores nothing for the blocklist, `RefreshBlockList` reads a nil blob, and the proposal handler's in-memory blocklist is cleared. Previously blocked addresses can then submit transactions that are included in blocks.

### Finding Description

The blocklist blob is written to the cronos KV store by `MsgStoreBlockList`: [1](#0-0) 

It is read back by `GetBlockList`: [2](#0-1) 

`ExportGenesis` returns only `Params`, `ExternalContracts`, and `AutoContracts` — `KeyPrefixBlockList` is never included: [3](#0-2) 

`InitGenesis` correspondingly restores only those three fields: [4](#0-3) 

`KeyPrefixBlockList` is a distinct, persistent KV key in the cronos store: [5](#0-4) 

At startup (or after re-initialization), `RefreshBlockList` reads from the KV store and pushes the result into the proposal handler: [6](#0-5) 

`SetBlockList` with a nil/empty blob explicitly clears the in-memory blocklist: [7](#0-6) 

The `height=-1` path in `appExport` does pass `loadLatest=true`, which triggers `RefreshBlockList` during `app.New`, but this is irrelevant to the root cause — the omission exists for every export height: [8](#0-7) 

### Impact Explanation

After a genesis export and re-initialization (a standard chain upgrade/migration procedure), the blocklist KV entry is absent. `RefreshBlockList` reads nil, the proposal handler's blocklist is empty, and the `BlockAddressesDecorator` ante handler (which is populated from the same in-memory map) also has no entries. Addresses that were blocked on the exporting chain can now submit transactions that are included in blocks on all re-initialized nodes. This is a bypass of the block-list authorization check.

### Likelihood Explanation

Genesis exports are performed routinely during chain upgrades and migrations. Any chain that has an active blocklist and performs a genesis export will silently lose the blocklist on all re-initialized nodes. No special attacker action is required beyond waiting for the re-initialization and then transacting normally.

### Recommendation

Add `BlockList` to `GenesisState` proto and serialize/deserialize `KeyPrefixBlockList` in `ExportGenesis`/`InitGenesis`, mirroring how `ExternalContracts` and `AutoContracts` are handled. After `InitGenesis` restores the blob, call `RefreshBlockList` (or ensure it is called before the first block is processed) so the in-memory proposal handler is populated correctly.

### Proof of Concept

1. Start a Cronos chain with an active blocklist (store a non-empty encrypted blob via `MsgStoreBlockList`).
2. Confirm a transaction from a blocked address is excluded from blocks.
3. Run `cronosd export` (any height, including `-1`).
4. Inspect the exported genesis JSON: the `cronos` module state contains only `params`, `external_contracts`, and `auto_contracts` — no `block_list` field.
5. Re-initialize a new chain from the exported genesis (`cronosd init` + `cronosd start`).
6. Query `cronosd query cronos block-list` — returns empty.
7. Submit a transaction from the previously blocked address — it is now included in a block.

### Citations

**File:** x/cronos/keeper/msg_server.go (L124-124)
```go
	ctx.KVStore(k.storeKey).Set(types.KeyPrefixBlockList, msg.Blob)
```

**File:** x/cronos/keeper/keeper.go (L489-491)
```go
func (k Keeper) GetBlockList(ctx sdk.Context) []byte {
	return ctx.KVStore(k.storeKey).Get(types.KeyPrefixBlockList)
}
```

**File:** x/cronos/genesis.go (L16-55)
```go
func InitGenesis(ctx sdk.Context, k keeper.Keeper, genState types.GenesisState) {
	if err := k.SetParams(ctx, genState.Params); err != nil {
		panic(fmt.Sprintf("Invalid cronos module params: %v\n", genState.Params))
	}

	for _, m := range genState.ExternalContracts {
		// Only allow IBC, gravity, or cronos denoms at genesis.
		if !types.IsValidIBCDenom(m.Denom) && !types.IsValidGravityDenom(m.Denom) && !types.IsValidCronosDenom(m.Denom) {
			panic(fmt.Sprintf("Invalid denom to map to contract: %s", m.Denom))
		}
		if !common.IsHexAddress(m.Contract) {
			panic(fmt.Sprintf("Invalid contract address: %s", m.Contract))
		}
		if err := k.SetExternalContractForDenom(ctx, m.Denom, common.HexToAddress(m.Contract)); err != nil {
			panic(err)
		}
	}

	for _, m := range genState.AutoContracts {
		// Only allow IBC, gravity, or cronos denoms at genesis.
		if !types.IsValidIBCDenom(m.Denom) && !types.IsValidGravityDenom(m.Denom) && !types.IsValidCronosDenom(m.Denom) {
			panic(fmt.Sprintf("Invalid denom to map to contract: %s", m.Denom))
		}
		if !common.IsHexAddress(m.Contract) {
			panic(fmt.Sprintf("Invalid contract address: %s", m.Contract))
		}
		if err := k.SetAutoContractForDenom(ctx, m.Denom, common.HexToAddress(m.Contract)); err != nil {
			if errors.Is(err, types.ErrExternalMappingExists) || errors.Is(err, types.ErrDenomAlreadyMapped) {
				k.Logger(ctx).Info("skipping auto contract import, denom mapping already exists",
					"denom", m.Denom, "contract", m.Contract, "error", err)
				continue
			}
			panic(err)
		}
	}

	// this line is used by starport scaffolding # genesis/module/init

	// this line is used by starport scaffolding # ibc/genesis/init
}
```

**File:** x/cronos/genesis.go (L58-69)
```go
func ExportGenesis(ctx sdk.Context, k keeper.Keeper) *types.GenesisState {
	// this line is used by starport scaffolding # genesis/module/export

	// this line is used by starport scaffolding # ibc/genesis/export

	// Auto and external contracts are mutually exclusive for non-source denoms:
	// SetExternalContractForDenom retires any auto mapping for the same denom.
	return &types.GenesisState{
		Params:            k.GetParams(ctx),
		ExternalContracts: k.GetExternalContracts(ctx),
		AutoContracts:     k.GetAutoContracts(ctx),
	}
```

**File:** x/cronos/types/keys.go (L30-41)
```go
	prefixBlockList
)

// KVStore key prefixes
var (
	KeyPrefixDenomToExternalContract = []byte{prefixDenomToExternalContract}
	KeyPrefixDenomToAutoContract     = []byte{prefixDenomToAutoContract}
	KeyPrefixContractToDenom         = []byte{prefixContractToDenom}
	// ParamsKey is the key for params.
	ParamsKey                   = []byte{paramsKey}
	KeyPrefixAdminToPermissions = []byte{prefixAdminToPermissions}
	KeyPrefixBlockList          = []byte{prefixBlockList}
```

**File:** app/app.go (L1181-1188)
```go
		if err := app.RefreshBlockList(app.NewUncachedContext(false, cmtproto.Header{})); err != nil { //nolint:staticcheck
			if !cast.ToBool(appOpts.Get(FlagUnsafeIgnoreBlockListFailure)) {
				panic(err)
			}

			// otherwise, just emit error log
			app.Logger().Error("failed to update blocklist", "error", err)
		}
```

**File:** app/proposal.go (L221-223)
```go
	if len(blob) == 0 {
		h.blocklist = make(map[string]struct{})
		return nil
```

**File:** cmd/cronosd/cmd/root.go (L335-343)
```go
	if height != -1 {
		cronosApp = app.New(logger, db, false, appOpts)

		if err := cronosApp.LoadHeight(height); err != nil {
			return servertypes.ExportedApp{}, err
		}
	} else {
		cronosApp = app.New(logger, db, true, appOpts)
	}
```
