### Title
Block-List Enforcement Skipped During `FinalizeBlock` Due to `IsCheckTx`-Only Guard - (File: `app/block_address.go`)

### Summary

`BlockAddressesDecorator.AnteHandle` wraps every block-list check inside `if ctx.IsCheckTx()`. Because Cosmos SDK ante handlers execute during both `CheckTx` (mempool admission) and `FinalizeBlock` (block execution), the guard causes the entire enforcement to be silently skipped at execution time. Any validator can include a transaction from a blocked address in a proposed block; every other validator will execute it during `FinalizeBlock` with no rejection.

### Finding Description

`app/block_address.go` registers `BlockAddressesDecorator` as an `ExtraDecorator` in the ante-handler chain. The decorator is responsible for rejecting transactions whose signers, EVM destinations, or EIP-7702 authorization targets appear in the static startup block list.

The entire body of the check is gated on a single condition:

```go
func (bad BlockAddressesDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (newCtx sdk.Context, err error) {
    if ctx.IsCheckTx() {          // ← guard covers ALL enforcement
        // signer check
        // EVM destination check
        // EIP-7702 authority / target check
        // MsgStoreBlockList admin check
    }
    return next(ctx, tx, simulate)   // ← always passes during FinalizeBlock
}
```

`ctx.IsCheckTx()` returns `true` only during `CheckTx` and `ReCheckTx`. During `FinalizeBlock` it returns `false`, so the decorator unconditionally calls `next(ctx, tx, simulate)` without performing any check.

The dynamic on-chain block list has a separate consensus-layer guard in `ProposalHandler.ProcessProposalHandler()` (`app/proposal.go`), but the static startup block list has no equivalent `ProcessProposal` enforcement. A block containing a transaction from a startup-blocked address will pass `ProcessProposal` and be executed by every validator during `FinalizeBlock`.

### Impact Explanation

This is a direct bypass of the block-list authorization check. Once a single validator (malicious or simply not configured with the block list) proposes a block containing a transaction from a blocked address, every honest validator executes it during `FinalizeBlock` without any rejection. The blocked address can perform arbitrary EVM transactions — including CRO/CRC20/CRC21 transfers, IBC bridge operations, and precompile calls — that the block list was specifically intended to prevent.

This maps to the allowed High impact: **"Bypass of Cronos admin, governance authority, permission, token-mapping, bridge, block-list, or module-account authorization checks."**

### Likelihood Explanation

The attacker needs only one validator to include their transaction. This can be achieved by submitting the transaction directly to a validator's RPC endpoint that either does not have the startup block list configured or is operated by a colluding party. No key compromise, governance action, or cryptographic break is required. The blocked address is unprivileged by definition.

### Recommendation

Remove the `if ctx.IsCheckTx()` wrapper so that block-list enforcement runs unconditionally during both `CheckTx` and `FinalizeBlock`:

```go
func (bad BlockAddressesDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (newCtx sdk.Context, err error) {
    // enforce on every execution path, not only CheckTx
    if sigTx, ok := tx.(signing.SigVerifiableTx); ok { ... }
    for _, msg := range tx.GetMsgs() { ... }
    return next(ctx, tx, simulate)
}
```

Alternatively, mirror the pattern used for the dynamic block list and add a `ProcessProposal` check for the startup block list so that blocks containing blocked-address transactions are rejected at the consensus layer before `FinalizeBlock` is reached.

### Proof of Concept

1. Configure all validators with address `X` in the startup block list.
2. Operate (or compromise) one validator that does **not** have the block list, or that submits a block directly.
3. From address `X`, sign a `MsgEthereumTx` transferring CRO to another address.
4. Submit the transaction directly to the non-configured validator's RPC; it passes `CheckTx` (no block list on that node) and is included in the proposed block.
5. During `ProcessProposal` on honest validators: `ProposalHandler` only checks the dynamic on-chain block list — the startup block list is not checked here — so the block is accepted.
6. During `FinalizeBlock` on every validator: `BlockAddressesDecorator.AnteHandle` is called with `ctx.IsCheckTx() == false`; the entire enforcement block is skipped; the transaction executes and the CRO transfer succeeds. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** app/block_address.go (L32-83)
```go
func (bad BlockAddressesDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (newCtx sdk.Context, err error) {
	if ctx.IsCheckTx() {
		if sigTx, ok := tx.(signing.SigVerifiableTx); ok {
			signers, err := sigTx.GetSigners()
			if err != nil {
				return ctx, err
			}
			for _, signer := range signers {
				if _, ok := bad.blockedMap[sdk.AccAddress(signer).String()]; ok {
					return ctx, fmt.Errorf("signer is blocked: %s", sdk.AccAddress(signer).String())
				}
			}
		}

		for _, msg := range tx.GetMsgs() {
			msgEthTx, ok := msg.(*evmtypes.MsgEthereumTx)
			if ok {
				ethTx := msgEthTx.AsTransaction()
				// check the destination address
				if ethTx.To() != nil {
					if _, ok := bad.blockedMap[sdk.AccAddress(ethTx.To().Bytes()).String()]; ok {
						return ctx, fmt.Errorf("destination address is blocked: %s", sdk.AccAddress(ethTx.To().Bytes()).String())
					}
				}
				// check EIP-7702 authorisation list
				if ethTx.SetCodeAuthorizations() != nil {
					for _, auth := range ethTx.SetCodeAuthorizations() {
						addr, err := auth.Authority()
						if err == nil {
							if _, ok := bad.blockedMap[sdk.AccAddress(addr.Bytes()).String()]; ok {
								return ctx, fmt.Errorf("signer is blocked: %s", addr.String())
							}
						}
						// check the target address
						if _, ok := bad.blockedMap[sdk.AccAddress(auth.Address.Bytes()).String()]; ok {
							return ctx, fmt.Errorf("authorisation address is blocked: %s", sdk.AccAddress(auth.Address.Bytes()).String())
						}
					}
				}
			}
		}

		admin := bad.getParams(ctx).CronosAdmin
		for _, msg := range tx.GetMsgs() {
			if blocklistMsg, ok := msg.(*types.MsgStoreBlockList); ok {
				if admin != blocklistMsg.From {
					return ctx, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
				}
			}
		}
	}
	return next(ctx, tx, simulate)
```

**File:** app/app.go (L1254-1272)
```go
	blockAddressDecorator := NewBlockAddressesDecorator(blockedMap, app.CronosKeeper.GetParams)
	options := evmante.HandlerOptions{
		AccountKeeper:          app.AccountKeeper,
		BankKeeper:             app.BankKeeper,
		FeegrantKeeper:         app.FeeGrantKeeper,
		IBCKeeper:              app.IBCKeeper,
		EvmKeeper:              app.EvmKeeper,
		FeeMarketKeeper:        app.FeeMarketKeeper,
		SignModeHandler:        txConfig.SignModeHandler(),
		SigGasConsumer:         evmante.DefaultSigVerificationGasConsumer,
		ExtensionOptionChecker: ethermint.HasDynamicFeeExtensionOption,
		DynamicFeeChecker:      true,
		DisabledAuthzMsgs: []string{
			sdk.MsgTypeURL(&evmtypes.MsgEthereumTx{}),
			sdk.MsgTypeURL(&vestingtypes.MsgCreateVestingAccount{}),
			sdk.MsgTypeURL(&vestingtypes.MsgCreatePermanentLockedAccount{}),
			sdk.MsgTypeURL(&vestingtypes.MsgCreatePeriodicVestingAccount{}),
		},
		ExtraDecorators:   []sdk.AnteDecorator{blockAddressDecorator},
```

**File:** app/proposal.go (L338-353)
```go
func (h *ProposalHandler) ProcessProposalHandler() sdk.ProcessProposalHandler {
	return func(ctx sdk.Context, req *abci.RequestProcessProposal) (*abci.ResponseProcessProposal, error) {
		if len(h.blocklist) == 0 {
			// fast path, accept all txs
			return &abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_ACCEPT}, nil
		}

		for _, txBz := range req.Txs {
			if err := h.ValidateTransaction(nil, txBz); err != nil {
				return &abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_REJECT}, nil
			}
		}

		return &abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_ACCEPT}, nil
	}
}
```
