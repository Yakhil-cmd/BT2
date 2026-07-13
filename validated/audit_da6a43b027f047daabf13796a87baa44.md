### Title
Blocklist Enforcement Skipped During Block Execution — (`app/block_address.go`)

### Summary

`BlockAddressesDecorator.AnteHandle` gates all blocklist checks behind `ctx.IsCheckTx()`. During `FinalizeBlock` (block execution), `IsCheckTx()` returns `false`, so the entire blocklist guard is bypassed. A blocked address whose transaction reaches `FinalizeBlock` — via a validator that has no e2ee identity configured and therefore an empty `ProposalHandler.blocklist` — executes without any blocklist enforcement.

### Finding Description

The Cronos blocklist has two enforcement layers:

1. **Mempool / ante layer** — `BlockAddressesDecorator.AnteHandle` in `app/block_address.go` checks the static node-config blocklist, but only when `ctx.IsCheckTx()` is `true`.
2. **Proposal layer** — `ProposalHandler.ValidateTransaction` / `ProcessProposalHandler` in `app/proposal.go` checks the on-chain blocklist (decrypted from the e2ee-encrypted blob stored by `MsgStoreBlockList`), but only if `h.Identity != nil` and `len(h.blocklist) > 0`.

The critical gap is in layer 1:

```go
// app/block_address.go:32-83
func (bad BlockAddressesDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (newCtx sdk.Context, err error) {
    if ctx.IsCheckTx() {   // ← entire blocklist check is inside this branch
        // ... signer check, destination check, EIP-7702 check, MsgStoreBlockList admin check
    }
    return next(ctx, tx, simulate)   // ← always passes during FinalizeBlock
}
```

During `FinalizeBlock`, the SDK sets `IsCheckTx() = false`, so `next(ctx, tx, simulate)` is called unconditionally, with no blocklist check whatsoever.

Layer 2 (`ProcessProposalHandler`) is the only consensus-level guard, but it silently becomes a no-op for any validator that has not configured an e2ee identity:

```go
// app/proposal.go:210-213
func (h *ProposalHandler) SetBlockList(blob []byte) error {
    if h.Identity == nil {
        return nil   // ← blocklist stays empty; ProcessProposalHandler fast-paths to ACCEPT
    }
```

```go
// app/proposal.go:338-352
func (h *ProposalHandler) ProcessProposalHandler() sdk.ProcessProposalHandler {
    return func(ctx sdk.Context, req *abci.RequestProcessProposal) (*abci.ResponseProcessProposal, error) {
        if len(h.blocklist) == 0 {
            return &abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_ACCEPT}, nil
        }
```

### Impact Explanation

**High — Bypass of Cronos admin/governance blocklist authorization check.**

A blocked address can have transactions executed on-chain:

1. Admin stores an on-chain blocklist via `MsgStoreBlockList`; `StoreBlockList` in `msg_server.go` writes the encrypted blob to KV store.
2. `EndBlocker` calls `RefreshBlockList` → `ProposalHandler.SetBlockList`. Validators without an e2ee identity skip decryption; their `h.blocklist` remains empty.
3. The blocked address submits a transaction to any such validator's RPC. `CheckTx` runs `BlockAddressesDecorator` with `IsCheckTx() = true`, but the static `blockedMap` (built from the node config flag `blocked-addresses`) does not contain the on-chain-blocked address, so the tx is admitted to the mempool.
4. That validator proposes a block containing the blocked tx. Other validators without an identity accept it (`ProcessProposalHandler` fast-paths to `ACCEPT`).
5. `FinalizeBlock` executes the tx. `BlockAddressesDecorator.AnteHandle` is called with `IsCheckTx() = false` and passes through unconditionally — no blocklist check occurs.

The blocked address's transaction is executed on-chain, bypassing the governance-controlled blocklist entirely.

### Likelihood Explanation

The e2ee identity setup is a manual, per-validator configuration step. Validators that have not completed it (or newly joined validators) will silently have an empty blocklist. A blocked address only needs to discover one such validator's RPC endpoint to submit a transaction that will be proposed and accepted by the identity-less majority.

### Recommendation

Remove the `if ctx.IsCheckTx()` guard from `BlockAddressesDecorator.AnteHandle`, or add a separate execution-time check that reads the on-chain blocklist directly from the KV store during `FinalizeBlock`. The on-chain blocklist should be enforced at the message-server or ante-handler level unconditionally, not only at the mempool/proposal level.

```diff
// app/block_address.go
func (bad BlockAddressesDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (newCtx sdk.Context, err error) {
-   if ctx.IsCheckTx() {
        // signer / destination / EIP-7702 / MsgStoreBlockList admin checks
-   }
    return next(ctx, tx, simulate)
}
```

### Proof of Concept

1. Deploy a Cronos devnet where at least one validator has **no** e2ee identity configured (the default state for a new validator).
2. Via the admin account, call `MsgStoreBlockList` with a blob that encrypts `{"addresses": ["<attacker_bech32>"]}` for the validators that do have an identity. The on-chain blob is stored; validators with an identity update their `ProposalHandler.blocklist`.
3. From the attacker address, submit a `MsgEthereumTx` (e.g., a CRO transfer) to the RPC endpoint of the validator **without** an identity. `CheckTx` passes (static `blockedMap` does not contain the attacker; on-chain blocklist is not consulted here).
4. The identity-less validator proposes a block containing the attacker's tx. Other identity-less validators accept it via `ProcessProposalHandler` (fast-path `ACCEPT` because `len(h.blocklist) == 0`).
5. `FinalizeBlock` executes the tx. `BlockAddressesDecorator.AnteHandle` is called with `ctx.IsCheckTx() == false` and skips all checks. The transfer succeeds on-chain.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** app/proposal.go (L209-213)
```go
// SetBlockList don't fail if the identity is not set or the block list is empty.
func (h *ProposalHandler) SetBlockList(blob []byte) error {
	if h.Identity == nil {
		return nil
	}
```

**File:** app/proposal.go (L338-352)
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
```

**File:** app/app.go (L1323-1334)
```go
func (app *App) EndBlocker(ctx sdk.Context) (sdk.EndBlock, error) {
	rsp, err := app.ModuleManager.EndBlock(ctx)
	if err := app.RefreshBlockList(ctx); err != nil {
		app.Logger().Error("failed to update blocklist", "error", err)
	}
	return rsp, err
}

func (app *App) RefreshBlockList(ctx sdk.Context) error {
	// refresh blocklist
	return app.blockProposalHandler.SetBlockList(app.CronosKeeper.GetBlockList(ctx))
}
```
