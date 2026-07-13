Looking at the Cronos codebase, I need to trace the blocklist enforcement lifecycle carefully to find a timing analog to the TaikoL1 pause/cooldown-window bug.

**Key flow I traced:**

1. `MsgStoreBlockList` writes the encrypted blob to KV store during `FinalizeBlock` (DeliverTx)
2. `RefreshBlockList` → `SetBlockList` is called in `EndBlocker` — updating the **in-memory** `ProposalHandler.blocklist`
3. `PrepareProposal` and `ProcessProposal` both use the **in-memory** `ProposalHandler.blocklist` to filter txs
4. `BlockAddressesDecorator.AnteHandle` only checks the blocklist when `ctx.IsCheckTx()` is true — **not during DeliverTx**

This creates a one-block timing gap that is a direct structural analog to the TaikoL1 pause/cooldown-window bug.

---

### Title
Blocklist Update Takes Effect One Block Late, Allowing a Newly-Blocked Address to Execute a Transaction in the Same Block as `MsgStoreBlockList` — (File: `app/app.go`, `app/proposal.go`)

### Summary
The Cronos blocklist is enforced via an in-memory map (`ProposalHandler.blocklist`) that is only refreshed in `EndBlocker`, one full block after `MsgStoreBlockList` is executed. Because `PrepareProposal` and `ProcessProposal` read the stale in-memory map, and because `BlockAddressesDecorator` skips the check during `DeliverTx`, a transaction from a newly-blocked address that is already in the mempool will pass all filters and be executed in the same block as the blocklist update. This is a one-block bypass of the block-list authorization check reachable by any unprivileged user.

### Finding Description

**Root cause — one-block stale window:**

`EndBlocker` calls `RefreshBlockList` after all transactions in the block have been executed: [1](#0-0) 

`RefreshBlockList` reads the KV store and calls `SetBlockList` to update the in-memory map: [2](#0-1) 

`PrepareProposal` (via `ExtTxSelector.SelectTxForProposal`) calls `validateTx`, which delegates to `ProposalHandler.ValidateTransaction`. This function reads only the **in-memory** `h.blocklist`: [3](#0-2) 

`ProcessProposalHandler` also reads only the in-memory map: [4](#0-3) 

`BlockAddressesDecorator` — the ante-handler path — explicitly skips the blocklist check during `DeliverTx` (only runs when `ctx.IsCheckTx()` is true): [5](#0-4) 

**Exploit path (block-by-block):**

| Step | What happens |
|------|-------------|
| Pre-block N | Address A submits tx → passes `CheckTx` (not yet blocklisted) → sits in mempool |
| Block N `PrepareProposal` | In-memory blocklist = state after block N-1; A is not blocked → A's tx is selected |
| Block N `ProcessProposal` | Same stale in-memory blocklist → all validators accept the block |
| Block N `FinalizeBlock` | `MsgStoreBlockList` (adding A) is executed → KV store updated; A's tx is also executed (no blocklist check at DeliverTx) |
| Block N `EndBlocker` | `RefreshBlockList` → in-memory blocklist now includes A |
| Block N+1 | A's future txs are filtered |

The attacker does not need to know they are being blocklisted. Any tx from A that is already in the mempool when the admin submits `MsgStoreBlockList` can be co-included in the same block. The attacker can also observe the opaque `MsgStoreBlockList` tx in the mempool and front-run it by submitting their own tx in the same round.

### Impact Explanation

This is a direct bypass of the block-list authorization check — explicitly listed as **High** impact in the allowed scope: *"Bypass of Cronos admin, governance authority, permission, token-mapping, bridge, block-list, or module-account authorization checks."*

A blocked address can execute exactly one transaction (any Cosmos or EVM tx) in the same block as the blocklist update. Depending on the transaction, this could include: transferring CRO or CRC20/IBC tokens out before the block takes effect, calling a bridge or IBC precompile, or executing an arbitrary EVM call. The admin's security invariant — that the address is blocked from the moment `MsgStoreBlockList` is committed — is violated.

### Likelihood Explanation

The precondition is low-friction: the attacker only needs a pending transaction in the mempool at the time the admin submits `MsgStoreBlockList`. This is a realistic scenario because:
- Blocklisting is typically a reactive measure (triggered by observed malicious activity), meaning the attacker is likely actively transacting at the time.
- The attacker can also observe the `MsgStoreBlockList` tx in the mempool (its content is encrypted but its existence is visible) and immediately submit a tx to race into the same block.
- No privileged access is required.

### Recommendation

Refresh the blocklist from the KV store at the start of `PrepareProposal` and `ProcessProposal` rather than relying on the `EndBlocker`-updated in-memory map. Alternatively, enforce the blocklist check during `FinalizeBlock` (i.e., remove the `ctx.IsCheckTx()` guard in `BlockAddressesDecorator` or add a separate `DeliverTx`-time check) so that even if a blocked tx is included in a proposal, it is rejected at execution time.

### Proof of Concept

1. Address A submits `MsgEthereumTx` (e.g., a large CRO transfer) → enters mempool, passes `CheckTx`.
2. Admin submits `MsgStoreBlockList` encrypting `{"addresses": ["<A>"]}` → enters mempool.
3. Proposer builds block N: `PrepareProposal` reads stale in-memory blocklist (A not yet blocked) → includes both txs.
4. All validators run `ProcessProposal` with the same stale blocklist → accept the block.
5. `FinalizeBlock`: `MsgStoreBlockList` is executed (KV store updated); A's `MsgEthereumTx` is also executed — `BlockAddressesDecorator` skips the check because `IsCheckTx()` is false.
6. `EndBlocker`: `RefreshBlockList` → A is now in the in-memory blocklist.
7. Result: A's transfer succeeded despite the admin's intent to block A before it could execute.

### Citations

**File:** app/app.go (L1322-1334)
```go
// EndBlocker application updates every end block
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

**File:** app/proposal.go (L262-266)
```go
func (h *ProposalHandler) ValidateTransaction(tx sdk.Tx, txBz []byte) error {
	if len(h.blocklist) == 0 {
		// fast path, accept all txs
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

**File:** app/block_address.go (L32-33)
```go
func (bad BlockAddressesDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (newCtx sdk.Context, err error) {
	if ctx.IsCheckTx() {
```
