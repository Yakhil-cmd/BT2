### Title
`ProcessProposalHandler` Accepts All Transactions Unconditionally When Blocklist Is Empty, Allowing Malicious Proposer to Bloat Block Store with Invalid Transactions - (File: app/proposal.go)

### Summary
Cronos's custom `ProcessProposalHandler` in `app/proposal.go` contains a fast-path that unconditionally accepts every transaction in a proposed block when no e2ee blocklist is configured (the default). Even when a blocklist is active, the handler only checks address membership — it performs no signature verification, no ante-handler validation, and no decode check. A malicious proposer can therefore fill every block they propose with garbage or invalid transaction bytes up to `MaxBlockSize`, and all honest validators will accept the block.

### Finding Description

In `app/app.go`, when `mempoolMaxTxs < 0 || feeBump < 0`, the app falls back to `mempool.NoOpMempool{}`: [1](#0-0) 

The developers were aware that the SDK's default `ProcessProposal` is a no-op with `NoOpMempool`, so they replaced it with a custom handler: [2](#0-1) 

However, the replacement handler (`ProposalHandler.ProcessProposalHandler`) only guards against the e2ee blocklist. When `h.blocklist` is empty — the default state for any node that has not configured an encrypted blocklist — it immediately returns `ACCEPT` for every transaction in the proposal without any validation: [3](#0-2) 

Even when a blocklist is present, `ValidateTransaction` only checks whether a signer or destination address appears in the blocklist. It performs no decode check on raw bytes, no signature verification, and no ante-handler execution: [4](#0-3) 

The `PrepareProposal` path has the same gap: `ExtTxSelector.SelectTxForProposal` calls `ts.validateTx` which resolves to `ValidateTransaction`, and with an empty blocklist it is a no-op fast path that accepts every byte slice passed by the proposer: [5](#0-4) 

### Impact Explanation

A malicious proposer can craft a `RequestPrepareProposal` whose `Txs` field is filled with arbitrary garbage bytes up to `MaxBlockSize`. Because `ProcessProposalHandler` returns `ACCEPT` unconditionally (empty-blocklist fast path), every honest validator accepts the block. CometBFT stores the raw transaction bytes of every included transaction in its BlockStore permanently. This constitutes **invalid block acceptance** triggered via the proposal path by a validator acting as proposer — matching the Critical impact category ("invalid block acceptance… triggered by… proposal path… or mempool/proposal interaction").

Secondary effects include permanent disk bloat on every full node and future syncing node, increased block propagation bandwidth, and elevated CPU/memory during block processing.

### Likelihood Explanation

The empty-blocklist fast path is the **default configuration** for all Cronos nodes. The e2ee blocklist feature requires validators to explicitly configure an age identity and a blocklist blob; without that, `h.blocklist` is always an empty map. Any validator who becomes a proposer (rotation is deterministic and unprivileged within the validator set) can exploit this without any additional precondition.

### Recommendation

`ProcessProposalHandler` should validate every transaction in the proposal beyond blocklist membership. At minimum, each raw byte slice should be decoded with the app's `TxDecoder` and run through the ante handler (or a lightweight validity check) before the block is accepted. The `ValidateTransaction` function should not short-circuit to `nil` when the blocklist is empty; decoding and basic structural validity should always be enforced. Consider mirroring the ante-handler check already present in the `mempool.type=app` path (`InsertTxHandler` runs `RunTx(execModeCheck)`) inside `ProcessProposalHandler` so that all proposal paths enforce the same admission criteria.

### Proof of Concept

1. Operator A is a validator whose turn it is to propose a block.
2. Operator A constructs a `RequestPrepareProposal` with `Txs` = `[<1 MB of random bytes>, <1 MB of random bytes>, …]` up to `MaxBlockSize`.
3. Cronos's `PrepareProposalHandler` (NoOpMempool path, empty blocklist) calls `ExtTxSelector.SelectTxForProposal` → `ValidateTransaction` → fast-path `return nil` → all byte slices are selected.
4. The proposed block is broadcast to all validators.
5. Each validator's `ProcessProposalHandler` hits `len(h.blocklist) == 0` → returns `ACCEPT` immediately.
6. CometBFT commits the block; all raw garbage bytes are written to every node's BlockStore permanently.
7. Repeat every block the malicious proposer is scheduled, filling the chain's storage with invalid data.

### Citations

**File:** app/app.go (L478-481)
```go
	} else {
		logger.Info("NoOpMempool is enabled")
		mpool = mempool.NoOpMempool{}
	}
```

**File:** app/app.go (L543-545)
```go
		// The default process proposal handler do nothing when the mempool is noop,
		// so we just implement a new one.
		app.SetProcessProposal(blockProposalHandler.ProcessProposalHandler())
```

**File:** app/proposal.go (L82-84)
```go
	if err := ts.validateTx(memTx, txBz); err != nil {
		return isFull() // blocked/invalid: skip, keep scanning
	}
```

**File:** app/proposal.go (L262-293)
```go
func (h *ProposalHandler) ValidateTransaction(tx sdk.Tx, txBz []byte) error {
	if len(h.blocklist) == 0 {
		// fast path, accept all txs
		return nil
	}

	var err error
	if tx == nil {
		tx, err = h.TxDecoder(txBz)
		if err != nil {
			return err
		}
	}

	sigTx, ok := tx.(signing.SigVerifiableTx)
	if !ok {
		return fmt.Errorf("tx of type %T does not implement SigVerifiableTx", tx)
	}

	signers, err := sigTx.GetSigners()
	if err != nil {
		return err
	}
	for _, signer := range signers {
		encoded, err := h.addressCodec.BytesToString(signer)
		if err != nil {
			return fmt.Errorf("invalid bech32 address: %s, err: %w", signer, err)
		}
		if _, ok := h.blocklist[encoded]; ok {
			return fmt.Errorf("signer is blocked: %s", encoded)
		}
	}
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
