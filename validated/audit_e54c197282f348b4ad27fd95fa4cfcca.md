### Title
Blocklist Enforcement Only Checks Outer EVM Transaction Destination, Not Internal EVM Calls — (File: app/proposal.go)

### Summary
The Cronos blocklist system enforces address restrictions only on the outer `to` field of EVM transactions during `PrepareProposal`/`ProcessProposal`. Internal EVM calls (contract-to-contract calls) are never inspected. An unprivileged attacker can route CRO, ERC20, CRC20, or CRC21 tokens to a blocklisted address through an intermediate contract, fully bypassing the admin-controlled blocklist.

### Finding Description

**Two-layer enforcement gap:**

**Layer 1 — `BlockAddressesDecorator` (ante handler):**
The decorator in `app/block_address.go` wraps all its checks inside `if ctx.IsCheckTx()`. [1](#0-0) 

This means the decorator is a no-op during `FinalizeBlock` (block execution). It only gates mempool admission, not actual state transitions.

**Layer 2 — `ProposalHandler.ValidateTransaction` (PrepareProposal / ProcessProposal):**
The proposal-time check in `app/proposal.go` inspects only the outer `ethTx.To()` field of each `MsgEthereumTx`: [2](#0-1) 

It iterates over `tx.GetMsgs()` and for each `MsgEthereumTx` checks the top-level destination. It has no visibility into internal EVM calls (CALL/DELEGATECALL/STATICCALL opcodes) that occur during contract execution.

**`ProcessProposalHandler` accepts all blocks when blocklist is empty:**
`SetBlockList` silently returns `nil` when `h.Identity == nil` (validator has no e2ee key), leaving `h.blocklist` empty. `ProcessProposalHandler` then fast-paths to `ACCEPT` for every block: [3](#0-2) [4](#0-3) 

**No EVM-execution-level enforcement:**
Neither the EVM hooks nor the precompiles enforce the dynamic Cronos blocklist. The `BankContract.checkBlockedAddr` in `x/cronos/keeper/precompiles/bank.go` only checks the SDK's static `bankKeeper.BlockedAddr` (module accounts), not the dynamic on-chain blocklist stored by `MsgStoreBlockList`: [5](#0-4) 

**Dynamic blocklist storage path:**
`MsgStoreBlockList` writes the encrypted blob to KV store; `RefreshBlockList` (called in `EndBlocker`) decrypts it into the in-memory `ProposalHandler.blocklist`: [6](#0-5) 

This blocklist is only consulted at proposal time, never during EVM execution.

### Impact Explanation

This is a **High** impact finding: bypass of the Cronos admin block-list authorization check. A blocked address can receive CRO, IBC vouchers, CRC20, or CRC21 tokens via an intermediate contract. The blocklist was explicitly extended to cover destination addresses (CHANGELOG v1.6.0, PR #1922), confirming the intent to prevent blocked addresses from receiving funds. The internal-call path defeats that intent entirely. [7](#0-6) 

### Likelihood Explanation

Medium. Any unprivileged user can deploy a trivial forwarding contract. No special privileges, leaked keys, or validator access are required. The attacker only needs to know the blocked address and be able to send a transaction to a non-blocked contract.

### Recommendation

Enforce the blocklist at EVM execution time, not only at proposal time. Options:
1. Add a `StateDB` hook or EVM tracer that checks every internal call's recipient against the dynamic blocklist and reverts if matched.
2. Alternatively, document explicitly that the blocklist only prevents direct (outer) transactions and does not prevent indirect fund receipt via contracts.

### Proof of Concept

1. Admin calls `MsgStoreBlockList` to add address `B` to the dynamic blocklist.
2. `RefreshBlockList` (called in `EndBlocker`) loads the blocklist into `ProposalHandler.blocklist`.
3. Attacker deploys forwarding contract `C`:
   ```solidity
   contract Forwarder {
       function forward(address payable to) external payable {
           to.transfer(msg.value);
       }
   }
   ```
4. Attacker sends an EVM transaction: `to = C` (not blocked), calling `forward(B)` with ETH value.
5. `PrepareProposal`/`ProcessProposal` check `ethTx.To() = C` — not in blocklist — transaction is included. [8](#0-7) 
6. During `FinalizeBlock`, `BlockAddressesDecorator` is a no-op (`!IsCheckTx()`). [1](#0-0) 
7. EVM executes the transaction; `C` internally calls `B.transfer(amount)`.
8. `B` receives ETH/tokens despite being on the blocklist — the restriction is bypassed.

### Citations

**File:** app/block_address.go (L32-33)
```go
func (bad BlockAddressesDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (newCtx sdk.Context, err error) {
	if ctx.IsCheckTx() {
```

**File:** app/proposal.go (L209-213)
```go
// SetBlockList don't fail if the identity is not set or the block list is empty.
func (h *ProposalHandler) SetBlockList(blob []byte) error {
	if h.Identity == nil {
		return nil
	}
```

**File:** app/proposal.go (L262-336)
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

	for _, msg := range tx.GetMsgs() {
		msgEthTx, ok := msg.(*evmtypes.MsgEthereumTx)
		if ok {
			ethTx := msgEthTx.AsTransaction()
			// check the destination address
			if ethTx.To() != nil {
				encoded, err := h.addressCodec.BytesToString(ethTx.To().Bytes())
				if err != nil {
					return fmt.Errorf("invalid bech32 address: %s, err: %w", ethTx.To(), err)
				}
				if _, ok := h.blocklist[encoded]; ok {
					return fmt.Errorf("destination address is blocked: %s", encoded)
				}
			}
			// check EIP-7702 authorisation list
			if ethTx.SetCodeAuthorizations() != nil {
				for _, auth := range ethTx.SetCodeAuthorizations() {
					addr, err := auth.Authority()
					if err == nil {
						encoded, err := h.addressCodec.BytesToString(addr.Bytes())
						if err != nil {
							return fmt.Errorf("invalid bech32 address: %s, err: %w", addr, err)
						}
						if _, ok := h.blocklist[encoded]; ok {
							return fmt.Errorf("signer is blocked: %s", encoded)
						}
					}
					// check the target address
					encoded, err := h.addressCodec.BytesToString(auth.Address.Bytes())
					if err != nil {
						return fmt.Errorf("invalid bech32 address: %s, err: %w", auth.Address, err)
					}
					if _, ok := h.blocklist[encoded]; ok {
						return fmt.Errorf("authorisation address is blocked: %s", encoded)
					}
				}
			}
		}
	}

	return nil
}
```

**File:** app/proposal.go (L338-343)
```go
func (h *ProposalHandler) ProcessProposalHandler() sdk.ProcessProposalHandler {
	return func(ctx sdk.Context, req *abci.RequestProcessProposal) (*abci.ResponseProcessProposal, error) {
		if len(h.blocklist) == 0 {
			// fast path, accept all txs
			return &abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_ACCEPT}, nil
		}
```

**File:** x/cronos/keeper/precompiles/bank.go (L92-101)
```go
func (bc *BankContract) checkBlockedAddr(addr sdk.AccAddress) error {
	to, err := sdk.AccAddressFromBech32(addr.String())
	if err != nil {
		return err
	}
	if bc.bankKeeper.BlockedAddr(to) {
		return errorsmod.Wrapf(errortypes.ErrUnauthorized, "%s is not allowed to receive funds", to.String())
	}
	return nil
}
```

**File:** app/app.go (L1325-1333)
```go
	if err := app.RefreshBlockList(ctx); err != nil {
		app.Logger().Error("failed to update blocklist", "error", err)
	}
	return rsp, err
}

func (app *App) RefreshBlockList(ctx sdk.Context) error {
	// refresh blocklist
	return app.blockProposalHandler.SetBlockList(app.CronosKeeper.GetBlockList(ctx))
```
