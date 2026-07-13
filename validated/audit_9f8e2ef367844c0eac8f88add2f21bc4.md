### Title
Blocklist Not Enforced at FinalizeBlock — `BlockAddressesDecorator` Skips Check Outside `CheckTx` — (`app/block_address.go`)

---

### Summary

`BlockAddressesDecorator.AnteHandle` gates its entire blocklist enforcement on `ctx.IsCheckTx()`. During `FinalizeBlock` (the execution phase), `IsCheckTx()` is `false`, so the check is unconditionally skipped. The only other enforcement layer — `ProposalHandler.ProcessProposalHandler` — contains a fast-path that accepts all transactions when the validator's local blocklist is empty, which is the default state for any node whose `age.Identity` is `nil`. A malicious block proposer can therefore inject a raw transaction from a blocked address directly into a proposal, have it accepted by validators whose blocklist is empty, and have it executed at `FinalizeBlock` without any blocklist check firing.

---

### Finding Description

**Root cause 1 — `AnteHandle` is a no-op at `FinalizeBlock`:**

The entire body of `BlockAddressesDecorator.AnteHandle` is wrapped in a single `if ctx.IsCheckTx()` guard: [1](#0-0) 

`ctx.IsCheckTx()` returns `false` during `FinalizeBlock`. The function falls through to `next(ctx, tx, simulate)` unconditionally, executing the transaction regardless of whether the signer is blocked.

**Root cause 2 — `ProcessProposalHandler` fast-path accepts all txs when blocklist is empty:** [2](#0-1) 

If `h.blocklist` is empty, every transaction in the proposal is accepted without inspection.

**Root cause 3 — `SetBlockList` silently no-ops when `Identity` is `nil`:** [3](#0-2) 

Any validator node that was not provisioned with an `age.Identity` (the decryption key for the encrypted blocklist blob) will have `h.blocklist == nil` (length 0), triggering the fast-path above for every proposal it processes.

**The two blocklists are independent data structures.** `BlockAddressesDecorator.blockedMap` (used in `AnteHandle`) and `ProposalHandler.blocklist` (used in `ProcessProposalHandler`) are populated separately and do not share state. [4](#0-3) [5](#0-4) 

---

### Impact Explanation

A blocked address (e.g., a sanctioned account holding CRO or IBC vouchers) can have its transaction included in a committed block and executed at `FinalizeBlock`. The transaction can be any message type: `MsgConvertVouchers`, `MsgEthereumTx` (EVM transfer), `MsgSend`, or any precompile call. This constitutes an unauthorized transfer/conversion of CRO, IBC vouchers, CRC20/CRC21 tokens — **Critical** impact under the allowed scope.

---

### Likelihood Explanation

The attack requires:
1. A malicious validator to be the current block proposer (happens in normal round-robin rotation).
2. Enough validators (≥ 1/3 by weight) to have an empty `ProposalHandler.blocklist` — i.e., they were not provisioned with the `age.Identity` key.

The code explicitly supports this configuration (the `Identity == nil` early return in `SetBlockList`), making it a realistic deployment scenario rather than a theoretical one. No leaked keys or external compromise is required.

---

### Recommendation

Remove the `if ctx.IsCheckTx()` guard from `BlockAddressesDecorator.AnteHandle`, or add a parallel check that also fires when `!ctx.IsCheckTx() && !simulate`. The blocklist must be enforced at every execution context — `CheckTx`, `ReCheckTx`, and `FinalizeBlock` — to be meaningful as a security control. `ProcessProposalHandler` is a complementary filter, not a substitute for ante-handler enforcement. [6](#0-5) 

---

### Proof of Concept

1. Configure a test network where validator B does **not** have an `age.Identity` (its `ProposalHandler.blocklist` is empty).
2. Add address A to the blocklist; fund A with CRO.
3. Make validator B the proposer for the next block (or wait for its turn).
4. Validator B constructs a `RequestPrepareProposal` that directly includes a raw-encoded `MsgSend` from A (injected into `req.Txs`, bypassing the mempool and `CheckTx`).
5. Other validators run `ProcessProposalHandler`: because their blocklist is also empty (or differs), they hit the fast-path at line 340 and return `ACCEPT`.
6. `FinalizeBlock` runs the ante-handler chain; `BlockAddressesDecorator.AnteHandle` is called with `ctx.IsCheckTx() == false`, skips all checks, and calls `next`.
7. The `MsgSend` executes; A's CRO balance decreases and the recipient's increases.
8. Assert: the blocked address successfully transferred CRO — the invariant is violated.

### Citations

**File:** app/block_address.go (L17-19)
```go
type BlockAddressesDecorator struct {
	blockedMap map[string]struct{}
	getParams  func(ctx sdk.Context) types.Params
```

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

**File:** app/proposal.go (L195-197)
```go
	blocklist     map[string]struct{}
	lastBlockList []byte
	addressCodec  address.Codec
```

**File:** app/proposal.go (L211-213)
```go
	if h.Identity == nil {
		return nil
	}
```

**File:** app/proposal.go (L340-343)
```go
		if len(h.blocklist) == 0 {
			// fast path, accept all txs
			return &abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_ACCEPT}, nil
		}
```
