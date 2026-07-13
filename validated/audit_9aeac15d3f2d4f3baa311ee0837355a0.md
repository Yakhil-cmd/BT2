### Title
Blocklist Enforcement Skipped During FinalizeBlock Allows Pre-Admitted Transactions to Bypass Admin Blocklist - (File: app/block_address.go)

### Summary
`BlockAddressesDecorator.AnteHandle` gates all blocklist checks behind `ctx.IsCheckTx()`. During `FinalizeBlock` (block execution), `ctx.IsCheckTx()` is `false`, so the entire blocklist check is skipped. Any transaction admitted to the mempool before a blocklist update is committed can be included in a subsequent block without the blocklist being consulted, bypassing the admin-controlled blocklist entirely.

### Finding Description
In `app/block_address.go`, the `BlockAddressesDecorator` ante handler wraps all enforcement logic in a single `if ctx.IsCheckTx()` guard:

```go
func (bad BlockAddressesDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (newCtx sdk.Context, err error) {
    if ctx.IsCheckTx() {
        // signer check
        // destination address check
        // EIP-7702 authorization check
        // MsgStoreBlockList sender check
    }
    return next(ctx, tx, simulate)
}
```

`ctx.IsCheckTx()` returns `true` only for `ExecModeCheck` and `ExecModeReCheck`. During `FinalizeBlock` (`ExecModeFinalize`), it returns `false`, so the entire body is skipped and the transaction proceeds unconditionally to `next`.

The Cronos mempool recheck mechanism (`Manager.StageRecheckSenders` / `Manager.RecheckTxs`) only rechecks pending transactions whose **senders appeared in the most recently committed block**. If the sender of a transaction to a newly-blocked destination address was not included in the block that committed the `MsgStoreBlockList` update, that transaction is never rechecked and remains in the mempool with its original "admitted" status.

When the block proposer selects that transaction for inclusion, `FinalizeBlock` runs the ante handler with `ctx.IsCheckTx() == false`, the blocklist check is skipped, and the transaction executes successfully against the blocked address.

### Impact Explanation
This is a **High** impact finding: **Bypass of Cronos admin blocklist authorization check**.

The blocklist is an admin-controlled security/compliance mechanism. Transactions to or from blocked addresses are supposed to be prevented from executing. Because the enforcement is absent at the consensus execution layer, the blocklist provides only a probabilistic mempool filter, not a protocol-level guarantee. Any transaction admitted before a blocklist update can execute against a blocked address.

### Likelihood Explanation
The window is narrow but reliably exploitable: an attacker (or any user) who submits a transaction to a target address before the `MsgStoreBlockList` transaction is committed has a high probability of success if:
- Their transaction is not rechecked (sender not in the committed block containing the blocklist update), OR
- The two transactions land in the same block (blocklist update and the transfer both in block N; the transfer executes before or after the update but the ante handler skips the check either way during FinalizeBlock).

No special privileges are required. Standard transaction submission suffices.

### Recommendation
Remove the `if ctx.IsCheckTx()` guard from the blocklist enforcement logic, or duplicate the signer/destination/EIP-7702 checks outside the guard so they run unconditionally during both `CheckTx` and `FinalizeBlock`. The `MsgStoreBlockList` sender authorization check can remain `CheckTx`-only if desired (it is a governance-level gate), but the address-blocking checks must run at execution time to be consensus-enforced.

### Proof of Concept
1. Address `A` is not on the blocklist.
2. Attacker submits `tx_transfer` (ETH transfer to address `A`) → passes `CheckTx` (blocklist check runs, `A` not blocked, admitted to mempool).
3. Admin submits `MsgStoreBlockList` adding `A` to the blocklist → committed in block `N`. Recheck runs only for the admin's sender address; `tx_transfer`'s sender was not in block `N`, so `tx_transfer` is **not rechecked**.
4. Block `N+1` proposer selects `tx_transfer`. `FinalizeBlock` calls `AnteHandle` with `ctx.IsCheckTx() == false` → the entire `if ctx.IsCheckTx()` body is skipped → no blocklist check → `tx_transfer` executes → transfer to blocked address `A` succeeds.

Relevant code: [1](#0-0) 

The recheck mechanism that fails to cover this gap: [2](#0-1)

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

**File:** app/mempool/manager.go (L257-281)
```go
// StageRecheckSenders records the senders of the just-committed block's txs so
// RecheckTxs can re-validate only their remaining pending txs, and stages the
// committed height.
func (a *Manager) StageRecheckSenders(height int64, txs [][]byte) {
	// Decode + extract signers unlocked (the expensive part), then publish height
	// and recheckSenders in one critical section so a reader never sees a torn update.
	var senders map[string]struct{}
	if a.signer != nil && a.decoder != nil {
		senders = make(map[string]struct{}, len(txs))
		for _, bz := range txs {
			tx, err := a.decoder(bz)
			if err != nil {
				continue // non-sdk txs (e.g. vote extensions) have no mempool entry
			}
			for _, s := range a.signers(tx) {
				senders[s] = struct{}{}
			}
		}
	}

	a.stagingMu.Lock()
	a.lastCommittedHeight = height
	a.mergeRecheckSenders(senders)
	a.stagingMu.Unlock()
}
```
