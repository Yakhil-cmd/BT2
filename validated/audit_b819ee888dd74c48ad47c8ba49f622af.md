### Title
Blocklist Bypass via `__CronosSendToAccount` EVM Log Handler — (`File: x/cronos/keeper/evmhandlers/send_to_account.go`)

---

### Summary

The Cronos blocklist enforcement filters direct EVM transaction signers and `To()` destinations at the mempool and proposal layers. However, the `SendToAccountHandler` EVM log hook transfers native tokens to a recipient address decoded from contract log data without any blocklist check. An unprivileged caller can route native tokens (IBC vouchers, gravity tokens, CRO) to a blocklisted address by invoking a mapped CRC20 contract that emits `__CronosSendToAccount(blocked_address, amount)`, fully bypassing the blocklist.

---

### Finding Description

Cronos enforces its blocklist at two layers:

1. **Mempool (CheckTx)** — `BlockAddressesDecorator.AnteHandle` rejects transactions whose signer or EVM `To()` address is blocked. [1](#0-0) 

2. **Proposal (PrepareProposal)** — `ProposalHandler.ValidateTransaction` filters the same fields before block inclusion. [2](#0-1) 

Both layers inspect only the **top-level EVM transaction's `To()` field**. Neither layer inspects the recipient addresses embedded in EVM log data that are processed by post-execution hooks.

The `SendToAccountHandler` is registered as an EVM hook and runs during `PostTxProcessing` (block execution, after the blocklist filters have already passed): [3](#0-2) 

Inside `SendToAccountHandler.Handle`, the recipient is decoded from the log data and native tokens are transferred directly via `bankKeeper.SendCoins` with **no blocklist check**: [4](#0-3) 

The handler only validates that the emitting contract is mapped to a native denom: [5](#0-4) 

It does not check whether `recipient` is on the blocklist before executing the bank transfer at line 84.

---

### Impact Explanation

**High — Bypass of Cronos blocklist authorization checks.**

A blocked address can receive native tokens (IBC vouchers, gravity-bridged ERC20s, CRO) via the `__CronosSendToAccount` hook path. The blocklist's stated purpose — enforced by blocking both signers and EVM `To()` destinations — is circumvented. The blocked address accumulates a spendable native-token balance without ever appearing as a direct transaction signer or destination.

---

### Likelihood Explanation

Requires an existing token-mapped CRC20 contract that exposes a user-callable function emitting `__CronosSendToAccount` with an attacker-controlled recipient. Token mapping requires CronosAdmin authorization, so the attacker cannot register an arbitrary contract. However, any already-deployed mapped contract whose interface allows a caller to specify the recipient of a `__CronosSendToAccount` event is sufficient. This is a realistic condition for external CRC20 contracts implementing the Cronos hook standard.

---

### Recommendation

Add a blocklist check on the `recipient` address inside `SendToAccountHandler.Handle` before executing the bank transfer. The check should mirror the pattern used in the bank precompile's `checkBlockedAddr`, but against the e2ee/validator blocklist rather than the SDK module-account blocklist. Alternatively, expose a `IsBlocklisted(addr)` query from the blocklist state and call it in all EVM log handlers that perform native token transfers to user-controlled addresses (`SendToAccountHandler`, and defensively in `SendCroToIbcHandler` and `SendToIbcHandler` for the intermediate sender transfer).

---

### Proof of Concept

1. Admin has registered contract `C` (a CRC20 mapped to denom `ibc/ATOM`) and address `B` is on the validator blocklist.
2. Contract `C` holds 1000 `ibc/ATOM` in its bank account (deposited by prior IBC inflow).
3. Attacker (unblocked address `A`) calls `C.sendToAccount(B, 1000)`, which emits:
   ```
   emit __CronosSendToAccount(B, 1000);
   ```
4. The EVM transaction `To()` is `C` (not `B`), so `BlockAddressesDecorator` and `ProposalHandler.ValidateTransaction` pass without rejection.
5. After EVM execution, `LogProcessEvmHook.PostTxProcessing` iterates logs and dispatches to `SendToAccountHandler.Handle`.
6. The handler calls `bankKeeper.SendCoins(C_addr, B_addr, 1000 ibc/ATOM)` — no blocklist check — and `B` receives 1000 `ibc/ATOM`. [6](#0-5) [7](#0-6)

### Citations

**File:** app/block_address.go (L32-54)
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
```

**File:** app/proposal.go (L262-308)
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
```

**File:** app/app.go (L851-856)
```go
	app.EvmKeeper.SetHooks(cronoskeeper.NewLogProcessEvmHook(
		evmhandlers.NewSendToAccountHandler(app.BankKeeper, app.CronosKeeper),
		evmhandlers.NewSendToIbcHandler(app.BankKeeper, app.CronosKeeper),
		evmhandlers.NewSendCroToIbcHandler(app.BankKeeper, app.CronosKeeper),
		evmhandlers.NewSendToIbcV2Handler(app.BankKeeper, app.CronosKeeper),
	))
```

**File:** x/cronos/keeper/evmhandlers/send_to_account.go (L62-89)
```go
func (h SendToAccountHandler) Handle(
	ctx sdk.Context,
	contract common.Address,
	topics []common.Hash,
	data []byte,
	_ func(contractAddress common.Address, logSig common.Hash, logData []byte),
) error {
	unpacked, err := SendToAccountEvent.Inputs.Unpack(data)
	if err != nil {
		// log and ignore
		h.cronosKeeper.Logger(ctx).Error("log signature matches but failed to decode", "error", err)
		return nil
	}

	denom, found := h.cronosKeeper.GetDenomByContract(ctx, contract)
	if !found {
		return fmt.Errorf("contract %s is not connected to native token", contract)
	}

	contractAddr := sdk.AccAddress(contract.Bytes())
	recipient := sdk.AccAddress(unpacked[0].(common.Address).Bytes())
	coins := sdk.NewCoins(sdk.NewCoin(denom, sdkmath.NewIntFromBigInt(unpacked[1].(*big.Int))))
	err = h.bankKeeper.SendCoins(ctx, contractAddr, recipient, coins)
	if err != nil {
		return err
	}

	return nil
```

**File:** x/cronos/keeper/evm_hooks.go (L28-44)
```go
func (h LogProcessEvmHook) PostTxProcessing(ctx sdk.Context, _ *core.Message, receipt *ethtypes.Receipt) error {
	addLogToReceiptFunc := newFuncAddLogToReceipt(receipt)
	for _, log := range receipt.Logs {
		if len(log.Topics) == 0 {
			continue
		}
		handler, ok := h.handlers[log.Topics[0]]
		if !ok {
			continue
		}
		err := handler.Handle(ctx, log.Address, log.Topics, log.Data, addLogToReceiptFunc)
		if err != nil {
			return err
		}
	}
	return nil
}
```
