### Title
Bank Precompile `transfer` Bypasses Cronos Blocklist for the Sender Address - (File: `x/cronos/keeper/precompiles/bank.go`)

### Summary
The `transfer` method of the bank precompile validates only the **recipient** against the Cosmos SDK module-account blocklist, but never checks the **sender** against the Cronos encrypted blocklist. Because the Cronos blocklist is enforced exclusively at the proposal/mempool layer (tx signer + EVM `to` field), an unprivileged actor can call a contract that invokes `bank.transfer(blocked_address, attacker, amount)`, moving native EVM-denom tokens out of a blocked address without the blocked address ever signing a transaction.

### Finding Description

The Cronos blocklist is enforced in two places:

1. **`app/proposal.go` `ValidateTransaction`** – rejects any tx whose signer or EVM `to` field is in the blocklist.
2. **`app/block_address.go` `BlockAddressesDecorator`** – same check at `CheckTx` time.

Neither layer inspects internal EVM calls or precompile arguments.

The bank precompile's `transfer` handler at `x/cronos/keeper/precompiles/bank.go` lines 167–200:

```go
case TransferMethodName:
    sender    := args[0].(common.Address)   // arbitrary, caller-supplied
    recipient := args[1].(common.Address)
    ...
    from := sdk.AccAddress(sender.Bytes())
    to   := sdk.AccAddress(recipient.Bytes())
    if err := bc.checkBlockedAddr(to); err != nil {   // ← only "to" is checked
        return nil, err
    }
    denom := EVMDenom(contract.Caller())
    ...
    bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
```

`checkBlockedAddr` (lines 92–101) calls `bankKeeper.BlockedAddr()`, which only covers Cosmos SDK module accounts — it is **not** the Cronos encrypted blocklist. The `from` address is never validated against the Cronos blocklist at all.

Because `sender` is a free argument supplied by the calling contract, any contract can pass a blocked address as `sender`. The tx signer is the unblocked attacker, so the proposal-layer check passes. The precompile then executes `SendCoins` from the blocked address unconditionally.

### Impact Explanation

A blocked address's native EVM-denom tokens (`evm/<contract_address>`) can be drained to an arbitrary recipient by any contract that calls the bank precompile's `transfer` method with the blocked address as `sender`. The Cronos blocklist restriction — intended to freeze the blocked address's ability to move assets — is fully bypassed without the blocked address signing anything.

This matches the **High** impact category: *Bypass of Cronos block-list authorization checks*.

### Likelihood Explanation

- The bank precompile is callable by any deployed EVM contract.
- A contract that exposes a `transferFrom`-style function (or any function that calls `bank.transfer` with a caller-supplied `from` address) is sufficient.
- The attacker only needs to be an unprivileged EVM user; no admin keys or governance access are required.
- The blocked address only needs to hold a non-zero balance of the relevant `evm/<contract>` denom.

### Recommendation

Add a Cronos-blocklist check on the `from` address inside the `transfer` case, mirroring the check already applied to the `to` address. Specifically, before calling `SendCoins`, verify that `from` is not present in the active Cronos blocklist (the same list consulted by `ValidateTransaction`). The `BankContract` should receive a reference to the blocklist lookup function (or the `ProposalHandler`) so it can perform this check at execution time.

### Proof of Concept

1. Admin adds `blocked_alice` to the Cronos encrypted blocklist. `blocked_alice` holds 1000 tokens of denom `evm/0xContractC`.
2. Attacker deploys (or reuses) contract `C` at `0xContractC`. Contract `C` exposes:
   ```solidity
   function steal(address victim, address to, uint256 amount) external {
       IBank(0x0000000000000000000000000000000000000064)
           .transfer(victim, to, amount);
   }
   ```
3. Attacker (unblocked) calls `C.steal(blocked_alice, attacker, 1000e18)`.
4. The tx signer is the attacker (not blocked) → passes `ValidateTransaction`.
5. The EVM `to` field is `0xContractC` (not blocked) → passes destination check.
6. Inside the bank precompile `transfer`: `checkBlockedAddr(attacker)` passes (attacker is not a module account); no Cronos-blocklist check on `blocked_alice`.
7. `bankKeeper.SendCoins(ctx, blocked_alice, attacker, 1000 evm/0xContractC)` executes successfully.
8. `blocked_alice`'s balance is now 0; attacker received 1000 tokens — blocklist restriction fully bypassed. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

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

**File:** x/cronos/keeper/precompiles/bank.go (L167-200)
```go
	case TransferMethodName:
		if readonly {
			return nil, errors.New("the method is not readonly")
		}
		args, err := method.Inputs.Unpack(contract.Input[4:])
		if err != nil {
			return nil, errors.New("fail to unpack input arguments")
		}
		sender := args[0].(common.Address)
		recipient := args[1].(common.Address)
		amount := args[2].(*big.Int)
		if amount.Sign() <= 0 {
			return nil, errors.New("invalid amount")
		}
		from := sdk.AccAddress(sender.Bytes())
		to := sdk.AccAddress(recipient.Bytes())
		if err := bc.checkBlockedAddr(to); err != nil {
			return nil, err
		}
		denom := EVMDenom(contract.Caller())
		amt := sdk.NewCoin(denom, sdkmath.NewIntFromBigInt(amount))
		err = stateDB.ExecuteNativeAction(precompileAddr, nil, func(ctx sdk.Context) error {
			if err := bc.bankKeeper.IsSendEnabledCoins(ctx, amt); err != nil {
				return err
			}
			if err := bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt)); err != nil {
				return errorsmod.Wrap(err, "fail to send coins in precompiled contract")
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		return method.Outputs.Pack(true)
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
