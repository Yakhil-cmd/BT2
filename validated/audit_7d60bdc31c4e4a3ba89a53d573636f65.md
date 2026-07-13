### Title
Non-EVM Cosmos Message Recipients Not Checked Against Blocklist in `ValidateTransaction` and `AnteHandle` — (`app/proposal.go`, `app/block_address.go`)

---

### Summary

`ProposalHandler.ValidateTransaction` and `BlockAddressesDecorator.AnteHandle` both check the blocklist for (a) tx signers across all message types and (b) the `To` address of `MsgEthereumTx` messages. Neither function checks the recipient address of non-EVM Cosmos messages (e.g., `bank.MsgSend`, `bank.MsgMultiSend`). An unprivileged sender whose own address is not blocked can therefore send funds to a Cronos-blocklisted address via a plain Cosmos bank transfer, bypassing the blocklist entirely.

---

### Finding Description

**`ProposalHandler.ValidateTransaction`** (`app/proposal.go` lines 262–335):

```
signers → checked against h.blocklist          ✓
MsgEthereumTx.To() → checked against h.blocklist  ✓
bank.MsgSend recipient → NOT checked            ✗
``` [1](#0-0) 

The loop at line 295 casts each message to `*evmtypes.MsgEthereumTx`. If the cast fails (i.e., the message is any non-EVM type), the body is skipped entirely and no recipient address is inspected.

**`BlockAddressesDecorator.AnteHandle`** (`app/block_address.go` lines 32–83) has the identical gap: [2](#0-1) 

Additionally, this decorator only runs during `CheckTx` (`if ctx.IsCheckTx()`), so during `FinalizeBlock` the blocklist is not enforced at all at the ante-handler layer. [3](#0-2) 

The proposal-handler path is therefore the only consensus-level enforcement, and it has the same recipient-check gap.

**Execution path:**

1. Attacker (unblocked address) submits `bank.MsgSend{FromAddress: attacker, ToAddress: blocked_addr, Amount: ...}`.
2. `CheckTx` → `BlockAddressesDecorator.AnteHandle`: signer (attacker) is not blocked; message is not `MsgEthereumTx`; no recipient check → **passes**.
3. `PrepareProposal` → `ValidateTransaction`: same logic → **tx included in block proposal**.
4. `ProcessProposal` on peer validators → `ValidateTransaction`: same logic → **block accepted**.
5. `FinalizeBlock`: ante handler skips blocklist (`IsCheckTx()` = false); bank keeper's `SendCoins` has no knowledge of the Cronos-specific blocklist → **transfer executes, blocked address receives funds**.

The bank keeper's own `BlockedAddr` guard covers only module accounts (standard Cosmos SDK behavior), not the Cronos-specific blocklist managed by `MsgStoreBlockList`.

---

### Impact Explanation

A blocked address receives native Cosmos funds (e.g., `basetcro`) via `bank.MsgSend` despite being on the Cronos blocklist. This directly bypasses the block-list authorization check that the codebase explicitly enforces for EVM transactions. The existing integration test `test_blocked_to_contract_address` confirms the intent is to prevent blocked addresses from receiving funds; the non-EVM path is simply unguarded. [4](#0-3) 

**Impact category:** High — Bypass of Cronos block-list authorization check.

---

### Likelihood Explanation

- Requires no special privileges; any Cosmos account can submit a `bank.MsgSend`.
- No cryptographic assumptions, no validator compromise, no leaked keys.
- The path is fully reachable on mainnet today.

---

### Recommendation

In both `ValidateTransaction` (`app/proposal.go`) and `BlockAddressesDecorator.AnteHandle` (`app/block_address.go`), after the existing EVM-message loop, add a recipient check for non-EVM messages that expose a recipient address. For `bank.MsgSend` and `bank.MsgMultiSend` this means inspecting `ToAddress` / each `Output.Address` and rejecting the transaction if any recipient is in the blocklist. The same pattern should be applied to any other Cosmos message type that transfers funds to an explicit recipient.

---

### Proof of Concept

```go
// Unit test sketch for ValidateTransaction
func TestValidateTransaction_BankSendToBlockedAddr(t *testing.T) {
    blockedAddr := sdk.AccAddress([]byte("blocked_____________"))
    handler := &ProposalHandler{
        blocklist: map[string]struct{}{
            blockedAddr.String(): {},
        },
        // ... other fields
    }

    msg := banktypes.NewMsgSend(
        sdk.AccAddress([]byte("attacker____________")),
        blockedAddr,
        sdk.NewCoins(sdk.NewInt64Coin("basetcro", 1)),
    )
    tx := buildTx(msg) // sign with attacker key

    err := handler.ValidateTransaction(tx, nil)
    // FAILS: err is nil, but should be non-nil
    require.Error(t, err, "expected blocked recipient to be rejected")
}
``` [5](#0-4) [6](#0-5)

### Citations

**File:** app/proposal.go (L262-335)
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

**File:** integration_tests/test_mempool.py (L88-98)
```python
def test_blocked_to_contract_address(cronos_mempool):
    w3 = cronos_mempool.w3
    tx = {
        "to": ADDRS["signer1"],
        "value": 1,
        "from": ADDRS["validator"],
    }
    tx1_signed = sign_transaction(w3, tx, key=KEYS["validator"])
    with pytest.raises(exceptions.Web3RPCError) as exc:
        _ = w3.eth.send_raw_transaction(tx1_signed.raw_transaction)
    assert "destination address is blocked" in str(exc)
```
