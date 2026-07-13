### Title
Blocklist Destination Check Only Inspects Top-Level `To` Field, Allowing Bypass via Intermediary Contract — (`app/block_address.go`, `app/proposal.go`)

### Summary

Both the mempool ante-handler (`BlockAddressesDecorator`) and the proposal-level validator (`ProposalHandler.ValidateTransaction`) enforce the encrypted blocklist by checking only the **top-level `To` address** of a `MsgEthereumTx`. Neither layer inspects internal EVM sub-call destinations. Any unprivileged user can route a transfer to a blocked address through an ordinary intermediary contract, bypassing the blocklist entirely.

### Finding Description

Cronos enforces its encrypted blocklist at two points:

**1. `BlockAddressesDecorator.AnteHandle` (`app/block_address.go:32-83`)**

The guard is wrapped in `if ctx.IsCheckTx()`, so it runs only during mempool admission, not during `DeliverTx`. For `MsgEthereumTx` it checks only `ethTx.To()` — the outer transaction destination:

```go
if ethTx.To() != nil {
    if _, ok := bad.blockedMap[sdk.AccAddress(ethTx.To().Bytes()).String()]; ok {
        return ctx, fmt.Errorf("destination address is blocked: ...")
    }
}
``` [1](#0-0) 

**2. `ProposalHandler.ValidateTransaction` (`app/proposal.go:262-336`)**

The proposal-level check mirrors the same logic — it inspects only the outer `ethTx.To()` and the tx signers:

```go
if ethTx.To() != nil {
    ...
    if _, ok := h.blocklist[encoded]; ok {
        return fmt.Errorf("destination address is blocked: ...")
    }
}
``` [2](#0-1) 

Neither check recurses into internal EVM calls. There is no runtime hook that re-validates sub-call destinations during EVM execution.

### Impact Explanation

The blocklist is a compliance/sanctions control (encrypted with validator keys, stored on-chain via `MsgStoreBlockList`). Its purpose is to prevent blocked addresses from sending or receiving funds. Because only the outer `To` field is checked, any non-blocked smart contract can act as a pass-through:

1. Attacker (non-blocked address B) calls contract C (not blocked) — proposal validation sees `To = C`, passes.
2. Contract C internally executes `C.call{value: amount}(blockedAddress)` or `token.transfer(blockedAddress, amount)`.
3. No blocklist check fires during EVM execution; the blocked address receives funds.

This is a **High** impact: bypass of the Cronos block-list authorization check, allowing CRO, CRC20, CRC21, or ERC20 tokens to be transferred to a sanctioned/blocked address through an intermediary contract.

### Likelihood Explanation

The attack requires only:
- Knowledge of a blocked address (the blocklist is encrypted, but the blocked address's on-chain activity is observable).
- Deployment of (or interaction with) any contract that can forward a transfer — a trivial one-liner in Solidity.

No privileged access, leaked keys, or special permissions are needed. Any unprivileged user can execute this.

### Recommendation

The blocklist destination check must be enforced at EVM execution time, not only at the transaction-admission layer. Options:

1. **EVM tracer / state-DB hook**: Intercept every `CALL`/`STATICCALL`/`DELEGATECALL` opcode and reject execution if the callee address is in the blocklist.
2. **Post-execution log scan**: After EVM execution, scan all generated logs and state changes for transfers to blocked addresses and revert the transaction if any are found.
3. **Precompile guard**: In the bank precompile's `checkBlockedAddr`, extend the check to cover the Cronos encrypted blocklist (currently it only checks `bankKeeper.BlockedAddr`, which is the Cosmos SDK module-account list, not the encrypted compliance blocklist). [3](#0-2) 

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract BlocklistBypass {
    // Called by non-blocked attacker B, with `to` = blocked address A
    function forward(address payable to) external payable {
        // top-level tx.to = this contract (not blocked) → passes proposal validation
        // internal call to `to` (blocked) → no check fires during EVM execution
        (bool ok,) = to.call{value: msg.value}("");
        require(ok);
    }
}
```

Attack steps:
1. Admin adds address A to the encrypted blocklist via `MsgStoreBlockList`.
2. Attacker B (not blocked) deploys `BlocklistBypass` contract C.
3. B calls `C.forward{value: 1 ether}(A)`.
4. Proposal validation sees `To = C` — not blocked, tx is included.
5. During execution, `C` internally sends 1 ETH to A. No blocklist check fires.
6. A's balance increases, bypassing the blocklist.

The same path works for ERC20/CRC20/CRC21 token transfers: B calls a contract that internally invokes `token.transfer(A, amount)`. [4](#0-3) [5](#0-4)

### Citations

**File:** app/block_address.go (L32-55)
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
