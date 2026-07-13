### Title
Blocklist Bypass via IBC Auto-Conversion: Missing Receiver Check in `IBCConversionModule.OnRecvPacket` — (File: `x/cronos/middleware/conversion_middleware.go`)

---

### Summary

The Cronos blocklist enforces destination-address checks for EVM transactions at both the mempool (`BlockAddressesDecorator`) and proposal (`ProposalHandler.ValidateTransaction`) levels. However, `IBCConversionModule.OnRecvPacket` auto-converts IBC vouchers to EVM coins for `data.Receiver` without any blocklist check. A blocked address can receive EVM coins by having an IBC transfer relayed to it, bypassing the blocklist's destination enforcement entirely.

---

### Finding Description

The blocklist is enforced in two places, both scoped exclusively to `MsgEthereumTx`:

**1. `app/block_address.go` — `BlockAddressesDecorator.AnteHandle` (CheckTx only)**

```go
func (bad BlockAddressesDecorator) AnteHandle(...) (...) {
    if ctx.IsCheckTx() {
        // checks signers and ethTx.To() for MsgEthereumTx only
    }
    return next(ctx, tx, simulate)
}
``` [1](#0-0) 

**2. `app/proposal.go` — `ProposalHandler.ValidateTransaction` (PrepareProposal/ProcessProposal)**

```go
for _, msg := range tx.GetMsgs() {
    msgEthTx, ok := msg.(*evmtypes.MsgEthereumTx)
    if ok {
        // checks ethTx.To() and EIP-7702 auth list
    }
}
``` [2](#0-1) 

Both checks only apply to `MsgEthereumTx`. IBC relay messages (`MsgRecvPacket`) are not `MsgEthereumTx` and are never inspected.

When a `MsgRecvPacket` is processed during block execution, `IBCConversionModule.OnRecvPacket` is called. It calls `ConvertVouchersToEvmCoins` for `data.Receiver` with no blocklist check:

```go
if im.canBeConverted(cacheCtx, denom) {
    // ...
    if err := im.cronoskeeper.ConvertVouchersToEvmCoins(cacheCtx, data.Receiver, sdk.NewCoins(token)); err != nil {
``` [3](#0-2) 

The check is applied when:
- A blocked address sends an EVM transaction (signer check)
- An EVM transaction is sent to a blocked address (destination check)

The check is **not** applied when:
- An IBC packet arrives with a blocked address as `data.Receiver`
- The middleware auto-converts vouchers to EVM coins for that blocked address

This is structurally identical to the external report's pattern: the guard is applied at registration time and for some execution paths (EVM transactions), but is absent for another execution path (IBC packet processing).

---

### Impact Explanation

**High — Bypass of block-list authorization checks.**

The blocklist was explicitly extended to check destination addresses (CHANGELOG entry: `[#1922] Feat: check destination address in the blocklist`), confirming the design intent is to prevent blocked addresses from receiving funds. [4](#0-3) 

The IBC conversion middleware bypasses this intent. Once a blocked address receives EVM coins via IBC auto-conversion, those coins can be moved via pre-approved ERC20 `allowance`/`transferFrom` mechanisms that do not require a direct transaction from the blocked address, or through any contract interaction initiated by a third party on behalf of the blocked address.

---

### Likelihood Explanation

**Medium.** The attacker only needs funds on any IBC-connected chain (e.g., Cosmos Hub, Osmosis) and a mapped denom on Cronos. The IBC relayer relays the packet without any blocklist awareness. No privileged access is required.

---

### Recommendation

Add a blocklist check in `IBCConversionModule.OnRecvPacket` before calling `ConvertVouchersToEvmCoins`. The keeper already exposes `GetBlockList` at: [5](#0-4) 

Before the conversion call, resolve `data.Receiver` to its byte-address form and check it against the active blocklist, mirroring the logic in `ProposalHandler.ValidateTransaction`.

---

### Proof of Concept

1. Admin adds address `A` to the blocklist via `MsgStoreBlockList`.
2. Address `A` holds funds on an IBC-connected chain (e.g., Cosmos Hub ATOM, or any denom with a Cronos contract mapping).
3. Address `A` (or any third party) initiates an IBC transfer to address `A` on Cronos.
4. The IBC relayer submits a `MsgRecvPacket` transaction to Cronos.
5. `ProposalHandler.ValidateTransaction` does not inspect `MsgRecvPacket` (only `MsgEthereumTx` is checked) — the transaction is included in the block.
6. During block execution, `IBCConversionModule.OnRecvPacket` is called.
7. `im.canBeConverted(cacheCtx, denom)` returns `true` (denom has a contract mapping).
8. `im.cronoskeeper.ConvertVouchersToEvmCoins(cacheCtx, data.Receiver, ...)` executes without any blocklist check.
9. Address `A` now holds EVM coins on Cronos, bypassing the blocklist's destination enforcement.

### Citations

**File:** app/block_address.go (L32-44)
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
```

**File:** app/proposal.go (L295-333)
```go
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
```

**File:** x/cronos/middleware/conversion_middleware.go (L125-143)
```go
	if im.canBeConverted(cacheCtx, denom) {
		transferAmount, ok := sdkmath.NewIntFromString(data.Token.Amount)
		if !ok {
			return channeltypes.NewErrorAcknowledgement(errors.Wrapf(
				transferTypes.ErrInvalidAmount,
				"unable to parse transfer amount (%s) into sdk.Int in middleware",
				data.Token.Amount,
			))
		}
		token := sdk.NewCoin(denom, transferAmount)
		if err := im.cronoskeeper.ConvertVouchersToEvmCoins(cacheCtx, data.Receiver, sdk.NewCoins(token)); err != nil {
			im.cronoskeeper.Logger(ctx).Error(
				"failed to convert vouchers on recv",
				"denom", denom,
				"receiver", data.Receiver,
				"error", err,
			)
			return channeltypes.NewErrorAcknowledgement(err)
		}
```

**File:** CHANGELOG.md (L92-93)
```markdown
* [#1922](https://github.com/crypto-org-chain/cronos/pull/1922) Feat: check destination address in the blocklist
* [#1924](https://github.com/crypto-org-chain/cronos/pull/1924) Fix: check authorisation address in the blocklist
```

**File:** x/cronos/keeper/keeper.go (L489-491)
```go
func (k Keeper) GetBlockList(ctx sdk.Context) []byte {
	return ctx.KVStore(k.storeKey).Get(types.KeyPrefixBlockList)
}
```
