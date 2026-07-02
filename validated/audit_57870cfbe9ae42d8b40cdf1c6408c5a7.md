### Title
Cross-Chain Replay of Unprotected Legacy Transactions Accepted by Flow EVM Signer — (`fvm/evm/emulator/config.go`, `fvm/evm/emulator/signer.go`, `fvm/evm/emulator/emulator.go`)

---

### Summary

Flow EVM's `GetSigner` returns a go-ethereum `CancunSigner` (or `OsakaSigner`/`PragueSigner` depending on network) via `types.MakeSigner`. For legacy transactions with `V ∈ {27, 28}` (unprotected, pre-EIP-155), the signer chain ultimately falls back to `HomesteadSigner`, which recovers the sender without any chain ID binding. Flow EVM has no additional guard to reject such transactions. An attacker who captures a legacy Ethereum mainnet transaction can submit it to Flow EVM via `EVM.run`, causing it to execute with the original signer's address as `msg.From`, mutating that address's state on Flow EVM without the owner's consent.

---

### Finding Description

`MakeChainConfig` sets all block-height forks to `bigZero` (block 0) and all timestamp forks to `&zero` (timestamp 0): [1](#0-0) 

`GetSigner` delegates directly to `types.MakeSigner` with no post-processing: [2](#0-1) 

Because `CancunTime = &zero`, `MakeSigner` returns a `CancunSigner`. For a `LegacyTx`, the call chain is:

```
CancunSigner.Sender(tx)
  → londonSigner.Sender(tx)       [not DynamicFeeTx]
    → eip2930Signer.Sender(tx)    [not AccessListTx]
      → EIP155Signer.Sender(tx)   [LegacyTx]
```

Inside `EIP155Signer.Sender()` (go-ethereum upstream):
```go
if !tx.Protected() {          // V == 27 or V == 28 → true
    return HomesteadSigner{}.Sender(tx)   // no chain ID check
}
```

`tx.Protected()` returns `false` when `V ∈ {27, 28}`, so the signer silently falls back to `HomesteadSigner`, which recovers the sender purely from the ECDSA signature without any chain ID binding.

`RunTransaction` then calls `gethCore.TransactionToMessage` with this signer. If no error is returned (and none will be for a valid Homestead-style signature), the message is executed with `msg.From` set to the Homestead-recovered address: [3](#0-2) 

There is no Flow EVM-level guard that checks `tx.Protected()` and rejects unprotected transactions before or after this call.

---

### Impact Explanation

An attacker who obtains a legacy Ethereum mainnet transaction (V=27/28, nonce=N) signed by victim address `A` can submit it to Flow EVM via `EVM.run`. If the victim's Flow EVM account also has nonce=N, the transaction executes with `msg.From = A`, causing:

- The victim's Flow EVM nonce to be incremented (unconditional state mutation)
- Any ETH value in the transaction to be transferred from the victim's Flow EVM balance
- Any contract call in the transaction to execute with the victim as `msg.sender`, potentially triggering privileged operations in contracts that use `msg.sender` for access control

The victim's address on Flow EVM is identical to their Ethereum address (both derived from the same ECDSA public key), so the precondition of address equality is always satisfied for EOAs.

---

### Likelihood Explanation

**Moderate.** The primary practical constraint is nonce alignment: the victim's Flow EVM nonce must equal the nonce in the replayed transaction. For fresh Flow EVM accounts (nonce=0), any captured Ethereum mainnet transaction with nonce=0 is immediately replayable. Pre-EIP-155 transactions (V=27/28) were common before Ethereum block 2,675,000 (October 2016) and are still produced by some hardware wallets and dApps that do not enforce EIP-155. The attack requires no special privileges, no staked nodes, and is submittable through the standard `EVM.run` Cadence entrypoint accessible to any Flow transaction sender.

---

### Recommendation

Explicitly reject unprotected legacy transactions before passing them to the EVM. In `RunTransaction` (and `BatchRunTransactions`), after decoding the transaction and before calling `TransactionToMessage`, add:

```go
if tx.Type() == gethTypes.LegacyTxType && !tx.Protected() {
    return types.NewInvalidResult(tx.Type(), tx.Hash(),
        errors.New("unprotected legacy transaction rejected: missing EIP-155 chain ID")), nil
}
```

Alternatively, enforce this at the `GetSigner` level by returning a custom signer that wraps `EIP155Signer` but returns `ErrInvalidChainId` instead of falling back to `HomesteadSigner` for unprotected transactions.

---

### Proof of Concept

1. Generate a valid ECDSA key pair `(sk, addr)`.
2. Sign a legacy Ethereum mainnet transaction with `V=27` (Homestead style, no chain ID): `tx = LegacyTx{Nonce: 0, To: someAddr, Value: 0, Gas: 21000, GasPrice: 0, V: 27, R: ..., S: ...}`.
3. On Flow EVM emulator/localnet, ensure `addr` has nonce=0 (fresh account).
4. Submit via Cadence: `EVM.run(tx: rlpEncode(tx), coinbase: ...)`.
5. Observe: `RunTransaction` calls `GetSigner` → `CancunSigner` → `EIP155Signer` → `HomesteadSigner.Sender(tx)` → returns `addr` without error.
6. `ApplyMessage` executes with `msg.From = addr`, incrementing `addr`'s nonce on Flow EVM.
7. Assert result is **not** `InvalidResult` — the transaction succeeds, proving unauthorized state mutation. [4](#0-3) [2](#0-1) [5](#0-4)

### Citations

**File:** fvm/evm/emulator/config.go (L85-110)
```go
func MakeChainConfig(chainID *big.Int) *gethParams.ChainConfig {
	chainConfig := &gethParams.ChainConfig{
		ChainID: chainID,

		// Fork scheduling based on block heights
		HomesteadBlock:      bigZero,
		DAOForkBlock:        bigZero,
		DAOForkSupport:      false,
		EIP150Block:         bigZero,
		EIP155Block:         bigZero,
		EIP158Block:         bigZero,
		ByzantiumBlock:      bigZero, // already on Byzantium
		ConstantinopleBlock: bigZero, // already on Constantinople
		PetersburgBlock:     bigZero, // already on Petersburg
		IstanbulBlock:       bigZero, // already on Istanbul
		BerlinBlock:         bigZero, // already on Berlin
		LondonBlock:         bigZero, // already on London
		MuirGlacierBlock:    bigZero, // already on MuirGlacier

		// Fork scheduling based on timestamps
		ShanghaiTime: &zero, // already on Shanghai
		CancunTime:   &zero, // already on Cancun
		PragueTime:   nil,   // this is conditionally set below
		OsakaTime:    nil,   // this is conditionally set below
		VerkleTime:   nil,   // not on Verkle
	}
```

**File:** fvm/evm/emulator/signer.go (L22-27)
```go
func GetSigner(cfg *Config) types.Signer {
	return types.MakeSigner(
		cfg.ChainConfig,
		cfg.BlockContext.BlockNumber,
		cfg.BlockContext.Time,
	)
```

**File:** fvm/evm/emulator/emulator.go (L175-193)
```go
func (bl *BlockView) RunTransaction(
	tx *gethTypes.Transaction,
) (result *types.Result, err error) {
	// create a new procedure
	proc, err := bl.newProcedure()
	if err != nil {
		return nil, err
	}

	// constructs a core.message from the tx
	msg, err := gethCore.TransactionToMessage(
		tx,
		GetSigner(bl.config),
		proc.config.BlockContext.BaseFee)
	if err != nil {
		// this is not a fatal error (e.g. due to bad signature)
		// not a valid transaction
		return types.NewInvalidResult(tx.Type(), tx.Hash(), err), nil
	}
```
