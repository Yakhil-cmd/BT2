### Title
Unrestricted Coinbase Self-Assignment in `EVM.run` / `EVM.batchRun` Allows Gas Fee Cashback - (File: `fvm/evm/stdlib/contract.cdc`)

### Summary

`EVM.run` and `EVM.batchRun` are declared `access(all)` and accept a caller-supplied `coinbase: EVMAddress` with no validation. Any unprivileged Cadence transaction sender can set the `coinbase` to an EVM address they control, routing the EVM gas fees collected during execution back to themselves. This is structurally identical to the AaveLens M-05 finding: a fee-sharing mechanism intended to reward legitimate infrastructure providers (relayers) can be self-dealt by any rational user, leaking value from the protocol's incentive system.

---

### Finding Description

`EVM.run` and `EVM.batchRun` in `fvm/evm/stdlib/contract.cdc` are both declared `access(all)`:

```cadence
access(all)
fun run(tx: [UInt8], coinbase: EVMAddress): Result { ... }

access(all)
fun batchRun(txs: [[UInt8]], coinbase: EVMAddress): [Result] { ... }
```

The `coinbase` parameter is documented as:

> "The address of entity to receive the transaction fees for relaying the transaction"

In the Go handler (`fvm/evm/handler/handler.go`), `runWithGasFeeRefund` collects gas fees that accumulate at the fixed internal `types.CoinbaseAddress` during EVM execution, then transfers the entire balance delta to the caller-supplied `gasFeeCollector`:

```go
func (h *ContractHandler) runWithGasFeeRefund(gasFeeCollector types.Address, f func()) {
    cb := h.AccountByAddress(types.CoinbaseAddress, true)
    initCoinbaseBalance := cb.Balance()
    f()
    afterBalance := cb.Balance()
    diff := new(big.Int).Sub(afterBalance, initCoinbaseBalance)
    if diff.Sign() > 0 {
        cb.Transfer(gasFeeCollector, diff)
    }
    ...
}
```

There is no check that `gasFeeCollector` is a whitelisted relayer, a different address from the EVM transaction sender, or any legitimate infrastructure provider. Any Cadence transaction can pass any arbitrary EVM address as `coinbase`.

---

### Impact Explanation

An EVM transaction sender who also controls the `coinbase` EVM address receives back the gas fees they paid, making EVM execution effectively free for self-submitters. The coinbase mechanism is designed to economically incentivize relayers and frontends to submit EVM transactions on behalf of users. When any user can self-assign the coinbase, the incentive system is broken: legitimate relayers receive no fees (users bypass them), and the protocol leaks the EVM gas fee value to self-dealing users rather than to infrastructure providers. This is value leakage from the protocol's fee distribution system, matching the AaveLens M-05 severity classification.

---

### Likelihood Explanation

The attack requires only a standard Cadence transaction — no special privileges, no staked node, no leaked keys. The pattern is straightforward: sign an EVM transaction from EVM address A, call `EVM.run(tx: ..., coinbase: A)` in the wrapping Cadence transaction. Any rational EVM user who discovers this will self-assign the coinbase, since it costs nothing extra and recovers the gas fees. The `access(all)` modifier means the entry path is fully open to any Flow account.

---

### Recommendation

1. **Restrict the coinbase to a protocol-controlled address**: Remove the `coinbase` parameter from `EVM.run` / `EVM.batchRun` and route gas fees to a fixed protocol-owned address (e.g., the FlowFees contract receiver), similar to how Cadence-layer transaction fees are handled.
2. **Alternatively, whitelist valid coinbase addresses**: Maintain an admin-controlled allowlist of approved relayer/frontend addresses and validate the `coinbase` argument against it before execution.
3. **At minimum, prevent self-referral**: Validate that the `coinbase` address is not the same as the EVM transaction's `from` address, mirroring the simplest mitigation discussed in the AaveLens issue.

---

### Proof of Concept

Any unprivileged Flow account can submit the following Cadence transaction to recover EVM gas fees:

```cadence
import EVM from <EVMContractAddress>

transaction(tx: [UInt8], myEVMAddress: [UInt8; 20]) {
    prepare(account: &Account) {
        // myEVMAddress is the same EVM address that signed `tx`
        let coinbase = EVM.EVMAddress(bytes: myEVMAddress)
        // Gas fees paid by the EVM tx sender are routed back to myEVMAddress
        let res = EVM.run(tx: tx, coinbase: coinbase)
    }
}
```

The EVM transaction `tx` is signed by the EVM key corresponding to `myEVMAddress`. Gas fees deducted from `myEVMAddress` during EVM execution accumulate at `types.CoinbaseAddress`, then `runWithGasFeeRefund` transfers them to `myEVMAddress` — the same address that paid them. Net EVM gas cost: zero.

The same applies to `EVM.batchRun` for batches of self-signed EVM transactions.

**Root cause references:**
- `fvm/evm/stdlib/contract.cdc` lines 827–836 (`EVM.run`, `access(all)`, no coinbase validation)
- `fvm/evm/stdlib/contract.cdc` lines 917–926 (`EVM.batchRun`, `access(all)`, no coinbase validation)
- `fvm/evm/handler/handler.go` lines 250–266 (`runWithGasFeeRefund`, unconditional transfer to caller-supplied address) [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** fvm/evm/stdlib/contract.cdc (L819-836)
```text
    /// Runs an a RLP-encoded EVM transaction, deducts the gas fees,
    /// and deposits the gas fees into the provided coinbase address.
    ///
    /// @param tx: The rlp-encoded transaction to run
    /// @param coinbase: The address of entity to receive the transaction fees
    /// for relaying the transaction
    ///
    /// @return: The transaction result
    access(all)
    fun run(tx: [UInt8], coinbase: EVMAddress): Result {
        pre {
            !self.isPaused(): "EVM operations are temporarily paused"
        }
        return InternalEVM.run(
            tx: tx,
            coinbase: coinbase.bytes
        ) as! Result
    }
```

**File:** fvm/evm/stdlib/contract.cdc (L914-926)
```text
    /// Runs a batch of RLP-encoded EVM transactions, deducts the gas fees,
    /// and deposits the gas fees into the provided coinbase address.
    /// An invalid transaction is not executed and not included in the block.
    access(all)
    fun batchRun(txs: [[UInt8]], coinbase: EVMAddress): [Result] {
        pre {
            !self.isPaused(): "EVM operations are temporarily paused"
        }
        return InternalEVM.batchRun(
            txs: txs,
            coinbase: coinbase.bytes,
        ) as! [Result]
    }
```

**File:** fvm/evm/handler/handler.go (L250-266)
```go
// runWithGasFeeRefund runs a method and transfers the balance changes of the
// coinbase address to the provided gas fee collector
func (h *ContractHandler) runWithGasFeeRefund(gasFeeCollector types.Address, f func()) {
	// capture coinbase init balance
	cb := h.AccountByAddress(types.CoinbaseAddress, true)
	initCoinbaseBalance := cb.Balance()
	f()
	// transfer the gas fees collected to the gas fee collector address
	afterBalance := cb.Balance()
	diff := new(big.Int).Sub(afterBalance, initCoinbaseBalance)
	if diff.Sign() > 0 {
		cb.Transfer(gasFeeCollector, diff)
	}
	if diff.Sign() < 0 { // this should never happen but in case
		panic(fvmErrors.NewEVMError(fmt.Errorf("negative balance change on coinbase")))
	}
}
```
