### Title
`EVM.mustRun()` Silently Passes Through `StatusFailed` EVM Results Without Reverting, Enabling Cross-VM Asset Loss - (`File: fvm/evm/stdlib/contract.cdc`)

---

### Summary

`EVM.mustRun()` in the EVM system contract is the direct Flow analog of the reported ERC20 `transferFrom()` vulnerability. Just as Solidity's `transferFrom()` can return `false` without reverting (requiring the caller to wrap it in `require()`), `EVM.mustRun()` can return `Status.failed` without reverting the Cadence transaction, requiring the caller to assert `result.status == Status.successful`. The function is `access(all)` and reachable by any unprivileged transaction sender.

---

### Finding Description

`EVM.mustRun()` is defined in `fvm/evm/stdlib/contract.cdc` at lines 838–851:

```cadence
/// mustRun runs the transaction using EVM.run
/// It will rollback if the tx execution status is unknown or invalid.
/// Note that this method does not rollback if transaction
/// is executed but an vm error is reported as the outcome
/// of the execution (status: failed).
access(all)
fun mustRun(tx: [UInt8], coinbase: EVMAddress): Result {
    let runResult = self.run(tx: tx, coinbase: coinbase)
    assert(
        runResult.status == Status.failed || runResult.status == Status.successful,
        message: "EVM.mustRun(): The provided transaction is not valid for execution"
    )
    return runResult
}
```

The `assert` condition is `status == failed || status == successful` — it only rejects `StatusInvalid` and `StatusUnknown`. It **explicitly allows `StatusFailed` to pass through** and return to the caller without reverting the Cadence transaction. The inline comment confirms this is intentional design.

The three EVM result statuses are:

| Status | Meaning |
|---|---|
| `StatusUnknown` (0) | Not executed |
| `StatusInvalid` (1) | Rejected before execution (e.g., bad nonce, gas limit) |
| `StatusFailed` (2) | Executed but EVM reverted (e.g., `transferFrom` reverted) |
| `StatusSuccessful` (3) | Executed and succeeded |

`mustRun` only blocks `StatusUnknown` and `StatusInvalid`. A `StatusFailed` result — which is exactly what an ERC20 `transferFrom` revert produces — is returned to the caller without any Cadence-level revert.

Any Cadence transaction that:
1. Calls `EVM.mustRun()` to execute an EVM token transfer (e.g., `transferFrom` on an ERC20)
2. Does **not** assert `result.status == EVM.Status.successful`
3. Proceeds to mint or deposit Cadence-side assets

…will complete the Cadence-side state change even though the EVM-side transfer failed. This is structurally identical to the reported Solidity pattern of calling `transferFrom()` without `require()`.

---

### Impact Explanation

**Cross-VM asset loss / bridge escrow mis-accounting.** An attacker can craft an EVM transaction that is designed to fail on the EVM side (e.g., by ensuring the ERC20 `transferFrom` reverts due to insufficient allowance or a non-standard ERC20 that returns `false`). If the calling Cadence code uses `mustRun` and does not check the returned `Result.status`, the Cadence transaction will proceed to mint or deposit Cadence-side tokens even though no EVM-side tokens were transferred. This breaks the invariant that Cadence-side assets are only issued when the corresponding EVM-side transfer succeeds, enabling an attacker to receive Cadence-side tokens for free.

---

### Likelihood Explanation

**Medium.** `EVM.mustRun()` is `access(all)` — any unprivileged transaction sender can call it directly. The function is explicitly documented to not revert on `StatusFailed`, making it a footgun for any Cadence code that uses it for EVM token transfers without a subsequent status check. The risk is realized whenever a Cadence transaction (including protocol-level bridge transactions) uses `mustRun` as a convenience wrapper and omits the `result.status == Status.successful` assertion before proceeding with Cadence-side asset issuance.

---

### Recommendation

1. **Add a `mustRunSuccessful` variant** that reverts on both `StatusFailed` and `StatusInvalid`, analogous to wrapping `transferFrom` in `require()`:

```cadence
access(all)
fun mustRunSuccessful(tx: [UInt8], coinbase: EVMAddress): Result {
    let runResult = self.run(tx: tx, coinbase: coinbase)
    assert(
        runResult.status == Status.successful,
        message: "EVM.mustRunSuccessful(): EVM transaction did not succeed"
    )
    return runResult
}
```

2. **Rename `mustRun`** to `runAllowingFailure` or `runOrFail` to make the non-reverting-on-failure behavior explicit in the name, reducing the chance of callers assuming it guarantees success.

3. **Audit all callers** of `mustRun` in Cadence transactions and bridge contracts to ensure every call site asserts `result.status == Status.successful` before performing any Cadence-side asset issuance or state mutation.

---

### Proof of Concept

A Cadence transaction exploiting this pattern:

```cadence
import EVM from <EVMContractAddress>
import FlowToken from <FlowTokenAddress>

transaction(erc20TransferFromTx: [UInt8], coinbaseBytes: [UInt8; 20]) {
    prepare(account: auth(Storage) &Account) {
        let coinbase = EVM.EVMAddress(bytes: coinbaseBytes)

        // Step 1: Call mustRun with an EVM tx that calls transferFrom on an ERC20.
        // The EVM transferFrom is crafted to revert (e.g., insufficient allowance).
        let result = EVM.mustRun(tx: erc20TransferFromTx, coinbase: coinbase)

        // result.status == EVM.Status.failed — but mustRun did NOT revert.
        // Step 2: No status check. Proceed to mint Cadence-side tokens.
        // (Any subsequent Cadence asset issuance here executes unconditionally.)
    }
}
```

`mustRun` returns `Status.failed` without reverting, so any Cadence-side asset issuance in Step 2 executes even though the EVM-side `transferFrom` failed — directly mirroring the reported Solidity vulnerability where `transferFrom()` returns `false` and the `mint()` call proceeds. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** fvm/evm/stdlib/contract.cdc (L827-836)
```text
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

**File:** fvm/evm/stdlib/contract.cdc (L838-851)
```text
    /// mustRun runs the transaction using EVM.run
    /// It will rollback if the tx execution status is unknown or invalid.
    /// Note that this method does not rollback if transaction
    /// is executed but an vm error is reported as the outcome
    /// of the execution (status: failed).
    access(all)
    fun mustRun(tx: [UInt8], coinbase: EVMAddress): Result {
        let runResult = self.run(tx: tx, coinbase: coinbase)
        assert(
            runResult.status == Status.failed || runResult.status == Status.successful,
            message: "EVM.mustRun(): The provided transaction is not valid for execution"
        )
        return runResult
    }
```

**File:** fvm/evm/types/result.go (L30-42)
```go
var (
	StatusUnknown Status = 0
	// StatusInvalid shows that the transaction was not a valid
	// transaction and rejected to be executed and included in any block.
	StatusInvalid Status = 1
	// StatusFailed shows that the transaction has been executed,
	// but the output of the execution was an error
	// for this case a block is formed and receipts are available
	StatusFailed Status = 2
	// StatusSuccessful shows that the transaction has been executed and the execution has returned success
	// for this case a block is formed and receipts are available
	StatusSuccessful Status = 3
)
```
