### Title
Missing Zero-Address Validation in `EVMAddress.deposit()` Enables Permanent Cross-VM FLOW Token Loss - (File: fvm/evm/stdlib/contract.cdc)

### Summary
The `EVMAddress.deposit()` function in the EVM system contract performs no validation that the recipient EVM address is non-zero before irreversibly moving FLOW tokens from Cadence into the EVM environment. Any unprivileged Cadence transaction can construct an `EVMAddress` with all-zero bytes and call `deposit()`, permanently losing the deposited FLOW tokens to an address no one controls.

### Finding Description
`EVMAddress` is a Cadence struct defined in `fvm/evm/stdlib/contract.cdc`. Its constructor accepts any 20-byte array with no restrictions:

```cadence
view init(bytes: [UInt8; 20]) {
    self.bytes = bytes
}
```

The `deposit()` method on `EVMAddress` is `access(all)` and moves a `FlowToken.Vault` from Cadence into the EVM environment at `self.bytes`:

```cadence
access(all)
fun deposit(from: @FlowToken.Vault) {
    pre {
        !EVM.isPaused(): "EVM operations are temporarily paused"
    }
    let amount = from.balance
    if amount == 0.0 {
        destroy from
        return
    }
    let depositedUUID = from.uuid
    InternalEVM.deposit(
        from: <-from,
        to: self.bytes          // ← no zero-address check
    )
    ...
}
```

The underlying Go implementation in `fvm/evm/impl/impl.go` (`newInternalEVMTypeDepositFunction`) resolves `self.bytes` to an EVM `types.Address` and calls `account.Deposit()` with no further validation of the address value. The zero address `0x0000000000000000000000000000000000000000` is not a COA (COA addresses carry the prefix `FlowEVMCOAAddressPrefix = {0,0,0,0,0,0,0,0,0,0,0,2,...}`) and is not a controlled precompile. No private key or COA resource corresponds to it; funds credited there are permanently inaccessible.

The same absence of validation applies to `EVM.run()` and `EVM.batchRun()` where the `coinbase: EVMAddress` parameter (the gas-fee collector) is also accepted without a zero-address guard, meaning gas fees can be silently routed to the zero address and lost.

### Impact Explanation
FLOW tokens moved from Cadence to the zero EVM address via `EVMAddress.deposit()` are credited to an address that no entity controls. The cross-VM transfer is irreversible: there is no corresponding withdrawal path because no COA or EOA private key maps to `0x0000...0000`. The tokens are permanently lost — a direct cross-VM asset loss matching the vulnerability class of the reference report.

### Likelihood Explanation
`EVMAddress` construction and `deposit()` are both `access(all)`, reachable by any unsigned Cadence script or signed transaction. A user building a Cadence transaction programmatically (e.g., from a dApp or SDK) who accidentally passes a zero-initialised byte array — a natural default value — will silently lose their tokens with no error or revert. The entry path requires no special privilege, no staked node, and no admin key.

### Recommendation
Add a pre-condition to `EVMAddress.deposit()` (and optionally to the `EVMAddress` constructor) rejecting the zero address:

```cadence
access(all)
fun deposit(from: @FlowToken.Vault) {
    pre {
        !EVM.isPaused(): "EVM operations are temporarily paused"
        self.bytes != [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]:
            "EVM.EVMAddress.deposit(): Cannot deposit to the zero address"
    }
    ...
}
```

Apply the same guard to the `coinbase` parameter in `EVM.run()` and `EVM.batchRun()`.

### Proof of Concept

```cadence
import EVM from <EVM_CONTRACT_ADDRESS>
import FlowToken from <FLOW_TOKEN_ADDRESS>
import FungibleToken from <FUNGIBLE_TOKEN_ADDRESS>

transaction(amount: UFix64) {
    prepare(signer: auth(BorrowValue) &Account) {
        let vault <- signer.storage
            .borrow<auth(FungibleToken.Withdraw) &FlowToken.Vault>(
                from: /storage/flowTokenVault
            )!
            .withdraw(amount: amount) as! @FlowToken.Vault

        // Construct the zero EVM address — no validation prevents this
        let zeroAddress = EVM.EVMAddress(
            bytes: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        )

        // Tokens are moved from Cadence to EVM at 0x0000...0000
        // No revert, no error — funds are permanently lost
        zeroAddress.deposit(from: <-vault)
    }
}
```

**Root cause lines:**

`EVMAddress` constructor — no address validation: [1](#0-0) 

`EVMAddress.deposit()` — no zero-address pre-condition before irreversible cross-VM transfer: [2](#0-1) 

Go-layer deposit implementation — no zero-address check on `toAddress`: [3](#0-2) 

`EVM.run()` — coinbase also unvalidated: [4](#0-3) 

`EVM.batchRun()` — coinbase also unvalidated: [5](#0-4)

### Citations

**File:** fvm/evm/stdlib/contract.cdc (L163-165)
```text
        view init(bytes: [UInt8; 20]) {
            self.bytes = bytes
        }
```

**File:** fvm/evm/stdlib/contract.cdc (L202-216)
```text
        fun deposit(from: @FlowToken.Vault) {
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }

            let amount = from.balance
            if amount == 0.0 {
                destroy from
                return
            }
            let depositedUUID = from.uuid
            InternalEVM.deposit(
                from: <-from,
                to: self.bytes
            )
```

**File:** fvm/evm/stdlib/contract.cdc (L828-836)
```text
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

**File:** fvm/evm/stdlib/contract.cdc (L918-926)
```text
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

**File:** fvm/evm/impl/impl.go (L665-679)
```go
			toAddress, err := AddressBytesArrayValueToEVMAddress(context, toAddressValue)
			if err != nil {
				panic(err)
			}

			// NOTE: We're intentionally not destroying the vault here,
			// because the value of it is supposed to be "kept alive".
			// Destroying would incorrectly be equivalent to a burn and decrease the total supply,
			// and a withdrawal would then have to perform an actual mint of new tokens.

			// Deposit

			const isAuthorized = false
			account := handler.AccountByAddress(toAddress, isAuthorized)
			account.Deposit(types.NewFlowTokenVault(amount))
```
