### Title
COA Resource EVM State Can Be Drained Before Cadence-Side Transfer, Enabling Buyer Deception — (File: `fvm/evm/stdlib/contract.cdc`)

---

### Summary

The `CadenceOwnedAccount` (COA) resource in `fvm/evm/stdlib/contract.cdc` is the Flow EVM analog of an NFT-owned vault: it is a Cadence resource that exclusively controls an EVM address and all assets held there. When a COA is sold or transferred via a Cadence marketplace, the seller retains full, unrestricted control of the COA's EVM state until the Cadence resource move is finalized. The seller can drain the EVM FLOW balance, call EVM contracts to extract ERC-20/ERC-721 tokens, or withdraw bridged NFTs in a transaction that executes before or concurrently with the sale settlement. The buyer receives a COA resource whose EVM address is empty, having paid full price for the asset.

---

### Finding Description

A `CadenceOwnedAccount` resource is the sole controller of its associated EVM address. The protocol comment in the contract makes this explicit:

> "COAs are not controlled by a key. Instead, every COA account has a unique resource accessible on the Cadence side, and anyone who owns that resource submits transactions on behalf of this address." [1](#0-0) 

The resource exposes three privileged mutation functions that are callable by whoever currently holds the resource:

1. **`withdraw`** (`access(Owner | Withdraw)`) — transfers the full EVM FLOW balance back to Cadence: [2](#0-1) 

2. **`call`** (`access(Owner | Call)`) — executes arbitrary EVM calls from the COA address, enabling the owner to drain ERC-20 balances or transfer ERC-721 tokens held by the COA's EVM address: [3](#0-2) 

3. **`withdrawNFT`** (`access(Owner | Bridge)`) — withdraws a bridged NFT from the EVM side back to Cadence: [4](#0-3) 

None of these functions check whether the COA is "pending transfer" or "listed for sale." There is no lock, escrow, or freeze mechanism on the resource itself.

Additionally, `validateCOAOwnershipProof` — the only on-chain proof mechanism for COA ownership — validates only that the Cadence account holds a capability to the COA and that the EVM address bytes match. It does **not** attest to the EVM balance or any other state: [5](#0-4) 

This means a buyer who queries the COA's balance before agreeing to a price receives a snapshot that is not guaranteed to hold at settlement time. The seller can submit a `withdraw` or `call` transaction in any block between the buyer's inspection and the resource transfer.

The `deposit` function is `access(all)`, meaning anyone can increase the COA's balance: [6](#0-5) 

This creates a complementary griefing vector: a seller can temporarily inflate the COA balance to attract a higher bid, then drain it before settlement.

---

### Impact Explanation

A buyer who purchases a COA resource through any Cadence marketplace that does not take atomic custody of the resource (i.e., the vast majority of NFT/resource marketplaces) can receive a COA whose EVM address has been fully drained. The buyer loses the purchase price and receives an asset worth zero. All EVM assets — FLOW tokens, ERC-20 tokens, ERC-721 NFTs, and bridged Cadence NFTs — are at risk. The `Account` interface confirms that `Withdraw`, `Call`, and `Deploy` are all COA-exclusive operations: [7](#0-6) 

---

### Likelihood Explanation

Any unprivileged Flow account that owns a COA resource can execute this attack. No special node access, key leakage, or admin privilege is required. The attacker simply submits a `withdraw` or `call` transaction before the marketplace settlement transaction is included. Because Flow transactions are ordered within a block and the seller controls their own transaction submission, this is straightforward to execute without any front-running infrastructure. The attack is economically rational whenever the sale price exceeds the cost of the drain transaction.

---

### Recommendation

1. **Document the risk** clearly in the COA and EVM bridge documentation: COA resources sold on non-custodial marketplaces carry the same state-manipulation risk as NFT-owned vaults on EVM.
2. **Implement a freeze/escrow entitlement** on `CadenceOwnedAccount` that, when set, blocks `withdraw`, `call`, `withdrawNFT`, and `withdrawTokens` until the entitlement is cleared. A custodial marketplace contract would set this flag when taking the resource into escrow.
3. **Vet and allowlist** only custodial marketplaces that atomically take ownership of the COA resource before exposing it for sale, analogous to the `_allowlist` recommendation in the original report.
4. **Extend `validateCOAOwnershipProof`** to optionally attest to a minimum balance or asset snapshot, so buyers can obtain a signed, on-chain commitment to the COA state at a specific block height.

---

### Proof of Concept

```
Block N:   Seller lists COA (EVM balance = 100 FLOW) for 50 FLOW on marketplace.
Block N+1: Buyer inspects COA via EVM.balance() → sees 100 FLOW, agrees to pay 50 FLOW.
Block N+2: Seller submits transaction calling coa.withdraw(balance: fullBalance).
           → EVM address drained to 0 FLOW. FLOWTokensWithdrawn event emitted.
Block N+3: Marketplace settlement transaction executes: COA resource moved to buyer.
           Buyer now owns a COA resource whose EVM address holds 0 FLOW.
           Buyer has paid 50 FLOW and received nothing of value.
```

The seller's drain transaction at Block N+2 is a standard user transaction requiring only ownership of the COA resource — no special access, no staked node, no key compromise. The `withdraw` call path through `InternalEVM.withdraw` is fully exercised in the existing test suite: [8](#0-7)

### Citations

**File:** fvm/evm/stdlib/contract.cdc (L476-482)
```text
        COAs are not controlled by a key.
        Instead, every COA account has a unique resource accessible
        on the Cadence side, and anyone who owns that resource submits transactions
        on behalf of this address. These direct transactions have COA’s EVM address
        as the tx.origin and a new EVM transaction type (TxType = 0xff)
        is used to differentiate these transactions from other types
        of EVM transactions (e.g, DynamicFeeTxType (0x02).
```

**File:** fvm/evm/stdlib/contract.cdc (L562-565)
```text
        access(all)
        fun deposit(from: @FlowToken.Vault) {
            self.address().deposit(from: <-from)
        }
```

**File:** fvm/evm/stdlib/contract.cdc (L586-606)
```text
        access(Owner | Withdraw)
        fun withdraw(balance: Balance): @FlowToken.Vault {
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }

            if balance.isZero() {
                return <-FlowToken.createEmptyVault(vaultType: Type<@FlowToken.Vault>())
            }
            let vault <- InternalEVM.withdraw(
                from: self.addressBytes,
                amount: balance.attoflow
            ) as! @FlowToken.Vault
            emit FLOWTokensWithdrawn(
                address: self.address().toString(),
                amount: balance.inFLOW(),
                withdrawnUUID: vault.uuid,
                balanceAfterInAttoFlow: self.balance().attoflow
            )
            return <-vault
        }
```

**File:** fvm/evm/stdlib/contract.cdc (L636-653)
```text
        access(Owner | Call)
        fun call(
            to: EVMAddress,
            data: [UInt8],
            gasLimit: UInt64,
            value: Balance
        ): Result {
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }
            return InternalEVM.call(
                from: self.addressBytes,
                to: to.bytes,
                data: data,
                gasLimit: gasLimit,
                value: value.attoflow
            ) as! Result
        }
```

**File:** fvm/evm/stdlib/contract.cdc (L755-770)
```text
        access(Owner | Bridge)
        fun withdrawNFT(
            type: Type,
            id: UInt256,
            feeProvider: auth(FungibleToken.Withdraw) &{FungibleToken.Provider}
        ): @{NonFungibleToken.NFT} {
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }
            return <- EVM.borrowBridgeAccessor().withdrawNFT(
                caller: &self as auth(Call) &CadenceOwnedAccount,
                type: type,
                id: id,
                feeProvider: feeProvider
            )
        }
```

**File:** fvm/evm/stdlib/contract.cdc (L1095-1110)
```text
        if let coaRef = acc.capabilities.borrow<&EVM.CadenceOwnedAccount>(path) {
            // verify evm address matching — capture bytes once to avoid redundant borrow
            let coaAddressBytes = coaRef.address().bytes
            for index, item in coaAddressBytes {
                if item != evmAddress[index] {
                    return ValidationResult(
                        isValid: false,
                        problem: "EVM.validateCOAOwnershipProof(): Cannot validate COA ownership. The provided evm address does not match the account's COA address."
                    )
                }
            }
            return ValidationResult(
                isValid: true,
                problem: nil
            )
        }
```

**File:** fvm/evm/types/account.go (L33-55)
```go
	// Withdraw withdraws the balance from account and
	// return it as a FlowTokenVault
	// works only for COAs
	Withdraw(Balance) *FLOWTokenVault

	// Transfer is a utility method on top of call for transferring tokens to another account
	Transfer(to Address, balance Balance)

	// Deploy deploys a contract to the environment
	// the new deployed contract would be at the returned
	// result address and the contract data is not controlled by the COA
	// works only for COAs
	Deploy(Code, GasLimit, Balance) *ResultSummary

	// Call calls a smart contract function with the given data.
	// The gas usage is limited by the given gas limit,
	// and the Flow transaction's computation limit.
	// The fees are deducted from the COA
	// and are transferred to the target address.
	// if no data is provided it would behave as transferring tokens to the
	// target address
	// works only for COAs
	Call(Address, Data, GasLimit, Balance) *ResultSummary
```

**File:** fvm/evm/evm_test.go (L2485-2540)
```go
	t.Run("test coa withdraw with fraction-only amount", func(t *testing.T) {
		t.Parallel()

		RunWithNewEnvironment(t,
			chain, func(
				ctx fvm.Context,
				vm fvm.VM,
				snapshot snapshot.SnapshotTree,
				testContract *TestContract,
				testAccount *EOATestAccount,
			) {
				code := fmt.Appendf(nil,
					`
				import EVM from %s
				import FlowToken from %s
				transaction() {
					prepare(account: auth(BorrowValue) &Account) {
						let admin = account.storage.borrow<&FlowToken.Administrator>(
							from: /storage/flowTokenAdmin
						)!

						let minter <- admin.createNewMinter(allowedAmount: 2.34)
						let vault <- minter.mintTokens(amount: 2.34)
						destroy minter

						let cadenceOwnedAccount <- EVM.createCadenceOwnedAccount()
						cadenceOwnedAccount.deposit(from: <-vault)

						let bal = EVM.Balance(attoflow: 230050780900000000)
						let vault2 <- cadenceOwnedAccount.withdraw(balance: bal)
						let balance = vault2.balance
						assert(balance == 0.23005078, message: "mismatching vault balance")
						destroy cadenceOwnedAccount
						destroy vault2
					}
				}
				`,
					sc.EVMContract.Address.HexWithPrefix(),
					sc.FlowToken.Address.HexWithPrefix(),
				)

				txBody, err := flow.NewTransactionBodyBuilder().
					SetScript(code).
					SetPayer(sc.FlowServiceAccount.Address).
					AddAuthorizer(sc.FlowServiceAccount.Address).
					Build()
				require.NoError(t, err)
				tx := fvm.Transaction(txBody, 0)

				_, output, err := vm.Run(
					ctx,
					tx,
					snapshot,
				)
				require.NoError(t, err)
				require.NoError(t, output.Err)
```
