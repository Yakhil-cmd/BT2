### Title
No Duplicate Authorizer Check Allows Multi-Account Authorization Bypass - (File: fvm/environment/transaction_info.go, access/validator/validator.go)

### Summary
The flow-go transaction validation pipeline never checks for duplicate addresses in `tx.Authorizers`. An unprivileged transaction sender can list the same account address multiple times in the `Authorizers` array. Because the FVM builds the Cadence runtime's authorizer list by directly appending each entry without deduplication, the Cadence runtime receives duplicate `AuthAccount` references for the same account. This allows a single-account signer to satisfy a transaction's multi-account `prepare` parameter list, bypassing the intended N-of-N distinct-account authorization requirement.

### Finding Description

**Root cause 1 — Access-node validation (`access/validator/validator.go`)**

`checkAddresses` iterates over `tx.Authorizers` and validates each address against the chain's address generator, but performs no uniqueness check: [1](#0-0) 

`checkAccounts` detects duplicate *signatures* (by `{address, keyIndex}` pair) but never checks whether the same address appears more than once in `tx.Authorizers`: [2](#0-1) 

If `tx.Authorizers = [addrA, addrA]`, the loop at line 452 runs twice for `addrA`. Both iterations find a valid signature and return no error.

**Root cause 2 — FVM execution-time verification (`fvm/transactionVerifier.go`)**

`verifyTransaction` iterates over `tx.Authorizers` to check key-weight thresholds but again performs no duplicate check: [3](#0-2) 

`payloadWeights[addrA]` is the same value on both iterations, so both pass.

**Root cause 3 — Runtime authorizer list construction (`fvm/environment/transaction_info.go`)**

`NewTransactionInfo` builds `runtimeAddresses` by appending every entry in `tx.Authorizers` verbatim, without deduplication: [4](#0-3) 

`runtimeAddresses` is stored as `runtimeAuthorizers` and handed directly to the Cadence runtime. With `tx.Authorizers = [addrA, addrA]`, the runtime receives `[addrA, addrA]` and creates two separate `auth(...) &Account` references for the same account, one per `prepare` parameter.

### Impact Explanation

A Cadence transaction whose `prepare` block declares N parameters is designed to require N *distinct* account authorizations. With duplicate authorizers, an attacker who controls a single account `addrA` can:

1. Set `tx.Authorizers = [addrA, addrA, …]` (N copies).
2. Provide only `addrA`'s signature — the weight check passes for every occurrence.
3. The Cadence runtime satisfies all N `prepare` parameters with references to `addrA`.

Any on-chain contract that enforces a multi-party invariant through the number of `prepare` signers (e.g., two-party atomic swaps, multi-sig vaults, governance proposals requiring distinct voters) can be executed by a single party, bypassing the intended authorization model. This constitutes unauthorized account mutation: the attacker gains `auth(...)` capabilities over the target contract's logic paths that were gated on a second independent account.

### Likelihood Explanation

The attack requires no special privileges, no staked node control, no leaked keys, and no social engineering. Any user who can submit a transaction to an Access node can craft `tx.Authorizers` with repeated entries. The only prerequisite is the existence of a deployed Cadence contract whose security relies on distinct `prepare` signers — a common pattern for multi-party DeFi and governance contracts on Flow.

### Recommendation

Add a uniqueness check for `tx.Authorizers` in `checkAccounts` (or `checkAddresses`) in `access/validator/validator.go`, mirroring the existing duplicate-signature guard:

```go
seenAuthorizers := make(map[flow.Address]struct{}, len(tx.Authorizers))
for _, auth := range tx.Authorizers {
    if _, dup := seenAuthorizers[auth]; dup {
        return DuplicateAuthorizerError{Address: auth}
    }
    seenAuthorizers[auth] = struct{}{}
}
```

Additionally, apply the same deduplication in `NewTransactionInfo` in `fvm/environment/transaction_info.go` as a defense-in-depth measure before constructing `runtimeAddresses`.

### Proof of Concept

1. Deploy a Cadence contract requiring two distinct signers:
   ```cadence
   transaction {
       prepare(buyer: auth(Storage) &Account, seller: auth(Storage) &Account) {
           // intended: buyer != seller
           let nft <- seller.storage.load<@NFT>(from: /storage/nft)!
           buyer.storage.save(<-nft, to: /storage/nft)
       }
   }
   ```
2. Construct `tx.Authorizers = [attackerAddr, attackerAddr]` and sign only with `attackerAddr`'s key.
3. Submit to any Access node. `checkAddresses` and `checkAccounts` pass without error.
4. The FVM's `verifyTransaction` passes the weight check for both occurrences of `attackerAddr`.
5. `NewTransactionInfo` builds `runtimeAddresses = [attackerAddr, attackerAddr]`.
6. The Cadence runtime binds both `buyer` and `seller` to `attackerAddr`'s account.
7. The attacker executes the swap referencing only their own account, bypassing the seller's authorization entirely.

### Citations

**File:** access/validator/validator.go (L404-413)
```go
func (v *TransactionValidator) checkAddresses(tx *flow.TransactionBody) error {
	for _, address := range append(tx.Authorizers, tx.Payer) {
		// we check whether this is a valid output of the address generator
		if !v.chain.IsValid(address) {
			return InvalidAddressError{Address: address}
		}
	}

	return nil
}
```

**File:** access/validator/validator.go (L421-460)
```go
func (v *TransactionValidator) checkAccounts(tx *flow.TransactionBody) error {
	// check for duplicate account key
	type uniqueKey struct {
		address flow.Address
		index   uint32
	}
	observedSigs := make(map[uniqueKey]bool)
	for _, sig := range append(tx.PayloadSignatures, tx.EnvelopeSignatures...) {
		if observedSigs[uniqueKey{sig.Address, sig.KeyIndex}] {
			return DuplicatedSignatureError{Address: sig.Address, KeyIndex: sig.KeyIndex}
		}
		observedSigs[uniqueKey{sig.Address, sig.KeyIndex}] = true
	}
	// check for minimum account signatures
	observedEnvelopeSig := make(map[flow.Address]bool)
	observedPayloadSig := make(map[flow.Address]bool)
	for _, sig := range tx.EnvelopeSignatures {
		observedEnvelopeSig[sig.Address] = true
	}
	for _, sig := range tx.PayloadSignatures {
		observedPayloadSig[sig.Address] = true
	}

	if !observedEnvelopeSig[tx.Payer] {
		return MissingSignatureError{Address: tx.Payer, Message: "payer envelope signature is missing"}
	}

	if !observedEnvelopeSig[tx.ProposalKey.Address] && !observedPayloadSig[tx.ProposalKey.Address] {
		return MissingSignatureError{Address: tx.ProposalKey.Address, Message: "proposer signature on either payload or envelope is missing"}
	}

	for _, authorizer := range tx.Authorizers {
		if authorizer == tx.Payer || authorizer == tx.ProposalKey.Address {
			// at this point, payer and proposer are guaranteed to have signatures
			continue
		}
		if !observedEnvelopeSig[authorizer] && !observedPayloadSig[authorizer] {
			return MissingSignatureError{Address: authorizer, Message: "authorizer signature on either payload or envelope is missing"}
		}
	}
```

**File:** fvm/transactionVerifier.go (L248-264)
```go
	// all authorizers must have sufficient weights
	for _, addr := range tx.Authorizers {
		// Skip this authorizer if it is also the payer. In the case where an account is
		// both a PAYER as well as an AUTHORIZER or PROPOSER, that account is required
		// to sign only the envelope.
		if addr == tx.Payer {
			continue
		}
		// hasSufficientKeyWeight
		if !v.hasSufficientKeyWeight(payloadWeights, addr, keyWeightThreshold) {
			return errors.NewAccountAuthorizationErrorf(
				addr,
				"authorizer account does not have sufficient signatures (%d < %d)",
				payloadWeights[addr],
				keyWeightThreshold)
		}
	}
```

**File:** fvm/environment/transaction_info.go (L122-135)
```go
	isServiceAccountAuthorizer := false
	runtimeAddresses := make(
		[]common.Address,
		0,
		len(params.TxBody.Authorizers))

	for _, auth := range params.TxBody.Authorizers {
		runtimeAddresses = append(
			runtimeAddresses,
			common.Address(auth))
		if auth == serviceAccount {
			isServiceAccountAuthorizer = true
		}
	}
```
