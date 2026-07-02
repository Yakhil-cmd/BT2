### Title
Duplicate Entries in `tx.Authorizers` Allow Single Account to Satisfy Multi-Authorizer Transaction Requirements - (File: `fvm/environment/transaction_info.go`)

### Summary

The Flow protocol does not enforce uniqueness of entries in the `tx.Authorizers` list. A malicious transaction sender can include the same account address multiple times in the authorizers list. Because neither the Access node validator nor the FVM verifier deduplicate this list before passing it to the Cadence runtime, the runtime receives duplicate `AuthAccount` references for the same account. This allows a single account holder to satisfy transaction `prepare` signatures that are intended to require authorization from multiple distinct accounts.

### Finding Description

The vulnerability class from the external report — a list of items that should be unique, where the verifier checks each item individually but never enforces global uniqueness — maps directly onto Flow's `tx.Authorizers` field.

**Step 1 — Access node validator does not check for duplicate authorizers.**

`checkAccounts` in `access/validator/validator.go` explicitly checks for duplicate *signatures* (by `{address, keyIndex}` pair) but iterates over `tx.Authorizers` with a plain map-lookup that only checks whether a signature exists for each authorizer address — it never checks whether the same address appears more than once in the list itself: [1](#0-0) 

**Step 2 — FVM transaction verifier does not check for duplicate authorizers.**

`verifyTransaction` in `fvm/transactionVerifier.go` iterates over `tx.Authorizers` and checks `payloadWeights[addr]` for each entry. If the same address appears twice, the weight check runs twice against the same map entry and passes both times. No uniqueness assertion is made: [2](#0-1) 

**Step 3 — `NewTransactionInfo` passes the raw, potentially-duplicate list directly to the Cadence runtime.**

`NewTransactionInfo` in `fvm/environment/transaction_info.go` appends every entry of `params.TxBody.Authorizers` into `runtimeAddresses` with no deduplication: [3](#0-2) 

If `tx.Authorizers = [A, A]`, then `runtimeAddresses = [A, A]`. The Cadence runtime receives this list and provides one `AuthAccount` reference per entry, yielding two references to the same account.

**Contrast with the duplicate-signature check that *is* present.**

The FVM's `newSignatureEntries` correctly deduplicates signatures by `{address, keyIndex}` and returns an error on collision: [4](#0-3) 

No equivalent deduplication exists for the authorizer address list itself.

### Impact Explanation

A transaction sender who controls account `A` can craft a transaction with `Authorizers = [A, A]` and a Cadence script whose `prepare` block declares two signer parameters:

```cadence
transaction {
    prepare(signer1: &Account, signer2: &Account) {
        // signer1 and signer2 are both &Account for address A
    }
}
```

The Cadence runtime receives `runtimeAddresses = [A, A]` and binds both `signer1` and `signer2` to account `A`. Any on-chain contract or transaction script that gates privileged operations behind a two-authorizer `prepare` signature — without additionally asserting `signer1.address != signer2.address` — can be satisfied by a single account holder. This is a direct authorization bypass: one account can impersonate two distinct authorizers, potentially accessing resources, capabilities, or administrative operations that are intended to require multi-party consent.

### Likelihood Explanation

The attack requires no special privileges. Any unprivileged transaction sender can construct a `TransactionBody` with a repeated address in `Authorizers`, sign it once with the key for that address, and submit it through the standard Access API. All existing validation layers (`checkAccounts`, `verifyTransaction`) pass without error.

### Recommendation

1. Add a duplicate-address check in `checkAccounts` (`access/validator/validator.go`) analogous to the existing duplicate-signature check — reject any `tx.Authorizers` list that contains the same address more than once.
2. Add the same check in `verifyTransaction` (`fvm/transactionVerifier.go`) as a defense-in-depth measure at the execution layer.
3. Deduplicate `params.TxBody.Authorizers` in `NewTransactionInfo` (`fvm/environment/transaction_info.go`) before constructing `runtimeAddresses`, so that even if upstream validation is bypassed the runtime never receives duplicate entries.

### Proof of Concept

```
1. Attacker controls account A (address 0x01).
2. Attacker constructs TransactionBody:
     Authorizers = [0x01, 0x01]
     PayloadSignatures = [sig from key 0 of 0x01]
     EnvelopeSignatures = [sig from key 0 of 0x01]  (if 0x01 is also payer)
     Script:
       transaction {
         prepare(s1: &Account, s2: &Account) {
           // s1.address == s2.address == 0x01
           // two-authorizer gate is satisfied
         }
       }
3. Access node: checkAccounts sees 0x01 has a signature → passes.
4. FVM verifyTransaction: payloadWeights[0x01] ≥ threshold → passes (twice).
5. NewTransactionInfo: runtimeAddresses = [0x01, 0x01].
6. Cadence runtime binds s1 and s2 both to &Account for 0x01.
7. Any two-authorizer guard in the script or called contract is satisfied
   by a single account holder.
```

### Citations

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

**File:** fvm/transactionVerifier.go (L139-174)
```go
	type uniqueKey struct {
		address flow.Address
		index   uint32
	}
	duplicate := make(map[uniqueKey]struct{}, numSignatures)

	for _, group := range list {
		for _, signature := range group.signatures {
			entry := &signatureContinuation{
				signatureEntry: signatureEntry{
					TransactionSignature: signature,
					signatureType:        group.signatureType,
				},
			}

			// check signature address is either payer, proposer or authorizer
			_, ok := transactionAddresses[signature.Address]
			if !ok {
				return nil, nil, nil, entry.newError(
					fmt.Errorf("signature is provided for account %s that is neither payer nor authorizer nor proposer", signature.Address))
			}

			key := uniqueKey{
				address: signature.Address,
				index:   signature.KeyIndex,
			}

			_, ok = duplicate[key]
			if ok {
				return nil, nil, nil, entry.newError(
					fmt.Errorf("duplicate signatures are provided for the same key"))
			}
			duplicate[key] = struct{}{}
			signatureContinuations = append(signatureContinuations, entry)
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

**File:** fvm/environment/transaction_info.go (L122-142)
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

	return &transactionInfo{
		params:                     params,
		tracer:                     tracer,
		runtimeAuthorizers:         runtimeAddresses,
		isServiceAccountAuthorizer: isServiceAccountAuthorizer,
	}
```
