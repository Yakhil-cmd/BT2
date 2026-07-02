### Title
Missing Deduplication of `tx.Authorizers` Allows Single-Signature Bypass of Multi-Party Authorization - (File: `fvm/transactionVerifier.go`)

---

### Summary
Neither the Access/Collection node pre-execution validator (`access/validator/validator.go`) nor the FVM in-execution verifier (`fvm/transactionVerifier.go`) deduplicate the `tx.Authorizers` address array before checking authorization. An unprivileged sender can list the same address multiple times in `Authorizers`, satisfy every authorizer slot with a single signature, and cause the Cadence runtime to receive multiple `auth(...)` account references for the same account — bypassing any multi-party authorization requirement that does not explicitly assert account-address uniqueness.

---

### Finding Description

`flow.TransactionBody.Authorizers` is an ordered `[]Address` slice with no uniqueness invariant enforced at the protocol level.

**Validator layer** — `access/validator/validator.go` `checkAccounts()`:

```go
for _, authorizer := range tx.Authorizers {          // line 452
    if authorizer == tx.Payer || authorizer == tx.ProposalKey.Address {
        continue
    }
    if !observedEnvelopeSig[authorizer] && !observedPayloadSig[authorizer] {
        return MissingSignatureError{...}
    }
}
```

`observedPayloadSig` is a `map[flow.Address]bool`. When `addrA` appears twice in `tx.Authorizers`, the second iteration finds `observedPayloadSig[addrA] == true` from the first iteration and silently passes — one signature satisfies both slots. [1](#0-0) 

**FVM execution layer** — `fvm/transactionVerifier.go` `verifyTransaction()`:

```go
for _, addr := range tx.Authorizers {               // line 249
    if addr == tx.Payer { continue }
    if !v.hasSufficientKeyWeight(payloadWeights, addr, keyWeightThreshold) {
        return errors.NewAccountAuthorizationErrorf(...)
    }
}
```

`payloadWeights` is a `map[flow.Address]int`. A duplicate `addrA` passes the weight check on every iteration because the map already holds the aggregated weight from the first occurrence. [2](#0-1) 

The duplicate-*signature* guard (`newSignatureEntries`) deduplicates on `(address, keyIndex)` pairs in the signature arrays, but never inspects `tx.Authorizers` for duplicate addresses. [3](#0-2) 

The REST API parser caps the total authorizer count at 100 but performs no uniqueness check. [4](#0-3) 

The gRPC / Collection-node ingest path applies no authorizer-count or uniqueness limit at all. [5](#0-4) 

The `TransactionBodyBuilder.signerList()` helper does deduplicate when *building* a transaction, but this is client-side only and is never called during server-side validation. [6](#0-5) 

---

### Impact Explanation

When the Cadence runtime executes a transaction whose `Authorizers` list is `[addrA, addrA]`, it provides two `auth(Storage) &Account` (or any entitlement set) references, both pointing to `addrA`. Any Cadence contract or transaction script that:

1. Declares `prepare(a: auth(Storage) &Account, b: auth(Storage) &Account)`, and
2. Does not assert `a.address != b.address`,

can be fully satisfied by a single account. Concrete exploitable patterns include two-party escrow contracts (attacker releases funds held for a second party without that party's consent), 2-of-2 multi-sig vaults, and DAO approval flows that require two distinct member accounts. In each case the attacker gains access to on-chain assets or executes privileged state mutations that require a second party's authorization — without that party ever signing.

---

### Likelihood Explanation

The attack requires only an ordinary user account and a standard transaction submission (gRPC `SendTransaction` or REST `POST /transactions`). No staked node, admin key, or privileged role is needed. The attacker constructs `Authorizers: [addrA, addrA, ...]`, signs once with `addrA`, and submits. The existing validation pipeline accepts the transaction without modification. Likelihood is medium: the exploit is trivially constructed, but requires a target contract that does not independently assert authorizer uniqueness.

---

### Recommendation

Add an explicit duplicate-address check in `checkAccounts()` (pre-execution, `access/validator/validator.go`) and/or at the start of `verifyTransaction()` (in-execution, `fvm/transactionVerifier.go`):

```go
seen := make(map[flow.Address]struct{}, len(tx.Authorizers))
for _, addr := range tx.Authorizers {
    if _, dup := seen[addr]; dup {
        return DuplicateAuthorizerError{Address: addr}
    }
    seen[addr] = struct{}{}
}
```

Rejecting duplicate authorizers at the validator layer prevents the malformed transaction from ever reaching the FVM, mirroring the fix recommended in the original report (push only on first occurrence).

---

### Proof of Concept

```
1. Deploy a Cadence contract requiring two distinct signers:
   access(all) contract TwoPartyVault {
       access(all) fun release(
           ownerRef: auth(Withdraw) &Vault,
           approverRef: auth(Withdraw) &Vault   // assumed to be a different account
       ) { /* transfer assets */ }
   }

2. Craft a transaction:
   Authorizers:        [addrA, addrA]
   PayloadSignatures:  [sig_addrA_key0]   // single signature

3. Submit via gRPC SendTransaction.

4. checkAccounts() iterates Authorizers:
   - first  addrA → observedPayloadSig[addrA] = true  → pass
   - second addrA → observedPayloadSig[addrA] = true  → pass (no error)

5. verifyTransaction() iterates Authorizers:
   - first  addrA → payloadWeights[addrA] >= threshold → pass
   - second addrA → payloadWeights[addrA] >= threshold → pass (same map entry)

6. Cadence runtime receives prepare(ownerRef, approverRef) where both
   references resolve to addrA's account.

7. TwoPartyVault.release() executes; the contract's two-party requirement
   is bypassed with only addrA's consent.
```

### Citations

**File:** access/validator/validator.go (L452-460)
```go
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

**File:** fvm/transactionVerifier.go (L249-264)
```go
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

**File:** engine/access/rest/common/parser/transaction.go (L14-36)
```go
const maxAuthorizers = 100

type Transaction flow.TransactionBody

func (t *Transaction) Parse(raw io.Reader, chain flow.Chain) error {
	var tx models.TransactionsBody
	err := common.ParseBody(raw, &tx)
	if err != nil {
		return err
	}

	if tx.ProposalKey == nil {
		return fmt.Errorf("proposal key not provided")
	}
	if tx.Script == "" {
		return fmt.Errorf("script not provided")
	}
	if tx.Payer == "" {
		return fmt.Errorf("payer not provided")
	}
	if len(tx.Authorizers) > maxAuthorizers {
		return fmt.Errorf("too many authorizers. Maximum authorizers allowed: %d", maxAuthorizers)
	}
```

**File:** engine/collection/ingest/engine.go (L335-365)
```go
func (e *Engine) ingestTransaction(
	log zerolog.Logger,
	refEpoch protocol.CommittedEpoch,
	tx *flow.TransactionBody,
	txID flow.Identifier,
	localClusterFingerprint flow.Identifier,
	txClusterFingerprint flow.Identifier,
) error {
	// use the transaction pool for the epoch the reference block is part of
	pool := e.pools.ForEpoch(refEpoch.Counter())

	// short-circuit if we have already stored the transaction
	if pool.Has(txID) {
		log.Debug().Msg("received dupe transaction")
		return nil
	}

	// we don't pass actual ctx as we don't execute any scripts inside for now
	err := e.transactionValidator.Validate(context.Background(), tx)
	if err != nil {
		return engine.NewInvalidInputErrorf("invalid transaction (%x): %w", txID, err)
	}

	// if our cluster is responsible for the transaction, add it to our local mempool
	if localClusterFingerprint == txClusterFingerprint {
		_ = pool.Add(tx.ID(), tx)
		e.colMetrics.TransactionIngested(txID)
	}

	return nil
}
```

**File:** model/flow/transaction_body_builder.go (L202-229)
```go
func (tb *TransactionBodyBuilder) signerList() []Address {
	signers := make([]Address, 0)
	seen := make(map[Address]struct{})

	var addSigner = func(address Address) {
		_, ok := seen[address]
		if ok {
			return
		}

		signers = append(signers, address)
		seen[address] = struct{}{}
	}

	if tb.u.ProposalKey.Address != EmptyAddress {
		addSigner(tb.u.ProposalKey.Address)
	}

	if tb.u.Payer != EmptyAddress {
		addSigner(tb.u.Payer)
	}

	for _, authorizer := range tb.u.Authorizers {
		addSigner(authorizer)
	}

	return signers
}
```
