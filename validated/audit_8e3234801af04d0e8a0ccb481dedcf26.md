### Title
`MaxPayerTransactionRate` Per-Payer Collection Rate Limit Can Be Gamed via Multiple Payer Addresses - (File: `module/builder/collection/rate_limiter.go`)

---

### Summary

Flow's Collection Node builder enforces a per-payer transaction rate limit (`MaxPayerTransactionRate`) during collection construction. This check is scoped exclusively to the `tx.Payer` address field. An attacker who controls multiple funded wallets can trivially bypass this limit by spreading transactions across N different payer addresses, filling entire collections and starving out legitimate users — exactly the same class of false-security invariant described in the external report.

---

### Finding Description

The `rateLimiter` in `module/builder/collection/rate_limiter.go` enforces a maximum number of transactions per payer address per collection. The `shouldRateLimit()` function checks only `tx.Payer`:

```go
func (limiter *rateLimiter) shouldRateLimit(tx *flow.TransactionBody) bool {
    payer := tx.Payer
    _, isUnlimited := limiter.unlimited[payer]
    if limiter.rate <= 0 || isUnlimited {
        return false
    }
    if limiter.rate >= 1 {
        if limiter.txIncludedCount[payer] >= limiter.txPerBlock {
            return true
        }
    }
    ...
}
``` [1](#0-0) 

The rate is tracked per-address in `txIncludedCount[payer]`. There is no identity binding, stake requirement, or cross-address aggregation. An attacker who controls N funded wallets can submit `MaxPayerTransactionRate` transactions from each wallet, collectively filling the entire collection (`N × rate` transactions) while each individual address appears compliant.

Compounding this, the default value of `MaxPayerTransactionRate` is `0`, meaning **rate limiting is disabled by default**: [2](#0-1) 

Even when operators enable the rate limit, the codebase itself documents that the per-node limit does not translate cleanly to a network-wide limit due to multi-cluster propagation: [3](#0-2) 

The ingest-level `AddressRateLimiter` (`engine/collection/ingest/rate_limiter.go`) has the same structural flaw: it is an opt-in allowlist that only limits addresses explicitly added by an operator. Any new address — trivially created by an attacker — is never rate-limited: [4](#0-3) 

---

### Impact Explanation

**Impact: Medium.** A protocol invariant — that `MaxPayerTransactionRate` provides fair access to collection space — can be broken. An attacker with N funded wallets can fill entire collections with their own transactions, preventing legitimate users from getting transactions included. The code gives operators and users a false sense of security that the rate limit is protective, when it is trivially bypassed by address proliferation. This is a fairness/access-control violation at the transaction inclusion layer, not a direct asset theft, hence Medium rather than High.

---

### Likelihood Explanation

**Likelihood: Medium.** Creating multiple Flow accounts is cheap and permissionless. An attacker only needs to fund N wallets with enough FLOW to pay transaction fees. The attack requires no privileged access, no staked node, and no special knowledge beyond the configured `MaxPayerTransactionRate` value (which is a public node configuration). Similar multi-wallet sniping attacks have been observed on other chains.

---

### Recommendation

1. **Document** that `MaxPayerTransactionRate` does not protect against multi-address sniping attacks. Operators should not rely on it as a fairness guarantee.
2. **Consider** an aggregate rate limit that tracks total transactions per time window across all payers, not just per-payer, to bound the total throughput any single economic actor can achieve.
3. **Consider** requiring a minimum account age or minimum FLOW balance for payer accounts to raise the cost of the multi-wallet attack.
4. **For the ingest-level `AddressRateLimiter`**: document that it is a reactive remediation tool (blocklist), not a proactive fairness mechanism, and cannot prevent attacks from new/unknown addresses.

---

### Proof of Concept

**Setup:** Collection node configured with `--builder-rate-limit 1` (1 transaction per payer per collection) and `--builder-max-collection-size 100`.

**Attack:**
1. Attacker creates 100 Flow accounts (`addr_1` … `addr_100`), each funded with enough FLOW to pay fees.
2. Attacker submits 1 transaction from each address simultaneously, all targeting the same collection window.
3. The `rateLimiter.shouldRateLimit()` checks `txIncludedCount[addr_i]` for each address independently. Each address has count 0, so none are rate-limited.
4. All 100 attacker transactions are included in the collection, filling it completely (`txIncludedCount[addr_i] = 1` for each, never reaching `txPerBlock = 1`).
5. Legitimate users' transactions are excluded from that collection.

The `transactionIncluded()` call only increments the count for the specific payer address used: [5](#0-4) 

Since each attacker address is a distinct key in `txIncludedCount`, the per-payer limit is never triggered, and the collection is monopolized.

### Citations

**File:** module/builder/collection/rate_limiter.go (L65-68)
```go
// note that we have added a transaction to the collection under construction.
func (limiter *rateLimiter) transactionIncluded(tx *flow.TransactionBody) {
	limiter.txIncludedCount[tx.Payer]++
}
```

**File:** module/builder/collection/rate_limiter.go (L72-88)
```go
func (limiter *rateLimiter) shouldRateLimit(tx *flow.TransactionBody) bool {

	payer := tx.Payer

	// skip rate limiting if it is turned off or the payer is unlimited
	_, isUnlimited := limiter.unlimited[payer]
	if limiter.rate <= 0 || isUnlimited {
		return false
	}

	// if rate >=1, we only consider the current collection and rate limit once
	// the number of transactions for the payer exceeds rate
	if limiter.rate >= 1 {
		if limiter.txIncludedCount[payer] >= limiter.txPerBlock {
			return true
		}
	}
```

**File:** module/builder/collection/config.go (L7-10)
```go
const (
	DefaultExpiryBuffer            uint    = 15 // 15 blocks for collections to be included
	DefaultMaxPayerTransactionRate float64 = 0  // no rate limiting
)
```

**File:** cmd/collection/main.go (L182-191)
```go
		// rate limiting for accounts, default is 2 transactions every 2.5 seconds
		// Note: The rate limit configured for each node may differ from the effective network-wide rate limit
		// for a given payer. In particular, the number of clusters and the message propagation factor will
		// influence how the individual rate limit translates to a network-wide rate limit.
		// For example, suppose we have 5 collection clusters and configure each Collection Node with a rate
		// limit of 1 message per second. Then, the effective network-wide rate limit for a payer address would
		// be *at least* 5 messages per second.
		flags.Float64Var(&txRatelimits, "ingest-tx-rate-limits", 2.5, "per second rate limits for processing transactions for limited account")
		flags.IntVar(&txBurstlimits, "ingest-tx-burst-limits", 2, "burst limits for processing transactions for limited account")
		flags.StringVar(&txRatelimitPayers, "ingest-tx-rate-limit-payers", "", "comma separated list of accounts to apply rate limiting to")
```

**File:** engine/collection/ingest/rate_limiter.go (L51-62)
```go
func (r *AddressRateLimiter) IsRateLimited(address flow.Address) bool {
	r.mu.RLock()
	limiter, ok := r.limiters[address]
	r.mu.RUnlock()

	if !ok {
		return false
	}

	rateLimited := !limiter.Allow()
	return rateLimited
}
```
