### Title
Light-client private payment validation trusts `linked` flag without re-verifying link proofs at final validation time - ([File: indivisible_asset.js])

### Summary
`ocore`'s light-client path for validating private (indivisible-asset) payment chains substitutes a full DAG-inclusion check with a separately-fetched "link proof" that is validated once and then cached via the `linked` flag, similarly to how Mithril's client trusted an unsigned ledger-state snapshot instead of doing a full, per-use consistency check. If the cached/short-circuited trust decision does not remain bound to the exact data that is later consumed for `validateAndSavePrivatePaymentChain`, a malicious private-payment counterparty (sender of a private chain to a light wallet) can get a chain accepted whose source-output inclusion was never actually checked against the same chain contents that are recorded and spent.

### Finding Description
For non-light nodes, `validateSourceOutput()` in `indivisible_asset.js` verifies that the referenced input unit is actually included in (an ancestor of) the unit that spends it, using `graph.determineIfIncluded`: [1](#0-0) 

For light clients this check is skipped entirely with the comment "already validated the linkproof": [2](#0-1) 

The "linkproof" is validated out-of-band by `updateLinkProofsOfPrivateChain`/`checkThatEachChainElementIncludesThePrevious`, which fetches proofs from the light vendor and, only if the check passes, sets a `linked=1` flag on the `unhandled_private_payments` row: [3](#0-2) 

That flag is later used purely as a gate to decide whether to re-run the link-proof check before final validation and save (`handleSavedPrivatePayments`): [4](#0-3) 

This mirrors the Mithril bug class: a security-critical consistency check (matching claimed ancestor/inclusion state against the actual chain content) is decoupled from the point where the data is trusted and persisted, relying on a previously-cached, remotely-sourced assertion (`linked=1`) which is not tied cryptographically to the exact `arrPrivateElements` payload being saved. Nothing recomputes a hash over the specific `arrPrivateElements` content and ties it to the stored `linked` flag — the flag is keyed only by `(unit, message_index)`, not by the full content of the private elements array, so if a peer later resends the same `(unit, message_index)` head with fabricated/altered private chain payload/ancestor data, the cached `linked=1` state from an earlier, differently-consistent chain could be reused to skip actual inclusion verification for the new chain, because `validateSourceOutput` in light mode never re-checks inclusion regardless.

### Impact Explanation
If the source output's actual DAG inclusion is not enforced at validation-and-save time on light clients, a malicious private-payment counterparty could construct a private (indivisible-asset) chain claiming a coin was transferred from an output that is not actually an ancestor of the current spending unit, or is stale relative to double-spend state that the honest inclusion check would have caught. Because `validation.validatePayment` still separately checks spend proofs and double-spend flags in the DB, the practical exploitability is bounded — but the removal of the ancestor-inclusion check specifically for light wallets, combined with a caching mechanism (`linked`) not scoped to the specific chain content, creates a path where light-wallet users could accept/spend coins based on private chains whose ordering/inclusion was never actually verified against the DAG, potentially leading to acceptance of a payment that references an output not legitimately spendable in that context (fund loss/freezing for the light-wallet counterparty).

### Likelihood Explanation
Reaching this path requires only that the victim run in light mode (`conf.bLight`) and receive a multi-element private payment chain from an untrusted counterparty or a colluding light vendor — a normal wallet-to-wallet flow, not requiring any special privilege. The `linked` flag caching and the unconditional inclusion-check bypass (`if (conf.bLight) return cb();`) are both reachable by a single posted private payment chain, matching the "private-payment counterparty" threat actor allowed by this analysis. However, without being able to run the full test suite / trace `checkThatEachChainElementIncludesThePrevious` against every re-entry path (e.g. whether `arrChain`/hashes are truly recomputed each time `validateAndSave` runs), the exact exploitability and whether other checks (spend-proof/double-spend) fully close the gap is not fully confirmed from static reading alone.

### Recommendation
- In `indivisible_asset.js`'s `validateSourceOutput`, do not unconditionally skip inclusion checking for light clients; instead verify that the specific private chain content currently being validated matches the content that was link-proofed (e.g. by hashing `arrPrivateElements` and storing/comparing that hash alongside the `linked` flag), or re-run `checkThatEachChainElementIncludesThePrevious` synchronously as part of `validateAndSavePrivatePaymentChain` regardless of the cached flag. [1](#0-0) 
- Scope the `linked` cache key in `unhandled_private_payments` to the full chain content hash, not just `(unit, message_index)`, so a resent/altered chain cannot reuse a stale trust decision. [3](#0-2) 

### Proof of Concept
Not fully constructible from static analysis alone: exploitation requires controlling a light-client wallet's private-chain reception flow and demonstrating that a resent `(unit, message_index)` head with altered payload bypasses `graph.determineIfIncluded`-equivalent verification purely via the cached `linked=1` state. This would need to be validated by tracing actual DB row keys and running the light-client test harness, which requires execution access beyond static code reading — this is explicitly flagged as unverified.

### Citations

**File:** indivisible_asset.js (L44-52)
```javascript
	function validateSourceOutput(cb){
		if (conf.bLight)
			return cb(); // already validated the linkproof
		profiler.start();
		graph.determineIfIncluded(conn, input.unit, [objPrivateElement.unit], function(bIncluded){
			profiler.stop('determineIfIncluded');
			bIncluded ? cb() : cb("input unit not included");
		});
	}
```

**File:** network.js (L2504-2510)
```javascript
					};
					
					if (conf.bLight && arrPrivateElements.length > 1 && !row.linked)
						updateLinkProofsOfPrivateChain(arrPrivateElements, row.unit, row.message_index, row.output_index, cb, validateAndSave);
					else
						validateAndSave();
					
```

**File:** network.js (L2693-2711)
```javascript
// light only
function updateLinkProofsOfPrivateChain(arrPrivateElements, unit, message_index, output_index, onFailure, onSuccess){
	if (!conf.bLight)
		throw Error("not light but updateLinkProofsOfPrivateChain");
	if (!onFailure)
		onFailure = function(){};
	if (!onSuccess)
		onSuccess = function(){};
	checkThatEachChainElementIncludesThePrevious(arrPrivateElements, function(bLinked){
		if (bLinked === null)
			return onFailure();
		if (!bLinked)
			return deleteHandledPrivateChain(unit, message_index, output_index, onFailure);
		// the result cannot depend on output_index
		db.query("UPDATE unhandled_private_payments SET linked=1 WHERE unit=? AND message_index=?", [unit, message_index], function(){
			onSuccess();
		});
	});
}
```
