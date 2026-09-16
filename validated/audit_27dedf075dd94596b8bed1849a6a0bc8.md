### Title
Light-client private payment inclusion check can be bypassed via a stale/mis-scoped `linked` flag - ([File: network.js])

### Summary
In light wallets, the crucial DAG-inclusion check for private-payment inputs (`graph.determineIfIncluded`, the ocore equivalent of a Merkle/inclusion-proof check) is skipped in `indivisible_asset.js`'s `validateSourceOutput`, on the assumption that an equivalent check ("linkproof") was already performed by a separate abstraction in `network.js`. That separate check is recorded via a `linked` flag that is scoped only by `unit` + `message_index`, not by `output_index`/full chain content, so it can be reused by an unrelated/unverified private-payment chain for a different output of the same message — exactly the "split abstraction, unsafe direct-call fallback" bug class described in the source report (`TxFinalizationVerifier.checkInclusionProof` vs. direct, unguarded `Merkle.checkMembership`).

### Finding Description
`indivisible_asset.js`'s `validateSourceOutput` is the function that verifies a private-payment input actually descends from the referenced prior transaction — the ocore analog of the plasma exit games' inclusion proof: [1](#0-0) 

For light clients it unconditionally skips this check, trusting that inclusion ("linkproof") was already validated elsewhere:
```
function validateSourceOutput(cb){
    if (conf.bLight)
        return cb(); // already validated the linkproof
    ...
    graph.determineIfIncluded(conn, input.unit, [objPrivateElement.unit], function(bIncluded){...});
}
``` [1](#0-0) 

The "already validated" claim depends on `network.js`'s `updateLinkProofsOfPrivateChain`, which is only invoked when the stored `unhandled_private_payments` row is not yet marked `linked`: [2](#0-1) 

That function marks the row `linked=1` scoped by `unit` and `message_index` only — explicitly not by `output_index` — based on the comment "the result cannot depend on output_index": [3](#0-2) 

The actual per-chain inclusion check performed there (`checkThatEachChainElementIncludesThePrevious` → `light.processLinkProofs`) validates the specific sequence of unit hops (`arrUnits`) belonging to one particular `arrPrivateElements` chain (i.e., one specific output/message combination): [4](#0-3) 

Because the `linked` flag is written for `unit`+`message_index` as a whole rather than per exact chain/`output_index`, once any one output of a multi-output message has its private-element chain validated and marked `linked=1`, subsequent (or concurrently received) private-payment chains for a *different* `output_index` of the same message — potentially referencing a completely different, unverified predecessor unit sequence — will be treated as already-linked and will skip `updateLinkProofsOfPrivateChain` in `handleSavedPrivatePayments`, and will then also skip the direct inclusion check inside `validateSourceOutput` (`conf.bLight` branch). This mirrors the report's root cause precisely: an inclusion check is delegated to a side abstraction, and a different code path relies on that abstraction's result without confirming it actually covers the same data.

### Impact Explanation
If exploited, a malicious private-payment counterparty (a normal, unprivileged actor that can send private payment chains to a light wallet, e.g. over a paired device / hub message) could craft a private-payment chain whose stated source output/input unit is not actually included in the DAG ancestry it claims, and have the light wallet's `validateSourceOutput` skip the inclusion check due to a `linked` flag set by an earlier, unrelated output in the same message. Since `validateSourceOutput` is the only defense that ties a claimed private input to a real, DAG-included predecessor transaction for light nodes, bypassing it can let a light wallet accept and later spend from an output whose chain of custody was never actually verified — i.e., value that does not legitimately trace back to a valid issuance, a form of fund fabrication/unauthorized spending in the victim's local (light) view of their private asset balance.

### Likelihood Explanation
Requires: (1) a private, indivisible asset message with multiple outputs to the same or split addresses (a normal use case, not requiring any privileged access), (2) light wallet mode (`conf.bLight`), and (3) the attacker crafting one output's chain to be legitimately link-proof-verified (setting `linked=1`) while attaching another output's chain with a fabricated/uninclusion input at the same `unit`+`message_index`. Constructing such a message is within reach of any normal payment-sending peer targeting a light wallet counterparty; no special privileges, hub compromise, or network-level attack is required. Full confirmation would need dynamic testing to verify that `unhandled_private_payments` can carry differing `arrPrivateElements` chains for the same `unit`/`message_index` pair concurrently, which I was not able to fully trace end-to-end in the available index (see caveat below).

### Recommendation
- Scope the `linked` flag (and the `UPDATE unhandled_private_payments SET linked=1 ...`) by the exact chain content (or at minimum by `output_index`) rather than by `unit`+`message_index` alone, so a verified link proof for one output cannot be reused to skip verification for another output's differing private-element chain.
- Remove the `conf.bLight` short-circuit in `indivisible_asset.js`'s `validateSourceOutput`, or make it re-validate/cross-check that the `linked` flag genuinely corresponds to the exact `arrPrivateElements` chain being processed, not merely to the same unit/message_index.
- As in the original report's recommendation, prefer performing the authoritative inclusion check directly at the point of use rather than trusting a flag set by a separate, loosely-scoped subsystem.

### Proof of Concept
Conceptual PoC (not executed, based on static code trace):
1. Attacker sends a private indivisible-asset message with two outputs (`output_index` 0 and 1) under one `unit`/`message_index` to a light-wallet victim.
2. Output 0's private-element chain is legitimate and verifiable; the light wallet requests link proofs and `network.js` marks `unhandled_private_payments` `linked=1` for that `unit`+`message_index` [5](#0-4) .
3. Attacker also delivers output 1's chain (same `unit`/`message_index`, different `output_index`) whose declared prior unit is not actually included in the chain's DAG ancestry.
4. When `handleSavedPrivatePayments` processes the row for output 1, `row.linked` is already `1` from step 2, so `updateLinkProofsOfPrivateChain` is skipped [2](#0-1) , and `validateAndSave()` proceeds directly to `indivisible_asset.validatePrivatePayment`, whose `validateSourceOutput` short-circuits for light clients without checking inclusion [1](#0-0) .

Note: I was unable to fully confirm within the available index whether the storage layer/composer guarantees that two different `output_index` rows sharing the same `unit`+`message_index` can carry genuinely divergent `arrPrivateElements` unit sequences in all cases (this would require deeper tracing through `divisible_asset.js`/`indivisible_asset.js` chain-building and the `unhandled_private_payments` write path than the indexing tools allowed). This uncertainty should be verified with a live Devin session with full file/test access before treating this as conclusively exploitable.

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

**File:** network.js (L2506-2509)
```javascript
					if (conf.bLight && arrPrivateElements.length > 1 && !row.linked)
						updateLinkProofsOfPrivateChain(arrPrivateElements, row.unit, row.message_index, row.output_index, cb, validateAndSave);
					else
						validateAndSave();
```

**File:** network.js (L2666-2690)
```javascript
// light only
// Note that we are leaking to light vendor information about the full chain. 
// If the light vendor was a party to any previous transaction in this chain, he'll know how much we received.
function checkThatEachChainElementIncludesThePrevious(arrPrivateElements, handleResult){
	if (arrPrivateElements.length === 1) // an issue
		return handleResult(true);
	var arrUnits = arrPrivateElements.map(function(objPrivateElement){ return objPrivateElement.unit; });
	requestFromLightVendor('light/get_link_proofs', arrUnits, function(ws, request, response){
		if (!response || response.error)
			return handleResult(null); // undefined result
		var arrChain = response;
		if (!ValidationUtils.isNonemptyArray(arrChain))
			return handleResult(null); // undefined result
		light.processLinkProofs(arrUnits, arrChain, {
			ifError: function(err){
				console.log("linkproof validation failed: "+err);
			//	throw Error(err);
				handleResult(false);
			},
			ifOk: function(){
				console.log("linkproof validated ok");
				handleResult(true);
			}
		});
	});
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
