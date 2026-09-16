Found a concrete analog: a stale/attacker-controllable cached object being trusted and reused after the authoritative record it came from was already pruned, which mirrors the "use a freed/invalidated object" root cause of CVE-2024-8362 (using memory whose backing allocation is gone/stale).

### Title
Unvalidated peer-supplied data from `archiving.getCachedOutput` is trusted to resolve pruned spend inputs, enabling forged/stale source-output data - (File: validation.js)

### Summary
When a payment input spends an output whose source unit was locally pruned as `final-bad` (its `outputs` row content stripped), `validatePaymentInputsAndOutputs` falls back to `archiving.getCachedOutput()` to reconstruct the address/amount/denomination/asset of that output instead of using anything cryptographically re-verified against the unit's original hash at spend time.

### Finding Description
In `validation.js` around the "transfer" input case, when `src_output.address` is empty because the source unit is `final-bad` and already stripped (`main_chain_index < storage.getMinRetrievableMci()`), the code retrieves substitute output data from an in-memory cache populated by network recovery logic: [1](#0-0) 

That cache is populated in `network.js`'s `tryRecoverPrunedContentOfFinalBadUnit`, which is invoked purely because a unit is present in `assocUnitsWaitingForPrunedContent` (i.e., some node earlier tried to spend the pruned output and asked to fetch its content back from peers): [2](#0-1) 

The only check performed before trusting and caching the recovered joint is `validation.allHashesAreValid(objJoint)`, which checks internal consistency of the *unit hash / message hashes* the peer supplied, not that this content is actually the same content that was originally accepted and later pruned. There is no re-verification against a stored `content_hash`, `ball` proof, or any previously-committed digest of that specific pruned unit's payload: [3](#0-2) 

Because a `final-bad` unit's row is still marked `final-bad` and its outputs are pruned/deleted by `generateQueriesToRemoveJoint`/`generateQueriesToVoidJoint` (see `archiving.js`), the node has no ground truth left to check the "recovered" joint against beyond internal hash self-consistency. A malicious/faulty peer that responds to `get_joint` for such a unit can supply any self-consistent (but never-actually-accepted) joint content, which is `cachePrunedJoint`'d and then used by `getCachedOutput` to backfill `src_output.address`/`amount`/`denomination`/`asset` for validation of the unit currently being validated: [4](#0-3) 

This is architecturally analogous to the Chrome WebAudio UAF: an object (the "true" output row) is torn down/freed (pruned from `outputs`/`units`), yet a later code path (`getCachedOutput`) trusts and operates on a substitute reconstruction of that freed data supplied via an untrusted external channel (a random peer's `get_joint` response), rather than re-deriving it from an immutable, previously-verified source (e.g., a hash of the original archived output, or the `archived_joints.json` snapshot saved during pruning, which does exist but is not consulted here).

### Impact Explanation
If an attacker can get a node to reach the "spend a pruned final-bad output" path (by first causing/observing that a unit later becomes `final-bad` and is pruned - can occur naturally via normal double-spend resolution) and then control the response to the resulting `get_joint` request (e.g., by being the responding peer, a Sybil, or a MITM-adjacent relay in the P2P mesh), they can inject a fabricated `address`/`amount`/`asset`/`denomination` for that spent output. This can let the validating node accept a transfer input as spending funds that were never actually there, or accept an input owned by a different address than actually authorized it — a path to unauthorized spending / value fabrication (fake source-output amount/address), which corrupts `total_input`, `owner_address` and ultimately the unit's acceptance as valid, potentially causing consensus disagreement between nodes that did/didn't successfully recover the (correct) original content.

### Likelihood Explanation
Requires: (1) the source unit already being `final-bad` and pruned below `getMinRetrievableMci()`, (2) the local node lacking a peer that will honestly answer `get_joint`, and (3) an attacker-controlled or malicious peer responding instead. This is a narrower, network-adjacent precondition (the prompt's "posted unit" reachability is only indirect, via a spending unit referencing the pruned output), so likelihood is moderate rather than trivially "any user."

### Recommendation
Do not trust peer-supplied recovered content for pruned `final-bad` units solely via `allHashesAreValid`. Instead, validate the recovered joint's specific message/output content against the immutable record already persisted at prune time in `archived_joints.json` (written by `generateQueriesToArchiveJoint`, `archiving.js:52-53`), or store and check a hash/digest of the pruned output(s) before pruning so the recovered content can be cryptographically tied back to what was actually originally validated, rather than only checking internal self-consistency of the newly received joint.

### Proof of Concept
Conceptual (network-dependent, not from a single posted unit alone):
1. Node A validates and stores unit `U` with a payment output O (address=Alice, amount=1000).
2. `U` later becomes `final-bad` (e.g., due to a conflicting good unit at a stable ancestor) and gets pruned (`generateQueriesToRemoveJoint`/`Void`), stripping `outputs` rows for `U`.
3. Attacker crafts unit `V` with a `transfer` input claiming to spend `U`'s output O.
4. Node A validation reaches `validatePaymentInputsAndOutputs`, finds `src_output.address` empty, `sequence==='final-bad'`, `main_chain_index < min_retrievable_mci`, so it requests `input.unit` (`U`) via `get_joint` with `bRequestPrunedContent:true`.
5. Attacker (or colluding peer) responds to `get_joint('U')` with a self-consistent but fabricated joint for `U`, where output O actually shows address=Attacker, amount=1000000.
6. `validation.allHashesAreValid` passes (internally consistent), `archiving.cachePrunedJoint` caches it, `getCachedOutput` returns the attacker-chosen address/amount, and `V`'s validation now treats Attacker (not Alice) as owner of that spent amount for `owner_address`/`total_input` checks in `validation.js:2464-2470`.

### Citations

**File:** validation.js (L2462-2474)
```javascript
							if (!src_output.address) {
								if (src_output.sequence === 'final-bad' && src_output.main_chain_index < storage.getMinRetrievableMci()) { // already stripped locally
									const objCachedOutput = archiving.getCachedOutput(input.unit, input.message_index, input.output_index);
									if (!objCachedOutput) // ask the peer who sent this unit. If the peer doesn't respond but other nodes have accepted the unit, they'll share it with us, we'll get here again and request input.unit from them
										return cb({error_code: "unresolved_dependency", arrMissingUnits: [input.unit], bRequestPrunedContent: true});
									src_output.address = objCachedOutput.address;
									src_output.amount = objCachedOutput.amount;
									src_output.denomination = objCachedOutput.denomination;
									src_output.asset = objCachedOutput.asset;
								}
								else
									return cb("output being spent " + input.unit + " not found");
							}
```

**File:** network.js (L1009-1019)
```javascript
function tryRecoverPrunedContentOfFinalBadUnit(ws, objJoint){
	const unit = objJoint.unit.unit;
	const arrWaitingJoints = assocUnitsWaitingForPrunedContent[unit];
	if (!arrWaitingJoints)
		return false;
	if (!validation.allHashesAreValid(objJoint)){
		console.log('recovered content for pruned unit ' + unit + ' from ' + ws.peer + ' failed hash check');
		return false;
	}
	archiving.cachePrunedJoint(objJoint);
	breadcrumbs.add('recovered pruned content of final-bad unit ' + unit + ' from ' + ws.peer);
```

**File:** archiving.js (L10-19)
```javascript
function cachePrunedJoint(objJoint){
	assocCachedPrunedJoints[objJoint.unit.unit] = { objJoint: objJoint, expiry_ts: Date.now() + PRUNED_JOINT_CACHE_TTL_ms };
}

function getCachedPrunedJoint(unit){
	const cached = assocCachedPrunedJoints[unit];
	if (!cached)
		return null;
	return cached.objJoint;
}
```

**File:** archiving.js (L21-38)
```javascript
// looks up a specific output within a cached pruned joint, in the same shape as the outputs table columns we lost to stripping
function getCachedOutput(unit, message_index, output_index){
	const objJoint = getCachedPrunedJoint(unit);
	if (!objJoint)
		return null;
	const message = objJoint.unit.messages && objJoint.unit.messages[message_index];
	if (!message || message.app !== 'payment' || !message.payload)
		return null;
	const output = message.payload.outputs && message.payload.outputs[output_index];
	if (!output)
		return null;
	return {
		address: output.address,
		amount: output.amount,
		denomination: message.payload.denomination || 1,
		asset: message.payload.asset || null
	};
}
```
