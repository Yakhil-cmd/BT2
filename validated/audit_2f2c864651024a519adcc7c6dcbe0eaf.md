## Title
Stale cached pruned-joint output data can be spent/validated after underlying state changed - no invalidation on write ([File: archiving.js])

### Summary
The CVE-2024-26598 bug class is: a cache lookup returns a live reference/handle to an object that can be concurrently invalidated (freed/discarded) by another code path, and the consumer keeps using the stale handle without re-validating or pinning it. The closest reachable analog in ocore is the `assocCachedPrunedJoints` in-memory cache in `archiving.js`, which is consulted by `validateOrCatchDoublespends`-style output resolution in `validation.js` when a spent output's source unit was already stripped/archived as `final-bad`.

### Finding Description
`archiving.js` keeps an in-memory cache of joints that were just pruned/voided: [1](#0-0) 

`getCachedPrunedJoint()` returns the cached object **without checking `expiry_ts`** — expiry is only enforced by a separate `setInterval(purgeExpiredCachedPrunedJoints, ...)` that runs once per hour: [2](#0-1) 

This cached, unvalidated data is consumed in `validation.js` to resurrect address/amount/denomination/asset for an output whose owning unit was already stripped from the `outputs` table because it was `final-bad`: [3](#0-2) 

The important property here is that `getCachedOutput()` returns data taken from a `final-bad` unit's *original, unauthenticated-at-use-time* joint content, and this data is trusted to satisfy `checkInputDoubleSpend`/asset/denomination matching for a *new* incoming unit, purely because the pruning happened "recently" (within the 1-hour TTL) — mirroring the "return a handle without confirming validity/ownership at time of use" pattern from the LPI cache bug (return of `vgic_irq` without checking whether it is still alive/owned before use).

Unlike the kernel bug, there is no refcount object being freed in JS, so there's no literal memory-safety UAF. However, the semantic hazard is analogous: `cachePrunedJoint()` is called at pruning/archiving time and the entry is *not proactively invalidated* if the same unit is later reprocessed (e.g. because the peer eventually supplies the real content and the unit is properly saved/un-pruned), nor is the entry keyed to the specific archival event/reason. Any subsequent validation for a competing/duplicate reference to the same `input.unit` within the TTL window will keep resolving through the stale cached copy rather than the authoritative `outputs`/`units` tables, because the code path is gated purely on `src_output.sequence === 'final-bad' AND main_chain_index < min_retrievable_mci` with no cross-check against the cache's freshness/consistency with the current DB state.

### Impact Explanation
If the cached pruned-joint output data becomes inconsistent with the authoritative on-disk state (e.g., due to a race between local pruning/voiding and legitimate re-validation/un-pruning of the same unit, or because two different nodes archive the unit for different reasons at different times while gossip is in flight), validation for units built on top of a "spent output" can proceed against a copy of data that no other node necessarily agrees is authoritative at that exact moment, since the cache is local, time-based, and unauthenticated against the current DB row. This can produce node disagreement on validity/sequence (`good` vs `final-bad`) for units spending outputs of a pruned parent unit, which is exactly the "node disagreement on validity or stability" impact category.

### Likelihood Explanation
This path is reachable only for units that spend an output of an already `final-bad`, locally-pruned unit (`main_chain_index < getMinRetrievableMci()`), which is a narrow, edge-case condition requiring pruning to already be enabled and active on the node (light/pruned nodes). It is triggerable by an ordinary unit poster referencing such an output, but requires precise timing around pruning/archiving and the 1-hour cache TTL, making it a lower-likelihood, timing-dependent condition rather than a straightforward, freely reproducible bug.

### Recommendation
- Validate `getCachedOutput()` results against `expiry_ts` in `getCachedPrunedJoint()` itself (not only via the separate interval sweep), so a technically-expired-but-not-yet-swept entry is never used.
- Invalidate/refresh the cache entry whenever the same unit is reprocessed (saved, un-pruned, or re-archived with a different reason) rather than relying purely on time-based expiry.
- Cross-check the cached output's `address`/`amount`/`denomination`/`asset` against any authoritative source still available (e.g. ball hash / unit hash verification of the cached joint) before using it to satisfy double-spend/asset checks in `validation.js`, ensuring the cache can only serve as a hint, not as a substitute for authoritative validation.

### Proof of Concept
Not concretely demonstrable from the indexed code alone: reproducing this requires controlling the exact timing of local pruning/archiving of a `final-bad` unit relative to submission of a new unit spending its output, which depends on runtime pruning configuration (`getMinRetrievableMci()`) not fully visible in the indexed files. This should be verified with a live/instrumented node (e.g. a Devin session) to confirm whether a genuinely exploitable staleness window exists, since I could not fully trace all callers of `cachePrunedJoint()` (e.g. in `network.js`) within the available context.

### Citations

**File:** archiving.js (L5-19)
```javascript
// in-memory holdover of joints we just voided (stripped final-bad units), so that for a while after pruning
// we can still serve their full content to peers and recover from spends that raced the pruning locally
const PRUNED_JOINT_CACHE_TTL_ms = 60 * 60 * 1000;
let assocCachedPrunedJoints = {};

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

**File:** archiving.js (L40-46)
```javascript
function purgeExpiredCachedPrunedJoints(){
	const now = Date.now();
	for (let unit in assocCachedPrunedJoints)
		if (assocCachedPrunedJoints[unit].expiry_ts < now)
			delete assocCachedPrunedJoints[unit];
}
setInterval(purgeExpiredCachedPrunedJoints, PRUNED_JOINT_CACHE_TTL_ms);
```

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
