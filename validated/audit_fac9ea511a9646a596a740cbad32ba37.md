### Title
Dangling In-Memory Reference to Pruned Unit Content Causes Permanent Validation Stall / Node Disagreement — ([File: archiving.js], [File: validation.js], [File: storage.js], [File: network.js])

### Summary
The pruning-recovery mechanism for stripped `final-bad` units relies on an ephemeral, non-durable, TTL-bounded in-memory cache (`assocCachedPrunedJoints`) as the *only* source of truth once the authoritative on-disk output row has been deleted. When a unit spends an input whose source output was already pruned, validation dereferences this cache instead of the database. If the cache entry has expired, been evicted, or never existed on that node (e.g., after a restart, since the cache is memory-only), the unit falls into an indefinite "waiting for pruned content" state that cannot be resolved unless some peer still happens to hold the same TTL-limited cache entry. Different nodes end up with different views of the same transaction's validity depending purely on the volatile state of this cache — a direct analog to a use-after-free: code keeps using a "freed" (deleted/stripped) resource through a lifetime-fragile pointer that may already be gone.

### Finding Description
`storage.js` `updateMinRetrievableMciAfterStabilizingMci` strips the content of stable `final-bad` units once `min_retrievable_mci` advances, deleting the `outputs`/`inputs`/etc. rows via `archiving.generateQueriesToArchiveJoint`, and separately stashes the full joint in a process-memory map: [1](#0-0) 

This cache lives only in memory, with a 1-hour TTL and a purge timer that deletes entries as soon as they expire, with no persistence and no cross-node guarantee: [2](#0-1) [3](#0-2) 

`validation.js` `validatePaymentInputsAndOutputs` treats this cache as authoritative when the real DB row for a spent output is gone: if `sequence==='final-bad'` and the output predates `min_retrievable_mci` but is *not* judged stable-in-parents for the spending unit (i.e., the spender references an earlier `last_ball`), the code skips the definitive "spending a stable final-bad output" rejection and instead falls into the cache lookup: [4](#0-3) 

If `archiving.getCachedOutput` (a thin wrapper over `getCachedPrunedJoint`) finds nothing, the code does not reject the unit outright — it returns a transient `unresolved_dependency` error that asks the network to supply the pruned content: [5](#0-4) [6](#0-5) 

`network.js` handles this by parking the spending joint on disk under `wj\n`+unit and requesting the missing content from peers, replaying it only if/when some peer's `tryRecoverPrunedContentOfFinalBadUnit` still has (or can re-fetch) the content and re-populates `assocCachedPrunedJoints`: [7](#0-6) [8](#0-7) 

The critical flaw is that there is no guarantee any peer still holds this content: the cache is purely in-process, expires after one hour, and is wiped on every node restart (it is never re-derived from the archived, hashed content that remains recoverable only via full-content peers that also just happen to still cache it). Consequently:
- A node that still has the cache entry validates the spend (inheriting the `final-bad` sequence into the new unit, per the existing "poisoned sequence" propagation logic).
- A node whose cache entry expired, was never populated, or was lost on restart cannot ever complete validation of that exact spend — the unit sits forever as an unresolved dependency, and `requestJoints`/reroute logic keeps re-requesting content that nobody may still be willing or able to supply.
- Because the outcome (accept-with-poisoned-sequence vs. permanently-stuck) depends solely on the ephemeral, non-consensus state of each node's local cache, different nodes can reach different final states for units that reference the same spend, and the network as a whole may never converge on whether the dependent branch is confirmable.

This is functionally the same bug class as CVE-2020-16039 (use of a resource after it has been freed/invalidated, where the "freed" object is only nominally accessible through a fragile lifetime-tied handle): here the "freed" resource is the stripped output row, and the "dangling handle" is the volatile `assocCachedPrunedJoints` map.

### Impact Explanation
This breaks the node-disagreement / non-convergence guarantee explicitly in scope: nodes can permanently diverge on whether a unit that spends a previously-pruned `final-bad` output is confirmable, and a unit can become permanently stuck as an unresolved dependency network-wide if no peer's cache still holds the content (TTL 1 hour, non-persistent, easily lost by restart or having pruned it long before the spend arrives). Any unprivileged unit poster can trigger the path by referencing a public/known `final-bad` unit's output with a spending unit whose `last_ball_mci` is chosen to be less than that output's `main_chain_index` (this is a legal choice of `last_ball`), forcing `bStableInParents` to be false and routing validation into the fragile cache path instead of the definitive same-instant rejection.

### Likelihood Explanation
The pruning of `final-bad` units happens automatically and routinely as `min_retrievable_mci` advances during normal chain operation, so pruned final-bad outputs with pointers eligible for this path exist continuously. Crafting a unit that references an earlier `last_ball` to avoid the `bStableInParents` short-circuit requires no special privilege — any wallet or AA-adjacent unit author can pick their own `last_ball_unit`. The main uncertainty is exact timing relative to the 1-hour cache TTL/purge cycle and node restarts, which is why this is best characterized as node-disagreement / persistent unresolved-dependency risk rather than a deterministic single-shot fund-theft primitive.

### Recommendation
- Do not treat the in-memory `assocCachedPrunedJoints` map as sufficient grounds to either accept or indefinitely stall validation. If the cache is empty, either persist recovered/soon-to-be-pruned content (e.g., in the `archived_joints` table, which already stores the full JSON) and read from there deterministically, or fall back to the same definitive rejection (`"spending a stable final-bad output"`) rather than an open-ended `unresolved_dependency`.
- Bound the number of retries/lifetime of `assocUnitsWaitingForPrunedContent` entries and fail closed (reject the unit) rather than fail open (retry forever) once that bound is exceeded, so all nodes converge to the same terminal outcome regardless of transient cache/peer availability.
- Ensure `bStableInParents`-based rejection of final-bad output spends cannot be bypassed merely by the spender's choice of `last_ball_mci`; the sequence/validity of a referenced output should not depend on which `last_ball` the spending unit happens to declare.

### Proof of Concept
1. Wait for (or arrange) a `final-bad` unit `U` whose output(s) get pruned once `min_retrievable_mci` passes its `main_chain_index` (`storage.js:1695-1765`).
2. After the in-memory `assocCachedPrunedJoints` TTL (1 hour) has elapsed, or after any node restart, so no node's cache holds `U`'s content.
3. Post a new unit `V` that spends `U`'s pruned output but declares a `last_ball_unit` whose MCI is lower than `U`'s `main_chain_index`, so `bStableInParents` is `false` for that input (`validation.js:2454-2461`).
4. Validation reaches `!src_output.address` → `archiving.getCachedOutput` returns `null` (cache empty) → `validation.js:2464-2466` returns `{error_code:"unresolved_dependency", bRequestPrunedContent:true}`.
5. `network.js:1229-1253` parks `V` and requests `U`'s content from peers; if no peer still caches it (likely, given the 1-hour TTL and non-persistence), `V` never resolves. Meanwhile, a node that happens to still have `U` cached will validate and accept `V` (with inherited `final-bad` sequence) — demonstrating divergent, cache-dependent outcomes for the identical unit `V` across the network.

### Citations

**File:** storage.js (L1743-1747)
```javascript
								var objStrippedJoint = {unit: objStrippedUnit, ball: objJoint.ball};
								batch.put('j\n'+unit, JSON.stringify(objStrippedJoint));
								archiving.cachePrunedJoint(objJoint); // keep the full content around for a while in case somebody still needs it
								archiving.generateQueriesToArchiveJoint(conn, objJoint, 'voided', arrQueries, cb);
							}
```

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

**File:** validation.js (L2454-2474)
```javascript
							var src_output = rows[0];
							var bStableInParents = (src_output.main_chain_index !== null && src_output.main_chain_index <= objValidationState.last_ball_mci);
							if (bStableInParents) {
								if (src_output.sequence === 'temp-bad')
									throw Error("spending a stable temp-bad output " + input.unit);
								if (src_output.sequence === 'final-bad')
									return cb("spending a stable final-bad output " + input.unit);
							}
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

**File:** network.js (L1009-1033)
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
	delete assocUnitsWaitingForPrunedContent[unit];
	// replay the waiting joints in the background, don't make the peer who sent us the recovered content wait for this
	async.eachSeries(arrWaitingJoints, function(o, cb){
		const key = 'wj\n' + o.unit;
		kvstore.get(key, strSavedJoint => {
			kvstore.del(key);
			if (!strSavedJoint) // already replayed via another missing unit it was also waiting on, or expired
				return cb();
			const { objJoint: objWaitingJoint, peer } = JSON.parse(strSavedJoint);
			handleOnlineJoint(peer ? getPeerWebSocket(peer) : null, objWaitingJoint, cb);
		});
	});
	return true;
}
```

**File:** network.js (L1229-1253)
```javascript
				ifNeedParentUnits: function(arrMissingUnits, bRequestPrunedContent){
					clearHost();
					if (bRequestPrunedContent && !bPosted) {
						// e.g. spending a locally pruned final-bad output: hold on to this joint ourselves and retry it if/when we
						// recover the missing content, since the missing unit already has a row in the units table and the usual
						// dependencies table would (wrongly) consider it satisfied right away.
						// the joint body goes to rocksdb (see comment on assocUnitsWaitingForPrunedContent), keyed by its own unit
						kvstore.put('wj\n' + unit, JSON.stringify({ objJoint, peer: ws ? ws.peer : null }), () => {});
						const expiry_ts = Date.now() + 60 * 60 * 1000;
						for (let missing_unit of arrMissingUnits) {
							if (!assocUnitsWaitingForPrunedContent[missing_unit])
								assocUnitsWaitingForPrunedContent[missing_unit] = [];
							assocUnitsWaitingForPrunedContent[missing_unit].push({ unit, expiry_ts });
						}
						delete assocUnitsInWork[unit];
						// requestNewMissingJoints relies on checkIfNewUnit, which can say ifKnown() for a unit that only has
						// stale props cached in assocCachedUnits, even though its full content is exactly what we are missing
						// Also, don't check havePendingJointRequest as the peer of an earlier request could intentionally withhold the unit (there is rerouting, but it would give up at the first peer that doesn't have the unit)
						// ws can be null here (e.g. replaying a saved joint whose original sender already disconnected)
						if (ws)
							requestJoints(ws, arrMissingUnits);
						else
							findNextPeer(null, function(next_ws){
								requestJoints(next_ws, arrMissingUnits);
							});
```
